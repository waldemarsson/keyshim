// Package app owns the running configuration: it builds providers, the
// secret store and rules from it, and applies changes without a restart.
package app

import (
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/waldemarsson/keyshim/internal/config"
	"github.com/waldemarsson/keyshim/internal/keystore"
	"github.com/waldemarsson/keyshim/internal/rules"
	"github.com/waldemarsson/keyshim/internal/secrets"
)

// Runtime is what a configuration compiles to.
type Runtime struct {
	Providers map[string]secrets.Provider
	Store     *secrets.Store
	Rules     *rules.Engine
	// Clients maps client names to token hashes.
	Clients map[string][32]byte
}

// Build compiles a prepared configuration. key encrypts data at rest.
func Build(cfg *config.Config, key *keystore.Key) (*Runtime, error) {
	providers, err := secrets.NewProviders(cfg, key)
	if err != nil {
		return nil, err
	}
	store, err := secrets.NewStore(cfg, providers)
	if err != nil {
		return nil, err
	}
	engine, err := rules.Compile(cfg.Rules, store.Has)
	if err != nil {
		return nil, err
	}
	clients := map[string][32]byte{}
	for _, c := range cfg.Clients {
		hash, err := config.ParseTokenHash(c.TokenHash)
		if err != nil {
			return nil, fmt.Errorf("client %q: %w", c.Name, err)
		}
		clients[c.Name] = hash
	}
	return &Runtime{Providers: providers, Store: store, Rules: engine, Clients: clients}, nil
}

// Editable is the part of the configuration that can change while running.
// Listen addresses and the CA directory need a restart.
type Editable struct {
	Providers map[string]config.Provider `json:"providers"`
	Secrets   map[string]config.Secret   `json:"secrets"`
	Rules     []config.Rule              `json:"rules"`
}

// App holds the current configuration and runtime.
type App struct {
	path     string
	key      *keystore.Key
	onChange func(*Runtime)

	mu  sync.Mutex
	cfg *config.Config
	rt  *Runtime
}

// New wraps a loaded configuration. onChange is called with each new runtime.
func New(path string, key *keystore.Key, cfg *config.Config, rt *Runtime, onChange func(*Runtime)) *App {
	return &App{path: path, key: key, cfg: cfg, rt: rt, onChange: onChange}
}

// Path returns the configuration file path.
func (a *App) Path() string { return a.path }

// Config returns a copy of the current configuration.
func (a *App) Config() config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	return clone(a.cfg)
}

// Runtime returns the current runtime.
func (a *App) Runtime() *Runtime {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rt
}

// Apply validates the edited configuration, saves it and switches the proxy
// to it. On error nothing changes.
func (a *App) Apply(e Editable) error {
	return a.change(func(next *config.Config) error {
		next.Providers, next.Secrets, next.Rules = e.Providers, e.Secrets, e.Rules
		return nil
	})
}

// Reload rereads the configuration file. Changes to listen addresses or the
// CA directory are rejected because they need a restart.
func (a *App) Reload() error {
	cfg, err := config.Load(a.path)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cfg.Listen != a.cfg.Listen || cfg.UI != a.cfg.UI || cfg.CADir != a.cfg.CADir ||
		cfg.AllowNonLoopback != a.cfg.AllowNonLoopback || cfg.AllowLoopbackTargets != a.cfg.AllowLoopbackTargets ||
		cfg.Encryption != a.cfg.Encryption {
		return errors.New("listen, ui, caDir, encryption and allow* settings changed; restart keyshim to apply them")
	}
	rt, err := Build(cfg, a.key)
	if err != nil {
		return err
	}
	a.cfg, a.rt = cfg, rt
	a.onChange(rt)
	return nil
}

// ReloadSecrets rebuilds the runtime from the current configuration, which
// drops cached secret values. Used after a local value changes.
func (a *App) ReloadSecrets() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	rt, err := Build(a.cfg, a.key)
	if err != nil {
		return err
	}
	a.rt = rt
	a.onChange(rt)
	return nil
}

// AddClient registers a client and returns its token. Only a hash of the
// token is stored, so it is shown once.
func (a *App) AddClient(name string) (string, error) {
	token := newClientToken()
	err := a.change(func(next *config.Config) error {
		if slices.ContainsFunc(next.Clients, func(c config.Client) bool { return c.Name == name }) {
			return fmt.Errorf("client %q already exists", name)
		}
		next.Clients = append(next.Clients, config.Client{
			Name:      name,
			TokenHash: config.HashToken(token),
			AddedAt:   time.Now().UTC().Truncate(time.Second),
		})
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// DeleteClient removes a client; its token stops working immediately.
func (a *App) DeleteClient(name string) error {
	return a.change(func(next *config.Config) error {
		i := slices.IndexFunc(next.Clients, func(c config.Client) bool { return c.Name == name })
		if i < 0 {
			return fmt.Errorf("client %q not found", name)
		}
		next.Clients = slices.Delete(next.Clients, i, i+1)
		return nil
	})
}

// change applies edit to a copy of the configuration, then validates, saves
// and activates it. On error nothing changes.
func (a *App) change(edit func(*config.Config) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := clone(a.cfg)
	if err := edit(&next); err != nil {
		return err
	}
	if err := next.Prepare(); err != nil {
		return err
	}
	rt, err := Build(&next, a.key)
	if err != nil {
		return err
	}
	if err := config.Save(a.path, &next); err != nil {
		return fmt.Errorf("save %s: %w", a.path, err)
	}
	a.cfg, a.rt = &next, rt
	a.onChange(rt)
	return nil
}

const (
	tokenPrefix   = "ks_"
	tokenLength   = 16 // random characters; about 95 bits
	tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// newClientToken returns "ks_" plus 16 random base62 characters. The prefix
// lets secret scanners and people recognise the value.
func newClientToken() string {
	out := make([]byte, 0, len(tokenPrefix)+tokenLength)
	out = append(out, tokenPrefix...)
	for len(out) < cap(out) {
		for _, b := range randomBytes(tokenLength) {
			// Reject bytes above the largest multiple of 62 to avoid bias.
			if b < 248 && len(out) < cap(out) {
				out = append(out, tokenAlphabet[b%62])
			}
		}
	}
	return string(out)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return b
}

func clone(c *config.Config) config.Config {
	out := *c
	out.Clients = slices.Clone(c.Clients)
	out.Providers = maps.Clone(c.Providers)
	out.Secrets = maps.Clone(c.Secrets)
	out.Rules = make([]config.Rule, len(c.Rules))
	for i, r := range c.Rules {
		r.Methods = slices.Clone(r.Methods)
		r.Paths = slices.Clone(r.Paths)
		r.Inject = slices.Clone(r.Inject)
		out.Rules[i] = r
	}
	return out
}
