// Package app owns the running configuration: it builds providers, the
// secret store and rules from it, and applies changes without a restart.
package app

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/waldemarsson/fullmakt/internal/config"
	"github.com/waldemarsson/fullmakt/internal/rules"
	"github.com/waldemarsson/fullmakt/internal/secrets"
)

// Runtime is what a configuration compiles to.
type Runtime struct {
	Providers map[string]secrets.Provider
	Store     *secrets.Store
	Rules     *rules.Engine
}

// Build compiles a prepared configuration.
func Build(cfg *config.Config) (*Runtime, error) {
	providers, err := secrets.NewProviders(cfg)
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
	return &Runtime{Providers: providers, Store: store, Rules: engine}, nil
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
	onChange func(*Runtime)

	mu  sync.Mutex
	cfg *config.Config
	rt  *Runtime
}

// New wraps a loaded configuration. onChange is called with each new runtime.
func New(path string, cfg *config.Config, rt *Runtime, onChange func(*Runtime)) *App {
	return &App{path: path, cfg: cfg, rt: rt, onChange: onChange}
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
	a.mu.Lock()
	defer a.mu.Unlock()

	next := clone(a.cfg)
	next.Providers, next.Secrets, next.Rules = e.Providers, e.Secrets, e.Rules
	if err := next.Prepare(); err != nil {
		return err
	}
	rt, err := Build(&next)
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
		cfg.AllowNonLoopback != a.cfg.AllowNonLoopback || cfg.AllowLoopbackTargets != a.cfg.AllowLoopbackTargets {
		return errors.New("listen, ui, caDir and allow* settings changed; restart fullmakt to apply them")
	}
	rt, err := Build(cfg)
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
	rt, err := Build(a.cfg)
	if err != nil {
		return err
	}
	a.rt = rt
	a.onChange(rt)
	return nil
}

func clone(c *config.Config) config.Config {
	out := *c
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
