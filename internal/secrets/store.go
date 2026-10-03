// Package secrets resolves secret names to values through providers and
// caches the values in memory.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/waldemarsson/fullmakt/internal/config"
	"github.com/waldemarsson/fullmakt/internal/keystore"
)

// Provider fetches a secret value from a backend.
type Provider interface {
	Fetch(ctx context.Context, name, version string) (string, error)
}

// Store resolves configured secret names and caches values until their TTL
// expires. Values live only in memory.
type Store struct {
	defs map[string]definition
	now  func() time.Time

	mu    sync.Mutex
	cache map[string]*entry
}

type definition struct {
	provider     Provider
	providerName string
	name         string
	version      string
	ttl          time.Duration
}

type entry struct {
	mu      sync.Mutex // held during fetch so concurrent callers share one fetch
	value   string
	expires time.Time

	// Status for the UI, guarded by Store.mu.
	fetchedAt time.Time
	lastErr   string
}

// Status describes a secret without its value.
type Status struct {
	Name      string    `json:"name"`
	Provider  string    `json:"provider"`
	Cached    bool      `json:"cached"`
	FetchedAt time.Time `json:"fetchedAt,omitzero"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
	Error     string    `json:"error,omitempty"`
}

// NewProviders creates the providers declared in cfg. key encrypts local
// providers' files.
func NewProviders(cfg *config.Config, key *keystore.Key) (map[string]Provider, error) {
	providers := map[string]Provider{}
	var azureCred azcore.TokenCredential
	for name, pc := range cfg.Providers {
		switch pc.Type {
		case config.ProviderLocal:
			providers[name] = NewLocal(pc.File, key)
		case config.ProviderAzureKeyVault:
			if azureCred == nil {
				cred, err := azidentity.NewDefaultAzureCredential(nil)
				if err != nil {
					return nil, fmt.Errorf("azure credential: %w", err)
				}
				azureCred = cred
			}
			p, err := NewAzureKeyVault(pc.VaultURI, azureCred)
			if err != nil {
				return nil, fmt.Errorf("provider %q: %w", name, err)
			}
			providers[name] = p
		default:
			return nil, fmt.Errorf("provider %q: unknown type %q", name, pc.Type)
		}
	}
	return providers, nil
}

// NewStore binds the configured secrets to their providers.
func NewStore(cfg *config.Config, providers map[string]Provider) (*Store, error) {
	s := &Store{defs: map[string]definition{}, cache: map[string]*entry{}, now: time.Now}
	for name, sc := range cfg.Secrets {
		p, ok := providers[sc.Provider]
		if !ok {
			return nil, fmt.Errorf("secret %q: unknown provider %q", name, sc.Provider)
		}
		s.defs[name] = definition{
			provider:     p,
			providerName: sc.Provider,
			name:         sc.Name,
			version:      sc.Version,
			ttl:          time.Duration(sc.TTL),
		}
	}
	return s, nil
}

// Has reports whether name is a configured secret.
func (s *Store) Has(name string) bool {
	_, ok := s.defs[name]
	return ok
}

// Names returns the configured secret names in sorted order.
func (s *Store) Names() []string {
	return slices.Sorted(maps.Keys(s.defs))
}

// Get returns the value of a configured secret, fetching it when the cached
// value is missing or expired. Errors never contain the value.
func (s *Store) Get(ctx context.Context, name string) (string, error) {
	return s.get(ctx, name, false)
}

// Check fetches a secret from its provider, bypassing the cache, and reports
// whether that worked. The value is cached but not returned.
func (s *Store) Check(ctx context.Context, name string) error {
	_, err := s.get(ctx, name, true)
	return err
}

func (s *Store) get(ctx context.Context, name string, refresh bool) (string, error) {
	def, ok := s.defs[name]
	if !ok {
		return "", fmt.Errorf("secret %q is not configured", name)
	}

	s.mu.Lock()
	e := s.cache[name]
	if e == nil {
		e = &entry{}
		s.cache[name] = e
	}
	s.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if !refresh && e.value != "" && s.now().Before(e.expires) {
		return e.value, nil
	}
	v, err := def.provider.Fetch(ctx, def.name, def.version)
	if err == nil && v == "" {
		err = errEmpty
	}
	if err != nil {
		err = fmt.Errorf("secret %q: %w", name, err)
		s.mu.Lock()
		e.lastErr = err.Error()
		s.mu.Unlock()
		return "", err
	}
	now := s.now()
	e.value, e.expires = v, now.Add(def.ttl)
	s.mu.Lock()
	e.fetchedAt, e.lastErr = now, ""
	s.mu.Unlock()
	return v, nil
}

// Statuses reports every configured secret in name order, without values.
func (s *Store) Statuses() []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []Status
	for _, name := range slices.Sorted(maps.Keys(s.defs)) {
		st := Status{Name: name, Provider: s.defs[name].providerName}
		if e := s.cache[name]; e != nil {
			st.FetchedAt, st.Error = e.fetchedAt, e.lastErr
			if !e.fetchedAt.IsZero() {
				st.ExpiresAt = e.fetchedAt.Add(s.defs[name].ttl)
				st.Cached = now.Before(st.ExpiresAt)
			}
		}
		out = append(out, st)
	}
	return out
}

var errEmpty = errors.New("value is empty")
