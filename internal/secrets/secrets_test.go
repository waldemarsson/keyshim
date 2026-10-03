package secrets

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/waldemarsson/keyshim/internal/config"
)

type countingProvider struct {
	mu    sync.Mutex
	calls int
	value string
	err   error
}

func (p *countingProvider) Fetch(context.Context, string, string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.value, p.err
}

func newTestStore(t *testing.T, p Provider) *Store {
	t.Helper()
	cfg := &config.Config{Secrets: map[string]config.Secret{
		"s": {Provider: "p", Name: "remote", TTL: config.Duration(time.Minute)},
	}}
	s, err := NewStore(cfg, map[string]Provider{"p": p})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreCachesUntilTTL(t *testing.T) {
	p := &countingProvider{value: "v"}
	s := newTestStore(t, p)
	now := time.Now()
	s.now = func() time.Time { return now }

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if v, err := s.Get(context.Background(), "s"); err != nil || v != "v" {
				t.Errorf("Get = %q, %v", v, err)
			}
		})
	}
	wg.Wait()
	if p.calls != 1 {
		t.Errorf("calls = %d, want 1", p.calls)
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.Get(context.Background(), "s"); err != nil {
		t.Fatal(err)
	}
	if p.calls != 2 {
		t.Errorf("calls after expiry = %d, want 2", p.calls)
	}
}

func TestStoreErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := newTestStore(t, &countingProvider{value: ""}).Get(ctx, "s"); !errors.Is(err, errEmpty) {
		t.Errorf("empty value: err = %v", err)
	}
	if _, err := newTestStore(t, &countingProvider{err: errors.New("down")}).Get(ctx, "s"); err == nil {
		t.Error("provider error: want error")
	}
	if _, err := newTestStore(t, &countingProvider{value: "v"}).Get(ctx, "unknown"); err == nil {
		t.Error("unknown secret: want error")
	}
}
