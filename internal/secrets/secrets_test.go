package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/waldemarsson/fullmakt/internal/config"
)

func TestLocal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(path, []byte("token: abc123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLocal(path)
	ctx := context.Background()

	if v, err := l.Fetch(ctx, "token", ""); err != nil || v != "abc123" {
		t.Errorf("Fetch = %q, %v", v, err)
	}
	if _, err := l.Fetch(ctx, "missing", ""); err == nil {
		t.Error("missing key: want error")
	}
	if _, err := l.Fetch(ctx, "token", "v1"); err == nil {
		t.Error("version: want error")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := l.Fetch(ctx, "token", "")
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("readable file: err = %v", err)
	}
}

func TestLocalInvalidYAMLHidesContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(path, []byte("token: [abc123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewLocal(path).Fetch(context.Background(), "token", "")
	if err == nil || strings.Contains(err.Error(), "abc123") {
		t.Errorf("err = %v", err)
	}
}

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
