package secrets

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLocalSetDeleteKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	l := NewLocal(path)

	if keys, err := l.Keys(); err != nil || len(keys) != 0 {
		t.Fatalf("missing file: keys = %v, err = %v", keys, err)
	}
	if err := l.Set("b", "2"); err != nil {
		t.Fatal(err)
	}
	if err := l.Set("a", "1"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("created file permissions = %#o", perm)
	}
	if keys, _ := l.Keys(); !slices.Equal(keys, []string{"a", "b"}) {
		t.Errorf("keys = %v", keys)
	}
	if v, err := l.Fetch(context.Background(), "a", ""); err != nil || v != "1" {
		t.Errorf("Fetch = %q, %v", v, err)
	}
	if err := l.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if keys, _ := l.Keys(); !slices.Equal(keys, []string{"b"}) {
		t.Errorf("keys after delete = %v", keys)
	}
	if err := l.Set("c", ""); err == nil {
		t.Error("empty value: want error")
	}
}
