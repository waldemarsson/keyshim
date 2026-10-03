package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/waldemarsson/keyshim/internal/keystore/keystoretest"
)

func names(entries []Entry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out
}

func TestLocalEncryptedRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	key := keystoretest.NewKey(t)
	l := NewLocal(path, key)
	added := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return added }
	ctx := context.Background()

	if entries, err := l.Entries(); err != nil || len(entries) != 0 {
		t.Fatalf("missing file: entries = %v, err = %v", entries, err)
	}
	if err := l.Add("token", "abc123-secret"); err != nil {
		t.Fatal(err)
	}
	if err := l.Add("other", "xyz"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "abc123-secret") || strings.Contains(string(data), "token") {
		t.Errorf("file reveals a value or name: %s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %#o", info.Mode().Perm())
	}

	// A new provider instance with the same key reads it back, as after a restart.
	again := NewLocal(path, key)
	if v, err := again.Fetch(ctx, "token", ""); err != nil || v != "abc123-secret" {
		t.Errorf("Fetch = %q, %v", v, err)
	}
	entries, err := again.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names(entries), []string{"other", "token"}) || !entries[0].AddedAt.Equal(added) {
		t.Errorf("entries = %+v", entries)
	}
	if _, err := again.Fetch(ctx, "token", "v1"); err == nil {
		t.Error("version: want error")
	}
	if _, err := NewLocal(path, keystoretest.NewKey(t)).Fetch(ctx, "token", ""); err == nil {
		t.Error("opened with another key")
	}
}

func TestLocalIsCreateOnly(t *testing.T) {
	l := NewLocal(filepath.Join(t.TempDir(), "secrets.enc"), keystoretest.NewKey(t))
	if err := l.Add("token", "first"); err != nil {
		t.Fatal(err)
	}
	if err := l.Add("token", "second"); !errors.Is(err, ErrExists) {
		t.Errorf("overwrite: err = %v, want ErrExists", err)
	}
	if v, _ := l.Fetch(context.Background(), "token", ""); v != "first" {
		t.Errorf("value changed to %q", v)
	}
	if err := l.Add("empty", ""); err == nil {
		t.Error("empty value accepted")
	}
	if err := l.Delete("token"); err != nil {
		t.Fatal(err)
	}
	if err := l.Delete("token"); err == nil {
		t.Error("deleting a missing key: want error")
	}
	if err := l.Add("token", "second"); err != nil {
		t.Errorf("add after delete: %v", err)
	}
}

func TestLocalImport(t *testing.T) {
	l := NewLocal(filepath.Join(t.TempDir(), "secrets.enc"), keystoretest.NewKey(t))
	if err := l.Add("existing", "keep"); err != nil {
		t.Fatal(err)
	}
	added, skipped, err := l.Import(map[string]string{"a": "1", "existing": "replace", "empty": ""})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(added, []string{"a"}) || !slices.Equal(skipped, []string{"empty", "existing"}) {
		t.Errorf("added = %v, skipped = %v", added, skipped)
	}
	if v, _ := l.Fetch(context.Background(), "existing", ""); v != "keep" {
		t.Errorf("import replaced a value: %q", v)
	}
}

func TestLocalRejectsPlaintextAndOpenPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(path, []byte("token: abc123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLocal(path, keystoretest.NewKey(t))
	_, err := l.Fetch(context.Background(), "token", "")
	if err == nil || !strings.Contains(err.Error(), "keyshim secrets import") || strings.Contains(err.Error(), "abc123") {
		t.Errorf("plaintext file: err = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Fetch(context.Background(), "token", ""); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("readable file: err = %v", err)
	}
}
