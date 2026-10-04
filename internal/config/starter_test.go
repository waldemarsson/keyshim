package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStarterLoads(t *testing.T) {
	// " #" starts a YAML comment unless quoted; the path must survive the
	// round trip. (No ':' — Windows does not allow it in file names.)
	dir := filepath.Join(t.TempDir(), "my keyshim #1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, enc := range []string{KeyKeychain, KeyPassphrase} {
		data, err := Starter(dir, enc)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("%s: %v\n%s", enc, err, data)
		}
		if cfg.Encryption.Key != enc || cfg.CADir != filepath.Join(dir, "ca") ||
			cfg.Providers["local"].File != filepath.Join(dir, "secrets.enc") {
			t.Errorf("%s: cfg = %+v", enc, cfg)
		}
		if len(cfg.Secrets) != 0 || len(cfg.Rules) != 0 || len(cfg.Clients) != 0 {
			t.Errorf("%s: starter is not empty: %+v", enc, cfg)
		}
	}
	if _, err := Starter(dir, "plaintext"); err == nil {
		t.Error("unknown encryption accepted")
	}
}

func TestStarterUsesHomeForDefaultDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	data, err := Starter(dir, KeyKeychain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "caDir: ~/.config/keyshim/ca\n") {
		t.Errorf("caDir not written relative to home:\n%s", data)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CADir != filepath.Join(home, ".config", "keyshim", "ca") {
		t.Errorf("caDir = %q", cfg.CADir)
	}
}

func TestLoadMissingSuggestsInit(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "keyshim init") {
		t.Errorf("err = %v", err)
	}
}
