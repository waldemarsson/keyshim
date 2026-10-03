package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validConfig = `
caDir: /tmp/keyshim-ca
providers:
  local: {type: local, file: ~/secrets.yaml}
  kv: {type: azure-keyvault, vaultUri: https://kv.vault.azure.net}
secrets:
  gh: {provider: kv, name: gh-token, ttl: 5m}
  db: {provider: local, name: db}
rules:
  - name: github
    host: api.github.com
    methods: [GET]
    paths: [/repos/*]
    inject:
      - header: Authorization
        value: 'Bearer {{ secret "gh" }}'
`

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.Secrets["db"].TTL != DefaultTTL || time.Duration(cfg.Secrets["gh"].TTL) != 5*time.Minute {
		t.Errorf("ttl defaults wrong: %+v", cfg.Secrets)
	}
	if strings.HasPrefix(cfg.Providers["local"].File, "~") {
		t.Errorf("file not expanded: %q", cfg.Providers["local"].File)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]string{
		"unknown field":   "listen: 127.0.0.1:1\nbogus: true\n",
		"non-loopback":    "listen: 0.0.0.0:8899\n",
		"empty":           "",
		"provider type":   "providers: {x: {type: vault}}\n",
		"http vault":      "providers: {x: {type: azure-keyvault, vaultUri: http://kv}}\n",
		"secret provider": "secrets: {a: {provider: none, name: a}}\n",
		"secret name":     "providers: {l: {type: local, file: f}}\nsecrets: {'a b': {provider: l, name: a}}\n",
		"header":          "rules: [{host: a.com, inject: [{header: Host, value: x}]}]\n",
		"no inject":       "rules: [{host: a.com}]\n",
		"relative path":   "rules: [{host: a.com, paths: [api/*], inject: [{header: A, value: x}]}]\n",
	}
	for name, content := range tests {
		if _, err := Load(writeConfig(t, content)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestAllowNonLoopback(t *testing.T) {
	if _, err := Load(writeConfig(t, "listen: 0.0.0.0:8899\nallowNonLoopback: true\n")); err != nil {
		t.Fatal(err)
	}
}

func TestRefusesConfigWritableByOthers(t *testing.T) {
	path := writeConfig(t, "listen: 127.0.0.1:8899\n")
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("group-writable config: err = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("world-readable but owner-writable config should load: %v", err)
	}
}

func TestClients(t *testing.T) {
	hash := HashToken("fmk_token")
	valid := "clients:\n  - {name: agentbox, tokenHash: " + hash + "}\n"
	if _, err := Load(writeConfig(t, valid)); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"bad hash":  "clients:\n  - {name: agentbox, tokenHash: md5:abc}\n",
		"bad name":  "clients:\n  - {name: 'a b', tokenHash: " + hash + "}\n",
		"duplicate": "clients:\n  - {name: a, tokenHash: " + hash + "}\n  - {name: a, tokenHash: " + hash + "}\n",
	} {
		if _, err := Load(writeConfig(t, content)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestRuleClientsMayNotExistYet(t *testing.T) {
	hash := HashToken("ks_token")
	base := "clients:\n  - {name: agentbox, tokenHash: " + hash + "}\nrules:\n  - {host: a.com, clients: [%s], inject: [{header: A, value: x}]}\n"
	cfg, err := Load(writeConfig(t, fmt.Sprintf(base, "agentbox")))
	if err != nil || len(cfg.Warnings()) != 0 {
		t.Fatalf("err = %v, warnings = %v", err, cfg.Warnings())
	}
	// Unknown clients are a warning, not an error, so the client can be
	// added after the rule.
	cfg, err = Load(writeConfig(t, fmt.Sprintf(base, "missing")))
	if err != nil {
		t.Fatal(err)
	}
	if w := cfg.Warnings(); len(w) != 1 || !strings.Contains(w[0], `client "missing" does not exist`) {
		t.Errorf("warnings = %v", w)
	}
}
