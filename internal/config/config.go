// Package config loads and validates the fullmakt configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	DefaultListen   = "127.0.0.1:8899"
	DefaultUIListen = "127.0.0.1:8900"
	DefaultTTL      = Duration(15 * time.Minute)

	ProviderLocal         = "local"
	ProviderAzureKeyVault = "azure-keyvault"
)

// Config is the root of the configuration file.
type Config struct {
	Listen string `yaml:"listen,omitempty" json:"listen"`
	// AllowNonLoopback permits a proxy listen address other than loopback.
	// Anything that can reach the address can then use the configured secrets.
	AllowNonLoopback bool `yaml:"allowNonLoopback,omitempty" json:"allowNonLoopback"`
	// AllowLoopbackTargets lets proxy clients reach loopback and link-local
	// addresses, which includes services on the proxy's own host.
	AllowLoopbackTargets bool                `yaml:"allowLoopbackTargets,omitempty" json:"allowLoopbackTargets"`
	CADir                string              `yaml:"caDir,omitempty" json:"caDir"`
	UI                   UI                  `yaml:"ui,omitempty" json:"ui"`
	Providers            map[string]Provider `yaml:"providers,omitempty" json:"providers"`
	Secrets              map[string]Secret   `yaml:"secrets,omitempty" json:"secrets"`
	Rules                []Rule              `yaml:"rules,omitempty" json:"rules"`
}

// UI configures the management web UI. It always listens on loopback.
type UI struct {
	Listen   string `yaml:"listen,omitempty" json:"listen"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled"`
}

// Provider is a secret backend.
type Provider struct {
	Type     string `yaml:"type" json:"type"`
	File     string `yaml:"file,omitempty" json:"file,omitempty"`         // local
	VaultURI string `yaml:"vaultUri,omitempty" json:"vaultUri,omitempty"` // azure-keyvault
}

// Secret maps a name used in rules to a value held by a provider.
type Secret struct {
	Provider string   `yaml:"provider" json:"provider"`
	Name     string   `yaml:"name" json:"name"`
	Version  string   `yaml:"version,omitempty" json:"version,omitempty"`
	TTL      Duration `yaml:"ttl,omitempty" json:"ttl"`
}

// Rule injects headers into HTTPS requests that match host, method and path.
type Rule struct {
	Name string `yaml:"name,omitempty" json:"name"`
	// Disabled pauses the rule: it is still validated but never matches.
	Disabled bool     `yaml:"disabled,omitempty" json:"disabled"`
	Host     string   `yaml:"host" json:"host"`
	Methods  []string `yaml:"methods,omitempty" json:"methods"`
	Paths    []string `yaml:"paths,omitempty" json:"paths"`
	Inject   []Inject `yaml:"inject" json:"inject"`
}

// Inject sets one request header from a template.
type Inject struct {
	Header string `yaml:"header" json:"header"`
	Value  string `yaml:"value" json:"value"`
}

// Duration is a time.Duration written as a string such as "15m" in YAML and JSON.
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).String() }

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	return d.parse(s)
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return d.parse(s)
}

func (d *Duration) parse(s string) error {
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

var (
	secretNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	headerNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// Headers that the proxy manages itself or that change message framing.
var forbiddenHeaders = map[string]bool{
	"host":                true,
	"content-length":      true,
	"transfer-encoding":   true,
	"connection":          true,
	"upgrade":             true,
	"te":                  true,
	"trailer":             true,
	"keep-alive":          true,
	"proxy-connection":    true,
	"proxy-authorization": true,
}

// DefaultDir returns ~/.config/fullmakt.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "fullmakt"), nil
}

// Load reads, defaults and validates the configuration at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: config is empty", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.Prepare(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// Prepare fills in defaults and validates the configuration.
func (c *Config) Prepare() error {
	if err := c.applyDefaults(); err != nil {
		return err
	}
	return c.Validate()
}

// Save writes the configuration atomically with owner-only permissions.
// Comments in an existing file are not preserved.
func Save(path string, c *Config) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	header := []byte("# Written by fullmakt. Comments are not preserved when the UI saves changes.\n")
	return WriteFileAtomic(path, append(header, data...), 0o600)
}

// WriteFileAtomic replaces path with data through a temporary file in the
// same directory, so readers never see a partial file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (c *Config) applyDefaults() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.UI.Listen == "" {
		c.UI.Listen = DefaultUIListen
	}
	if c.CADir == "" {
		dir, err := DefaultDir()
		if err != nil {
			return err
		}
		c.CADir = filepath.Join(dir, "ca")
	}
	var err error
	if c.CADir, err = expandHome(c.CADir); err != nil {
		return err
	}
	for name, p := range c.Providers {
		if p.File == "" {
			continue
		}
		if p.File, err = expandHome(p.File); err != nil {
			return err
		}
		c.Providers[name] = p
	}
	for name, s := range c.Secrets {
		if s.TTL == 0 {
			s.TTL = DefaultTTL
			c.Secrets[name] = s
		}
	}
	return nil
}

func expandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
}

// Validate reports every structural problem in the configuration. Rule
// templates are checked by the rules package, which knows the template syntax.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if host, _, err := net.SplitHostPort(c.Listen); err != nil {
		add("listen %q: %v", c.Listen, err)
	} else if !c.AllowNonLoopback && !isLoopback(host) {
		add("listen %q is not a loopback address; set allowNonLoopback to accept it", c.Listen)
	}
	if host, _, err := net.SplitHostPort(c.UI.Listen); err != nil {
		add("ui.listen %q: %v", c.UI.Listen, err)
	} else if !isLoopback(host) {
		add("ui.listen %q must be a loopback address", c.UI.Listen)
	}
	if !c.UI.Disabled && c.UI.Listen == c.Listen {
		add("ui.listen must differ from listen")
	}

	for _, name := range slices.Sorted(maps.Keys(c.Providers)) {
		p := c.Providers[name]
		switch p.Type {
		case ProviderLocal:
			if p.File == "" {
				add("provider %q: file is required", name)
			}
			if p.VaultURI != "" {
				add("provider %q: vaultUri is not valid for type local", name)
			}
		case ProviderAzureKeyVault:
			if u, err := url.Parse(p.VaultURI); err != nil || u.Scheme != "https" || u.Host == "" {
				add("provider %q: vaultUri must be an https URL", name)
			}
			if p.File != "" {
				add("provider %q: file is not valid for type azure-keyvault", name)
			}
		default:
			add("provider %q: unknown type %q", name, p.Type)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(c.Secrets)) {
		s := c.Secrets[name]
		if !secretNamePattern.MatchString(name) {
			add("secret %q: names may contain only letters, digits, '_' and '-'", name)
		}
		if _, ok := c.Providers[s.Provider]; !ok {
			add("secret %q: unknown provider %q", name, s.Provider)
		}
		if s.Name == "" {
			add("secret %q: name is required", name)
		}
		if s.TTL < 0 {
			add("secret %q: ttl must not be negative", name)
		}
	}

	for i, r := range c.Rules {
		label := r.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		if r.Host == "" {
			add("rule %s: host is required", label)
		}
		for _, p := range r.Paths {
			if !strings.HasPrefix(p, "/") {
				add("rule %s: path %q must start with /", label, p)
			}
		}
		if len(r.Inject) == 0 {
			add("rule %s: inject is required", label)
		}
		for _, inj := range r.Inject {
			switch {
			case !headerNamePattern.MatchString(inj.Header):
				add("rule %s: invalid header name %q", label, inj.Header)
			case forbiddenHeaders[strings.ToLower(inj.Header)]:
				add("rule %s: header %q cannot be injected", label, inj.Header)
			}
			if inj.Value == "" {
				add("rule %s: header %q has no value", label, inj.Header)
			}
		}
	}
	return errors.Join(errs...)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
