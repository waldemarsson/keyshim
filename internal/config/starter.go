package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

const starterTemplate = `# keyshim configuration, created by ` + "`keyshim init`" + `.
# config.example.yaml in the release archive and the README describe every
# option. The UI rewrites this file without comments when it saves changes.

# Loopback only. Anything that can reach this address can use the configured
# secrets.
listen: 127.0.0.1:8899

# Local CA for TLS interception. Trust its certificate inside sandboxes only.
caDir: %s

# Where the master key comes from: keychain (OS keychain) or passphrase
# (KEYSHIM_PASSPHRASE or a terminal prompt). Cannot be changed later.
encryption:
  key: %s

providers:
  # Encrypted with the master key. Add values with ` + "`keyshim secrets add <name>`" + `;
  # they can never be read back.
  local:
    type: local
    file: %s

# Map a name to a stored value, then inject it with a rule. For example:
#
# secrets:
#   github:
#     provider: local
#     name: github
#
# rules:
#   - name: github-api
#     host: api.github.com
#     inject:
#       - header: Authorization
#         value: 'Bearer {{ secret "github" }}'
`

// Starter returns a minimal configuration for a new installation whose
// config, CA and local secrets live in dir. encryption is KeyKeychain or
// KeyPassphrase. Paths under the default directory are written with ~ so the
// files can be copied to another machine.
func Starter(dir, encryption string) ([]byte, error) {
	if encryption != KeyKeychain && encryption != KeyPassphrase {
		return nil, fmt.Errorf("encryption must be %q or %q", KeyKeychain, KeyPassphrase)
	}
	join := func(name string) string { return filepath.Join(dir, name) }
	if def, err := DefaultDir(); err == nil && filepath.Clean(dir) == def {
		join = func(name string) string { return "~/.config/keyshim/" + name }
	}
	caDir, err := yamlScalar(join("ca"))
	if err != nil {
		return nil, err
	}
	file, err := yamlScalar(join("secrets.enc"))
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, starterTemplate, caDir, encryption, file), nil
}

// yamlScalar quotes s when YAML needs it, such as for paths containing " #".
func yamlScalar(s string) (string, error) {
	out, err := yaml.Marshal(s)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(out), "\n"), nil
}
