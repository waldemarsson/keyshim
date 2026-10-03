package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/term"

	"github.com/waldemarsson/fullmakt/internal/app"
	"github.com/waldemarsson/fullmakt/internal/config"
	"github.com/waldemarsson/fullmakt/internal/keystore"
	"github.com/waldemarsson/fullmakt/internal/secrets"
)

const secretsUsage = `Usage: fullmakt secrets <command> [flags]

Commands:
  list               List stored names and when they were added
  add <name>         Store a new value, read from the terminal or stdin
  delete <name>      Delete a value
  import <file>      Encrypt every key: value pair from a plaintext YAML file

Values can be added and deleted, never shown or changed. To replace a value,
delete it and add it again. Flags: -config, -provider (needed when more than
one local provider is configured).
`

func secretsCmd(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, secretsUsage)
		return errors.New("missing command")
	}
	fs, configPath := newFlagSet("secrets " + args[0])
	providerName := fs.String("provider", "", "local provider to use")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	local, name, err := openLocal(*configPath, *providerName)
	if err != nil {
		return err
	}

	switch args[0] {
	case "list":
		entries, err := local.Entries()
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Printf("no values stored in %s\n", name)
		}
		for _, e := range entries {
			fmt.Printf("%-32s added %s\n", e.Name, e.AddedAt.Local().Format(time.DateTime))
		}
		return nil

	case "add":
		key, err := oneArg(fs.Args(), "name")
		if err != nil {
			return err
		}
		value, err := readValue("value for " + key + ": ")
		if err != nil {
			return err
		}
		if err := local.Add(key, value); err != nil {
			return err
		}
		fmt.Printf("added %s to %s\n", key, name)
		return nil

	case "delete":
		key, err := oneArg(fs.Args(), "name")
		if err != nil {
			return err
		}
		if err := local.Delete(key); err != nil {
			return err
		}
		fmt.Printf("deleted %s from %s\n", key, name)
		return nil

	case "import":
		path, err := oneArg(fs.Args(), "file")
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var values map[string]string
		if err := yaml.Unmarshal(data, &values); err != nil {
			return fmt.Errorf("%s: expected a YAML map of key: value strings", path)
		}
		added, skipped, err := local.Import(values)
		if err != nil {
			return err
		}
		fmt.Printf("imported %d values into %s\n", len(added), name)
		if len(skipped) > 0 {
			fmt.Printf("skipped (already stored or empty): %s\n", strings.Join(skipped, ", "))
		}
		fmt.Printf("%s still contains the plaintext values; delete it once you have checked the import.\n", path)
		return nil

	default:
		fmt.Fprint(os.Stderr, secretsUsage)
		return fmt.Errorf("unknown secrets command %q", args[0])
	}
}

// openLocal returns the named local provider, or the only one configured.
func openLocal(configPath, name string) (*secrets.Local, string, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, "", err
	}
	var locals []string
	for n, p := range cfg.Providers {
		if p.Type == config.ProviderLocal {
			locals = append(locals, n)
		}
	}
	slices.Sort(locals)
	switch {
	case name != "" && !slices.Contains(locals, name):
		return nil, "", fmt.Errorf("no local provider named %q (local providers: %s)", name, strings.Join(locals, ", "))
	case name == "" && len(locals) == 1:
		name = locals[0]
	case name == "" && len(locals) == 0:
		return nil, "", errors.New("no local provider is configured")
	case name == "":
		return nil, "", fmt.Errorf("several local providers are configured; choose one with -provider (%s)", strings.Join(locals, ", "))
	}
	key, err := unlock(configPath, cfg)
	if err != nil {
		return nil, "", err
	}
	return secrets.NewLocal(cfg.Providers[name].File, key), name, nil
}

// readValue reads a secret without echo in a terminal, or all of stdin
// without its trailing newline when piped.
func readValue(prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return readHidden(prompt)
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"), nil
}

const keyUsage = `Usage: fullmakt key <command> [-config path]

Commands:
  export   Print a recovery code for the master key
  import   Restore the master key into the OS keychain from a recovery code

Back up config.yaml, key.json and the encrypted files anywhere; keep the
recovery code in a password manager. Anyone with the code and the files can
decrypt your secrets and the CA key.
`

func keyCmd(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, keyUsage)
		return errors.New("missing command")
	}
	fs, configPath := newFlagSet("key " + args[0])
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	switch args[0] {
	case "export":
		key, err := unlock(*configPath, cfg)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Store this recovery code in a password manager. It decrypts all fullmakt data.")
		fmt.Println(key.RecoveryCode())
		return nil

	case "import":
		code, err := readValue("recovery code: ")
		if err != nil {
			return err
		}
		if err := keystore.Import(keyOptions(*configPath, cfg), code); err != nil {
			return err
		}
		fmt.Println("master key restored to the OS keychain")
		return nil

	default:
		fmt.Fprint(os.Stderr, keyUsage)
		return fmt.Errorf("unknown key command %q", args[0])
	}
}

const clientUsage = `Usage: fullmakt client <command> [-config path]

Commands:
  list            List clients
  add <name>      Add a client and print its token (shown once)
  delete <name>   Delete a client; its token stops working

Clients authenticate to the proxy with their name and token:
  HTTPS_PROXY=http://<name>:<token>@host:port
`

func clientCmd(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, clientUsage)
		return errors.New("missing command")
	}
	fs, configPath := newFlagSet("client " + args[0])
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, key, rt, err := setup(*configPath)
	if err != nil {
		return err
	}
	application := app.New(*configPath, key, cfg, rt, func(*app.Runtime) {})

	switch args[0] {
	case "list":
		if len(cfg.Clients) == 0 {
			fmt.Println("no clients configured")
		}
		for _, c := range cfg.Clients {
			fmt.Printf("%-32s added %s\n", c.Name, c.AddedAt.Local().Format(time.DateTime))
		}
		return nil
	case "add":
		name, err := oneArg(fs.Args(), "name")
		if err != nil {
			return err
		}
		token, err := application.AddClient(name)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Token for "+name+" (shown once; a running fullmakt picks it up after `Reload file from disk` or a restart):")
		fmt.Println(token)
		fmt.Fprintf(os.Stderr, "Use: HTTPS_PROXY=http://%s:<token>@<host>:%s\n", name, portOf(cfg.Listen))
		return nil
	case "delete":
		name, err := oneArg(fs.Args(), "name")
		if err != nil {
			return err
		}
		if err := application.DeleteClient(name); err != nil {
			return err
		}
		fmt.Printf("deleted client %s (a running fullmakt applies this after a reload or restart)\n", name)
		return nil
	default:
		fmt.Fprint(os.Stderr, clientUsage)
		return fmt.Errorf("unknown client command %q", args[0])
	}
}

func portOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return addr
}

func oneArg(args []string, what string) (string, error) {
	if len(args) != 1 || args[0] == "" {
		return "", fmt.Errorf("expected exactly one %s", what)
	}
	return args[0], nil
}
