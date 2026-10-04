package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/term"

	"github.com/waldemarsson/keyshim/internal/app"
	"github.com/waldemarsson/keyshim/internal/ca"
	"github.com/waldemarsson/keyshim/internal/config"
	"github.com/waldemarsson/keyshim/internal/keystore"
)

// initCmd sets up everything keyshim needs before the first run: the
// configuration, the master key, the CA and optionally a first proxy client.
// Steps that are already done are left as they are, so it is safe to rerun.
func initCmd(args []string) error {
	fs, configPath := newFlagSet("init")
	passphrase := fs.Bool("passphrase", false, "derive the master key from a passphrase instead of using the OS keychain")
	clientName := fs.String("client", "", "add a proxy client with this name and print its token (asked for in a terminal)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	path, err := filepath.Abs(*configPath)
	if err != nil {
		return err
	}
	encryption := config.KeyKeychain
	if *passphrase {
		encryption = config.KeyPassphrase
	}

	created, err := writeStarter(path, encryption)
	if err != nil {
		return err
	}
	if created {
		fmt.Printf("✓ configuration  created %s\n", path)
	} else {
		fmt.Printf("✓ configuration  using the existing %s\n", path)
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if *passphrase && cfg.Encryption.Key != config.KeyPassphrase {
		return fmt.Errorf("%s already exists and uses encryption.key %q; -passphrase only applies to a new configuration", path, cfg.Encryption.Key)
	}

	keyExisted := exists(filepath.Join(filepath.Dir(path), "key.json"))
	key, err := unlock(path, cfg)
	if errors.Is(err, keystore.ErrKeychainUnavailable) && created && !keyExisted {
		// No keychain, such as on headless Linux. The configuration was
		// written by this run, so switch it to a passphrase.
		fmt.Println("  The OS keychain is not available; using a passphrase for the master key instead.")
		data, serr := config.Starter(filepath.Dir(path), config.KeyPassphrase)
		if serr != nil {
			return serr
		}
		if err := config.WriteFileAtomic(path, data, 0o600); err != nil {
			return err
		}
		if cfg, err = config.Load(path); err != nil {
			return err
		}
		key, err = unlock(path, cfg)
	}
	if err != nil {
		return err
	}
	switch {
	case keyExisted:
		fmt.Printf("✓ master key     unlocked (%s)\n", cfg.Encryption.Key)
	case cfg.Encryption.Key == config.KeyPassphrase:
		fmt.Println("✓ master key     created from your passphrase")
		fmt.Println("  Every start asks for it, or reads KEYSHIM_PASSPHRASE. It cannot be")
		fmt.Println("  recovered: keep it in a password manager.")
	default:
		fmt.Println("✓ master key     created in the OS keychain")
		fmt.Printf("  Back it up: %s, and keep the code in a password manager.\n", command(path, "key export", ""))
	}

	caExisted := exists(filepath.Join(cfg.CADir, "ca.crt"))
	authority, err := ca.LoadOrCreate(cfg.CADir, key)
	if err != nil {
		return err
	}
	if caExisted {
		fmt.Printf("✓ CA             using the existing %s\n", authority.CertPath())
	} else {
		fmt.Printf("✓ CA             created %s\n", authority.CertPath())
	}

	usesAzure := slices.ContainsFunc(slices.Collect(maps.Values(cfg.Providers)), func(p config.Provider) bool {
		return p.Type == config.ProviderAzureKeyVault
	})
	if _, err := exec.LookPath("az"); usesAzure && err != nil {
		fmt.Println("! Azure Key Vault  the az CLI was not found. Key Vault access needs `az login`,")
		fmt.Println("                   a managed or workload identity, or credentials in the environment.")
	}

	name := *clientName
	if name == "" && len(cfg.Clients) == 0 && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("\nName a first proxy client, such as the VM or sandbox (empty to skip): ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		name = strings.TrimSpace(line)
	}
	token := ""
	switch {
	case name == "":
	case slices.ContainsFunc(cfg.Clients, func(c config.Client) bool { return c.Name == name }):
		fmt.Printf("✓ client         %s already exists; its token was shown when it was added\n", name)
	default:
		rt, err := app.Build(cfg, key)
		if err != nil {
			return err
		}
		if token, err = app.New(path, key, cfg, rt, func(*app.Runtime) {}).AddClient(name); err != nil {
			return err
		}
		fmt.Printf("✓ client         added %s\n", name)
	}

	printNextSteps(path, cfg, name, token)
	return nil
}

// writeStarter creates the configuration file unless it exists. It never
// replaces an existing file.
func writeStarter(path, encryption string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	data, err := config.Starter(filepath.Dir(path), encryption)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return false, err
	}
	return true, f.Close()
}

const ruleExample = `       secrets:
         github: {provider: local, name: github}
       rules:
         - name: github-api
           host: api.github.com
           inject:
             - header: Authorization
               value: 'Bearer {{ secret "github" }}'
`

func printNextSteps(path string, cfg *config.Config, client, token string) {
	port := portOf(cfg.Listen)
	fmt.Println("\nNext steps on this machine:")
	fmt.Printf("  1. Store a secret value:  %s\n", command(path, "secrets add", "<name>"))
	fmt.Printf("  2. Use it in a rule, in %s or the UI. For example:\n", path)
	fmt.Print(ruleExample)
	fmt.Printf("  3. Verify:                %s\n", command(path, "check", "-resolve"))
	fmt.Printf("  4. Start:                 %s (prints a login link for the UI)\n", command(path, "run", ""))

	fmt.Println("\nIn each sandbox or VM:")
	switch {
	case token != "":
		fmt.Printf("  Proxy settings for %s (the token is shown only now):\n", client)
		fmt.Printf("    export HTTPS_PROXY=http://%s:%s@<keyshim-host>:%s\n", client, token, port)
		fmt.Printf("    export HTTP_PROXY=http://%s:%s@<keyshim-host>:%s\n", client, token, port)
		fmt.Println("    export NO_PROXY=localhost,127.0.0.1")
	case len(cfg.Clients) == 0 && client == "":
		fmt.Printf("  Add a proxy client first: %s (prints its token once)\n", command(path, "client add", "<name>"))
		fmt.Printf("  Then: export HTTPS_PROXY=http://<name>:<token>@<keyshim-host>:%s\n", port)
	default:
		fmt.Printf("  export HTTPS_PROXY=http://<name>:<token>@<keyshim-host>:%s\n", port)
	}
	fmt.Printf("  Trust the CA there (never on this host): %s > keyshim-ca.pem\n", command(path, "ca", ""))
	fmt.Println("  The README's \"Client setup\" section shows how to install it.")
}

// command formats a keyshim command line, adding -config after the
// subcommand when path is not the default location.
func command(path, cmd, args string) string {
	line := "keyshim " + cmd
	if dir, err := config.DefaultDir(); err != nil || path != filepath.Join(dir, "config.yaml") {
		line += " -config " + quoteArg(path)
	}
	if args != "" {
		line += " " + args
	}
	return line
}

func quoteArg(s string) string {
	if strings.ContainsAny(s, " '\"$`\\") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
