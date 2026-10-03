// Command fullmakt runs a local HTTP proxy that injects secrets into
// matching HTTPS requests, so the client never holds the secret values.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/waldemarsson/fullmakt/internal/app"
	"github.com/waldemarsson/fullmakt/internal/audit"
	"github.com/waldemarsson/fullmakt/internal/ca"
	"github.com/waldemarsson/fullmakt/internal/config"
	"github.com/waldemarsson/fullmakt/internal/keystore"
	"github.com/waldemarsson/fullmakt/internal/proxy"
	"github.com/waldemarsson/fullmakt/internal/ui"
	"golang.org/x/term"
)

var version = "dev"

const usage = `Usage: fullmakt <command> [flags]

Commands:
  run      Start the proxy
  check    Validate the configuration; -resolve also fetches every secret
  ca       Print the CA certificate (PEM) for client trust stores
  client   Manage proxy clients (sandboxes): list, add, delete
  secrets  Manage encrypted local secrets: list, add, delete, import
  key      Back up or restore the master key: export, import
  version  Print the version

The master key comes from the OS keychain, or from a passphrase when the
configuration sets encryption.key: passphrase. The passphrase is read from
FULLMAKT_PASSPHRASE or asked for in the terminal.

Run "fullmakt <command> -h" for command flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runCmd(os.Args[2:])
	case "check":
		err = checkCmd(os.Args[2:])
	case "ca":
		err = caCmd(os.Args[2:])
	case "client":
		err = clientCmd(os.Args[2:])
	case "secrets":
		err = secretsCmd(os.Args[2:])
	case "key":
		err = keyCmd(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "fullmakt: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "fullmakt:", err)
		}
		os.Exit(1)
	}
}

func newFlagSet(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	defaultPath := "config.yaml"
	if dir, err := config.DefaultDir(); err == nil {
		defaultPath = filepath.Join(dir, "config.yaml")
	}
	return fs, fs.String("config", defaultPath, "path to the configuration file")
}

// setup loads the configuration, unlocks the master key and compiles the
// configuration.
func setup(path string) (*config.Config, *keystore.Key, *app.Runtime, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := unlock(path, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	rt, err := app.Build(cfg, key)
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, key, rt, nil
}

// keyOptions locates the master key: key.json lives next to the config file.
func keyOptions(path string, cfg *config.Config) keystore.Options {
	return keystore.Options{
		Dir:        filepath.Dir(path),
		Source:     cfg.Encryption.Key,
		Passphrase: promptPassphrase,
	}
}

func unlock(path string, cfg *config.Config) (*keystore.Key, error) {
	key, err := keystore.LoadOrCreate(keyOptions(path, cfg))
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	return key, nil
}

// promptPassphrase reads FULLMAKT_PASSPHRASE, or asks in the terminal without
// echo. A new key asks twice.
func promptPassphrase(confirm bool) (string, error) {
	if p, ok := os.LookupEnv("FULLMAKT_PASSPHRASE"); ok {
		// Child processes, such as the az CLI that the Azure credential
		// runs, must not inherit it.
		os.Unsetenv("FULLMAKT_PASSPHRASE")
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no passphrase: set FULLMAKT_PASSPHRASE or run in a terminal")
	}
	first, err := readHidden("fullmakt passphrase: ")
	if err != nil || !confirm {
		return first, err
	}
	second, err := readHidden("repeat passphrase: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("passphrases do not match")
	}
	return first, nil
}

// readHidden prompts on stderr and reads a line from the terminal without echo.
func readHidden(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func runCmd(args []string) error {
	fs, configPath := newFlagSet("run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, key, rt, err := setup(*configPath)
	if err != nil {
		return err
	}
	authority, err := ca.LoadOrCreate(cfg.CADir, key)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if authority.Migrated {
		logger.Warn("encrypted the plaintext CA key from an older version", "ca", authority.CertPath())
	}
	events := audit.NewLog(1000)

	p := proxy.New(proxy.Options{
		Rules:                rt.Rules,
		Secrets:              rt.Store.Get,
		Clients:              rt.Clients,
		CA:                   authority,
		Logger:               logger,
		Audit:                events.Add,
		AllowLoopbackTargets: cfg.AllowLoopbackTargets,
	})
	application := app.New(*configPath, key, cfg, rt, func(rt *app.Runtime) { p.Update(rt.Rules, rt.Store.Get, rt.Clients) })

	servers := []*http.Server{}
	errc := make(chan error, 2)
	serve := func(addr string, h http.Handler) (net.Addr, error) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		srv := &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
		}
		servers = append(servers, srv)
		go func() { errc <- srv.Serve(ln) }()
		return ln.Addr(), nil
	}

	proxyAddr, err := serve(cfg.Listen, p)
	if err != nil {
		return err
	}
	logger.Info("fullmakt listening", "addr", proxyAddr.String(), "ca", authority.CertPath(),
		"rules", len(cfg.Rules), "secrets", len(cfg.Secrets), "clients", len(cfg.Clients), "version", version)
	if len(cfg.Clients) == 0 {
		logger.Warn("no proxy clients configured; every proxy request is refused until you add one with `fullmakt client add <name>` or the UI")
	}

	if !cfg.UI.Disabled {
		uiServer, err := ui.New(ui.Options{
			App:         application,
			Audit:       events,
			CA:          authority,
			Listen:      cfg.UI.Listen,
			ProxyListen: proxyAddr.String(),
			Version:     version,
			Logger:      logger,
			OnLoginURL: func(url string) {
				fmt.Fprintf(os.Stderr, "\nOpen the fullmakt UI (single-use link; a new one is printed after each login):\n  %s\n\n", url)
			},
		})
		if err != nil {
			return err
		}
		if _, err := serve(cfg.UI.Listen, uiServer); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var errs []error
	for _, srv := range servers {
		errs = append(errs, srv.Shutdown(shutdownCtx))
	}
	return errors.Join(errs...)
}

func checkCmd(args []string) error {
	fs, configPath := newFlagSet("check")
	resolve := fs.Bool("resolve", false, "fetch every secret to verify access (values are never printed)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, _, rt, err := setup(*configPath)
	if err != nil {
		return err
	}
	store := rt.Store
	fmt.Printf("config ok: %d providers, %d secrets, %d rules\n", len(cfg.Providers), len(cfg.Secrets), len(cfg.Rules))
	if !*resolve {
		return nil
	}
	failed := 0
	for _, name := range store.Names() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := store.Get(ctx, name)
		cancel()
		if err != nil {
			failed++
			fmt.Printf("secret %s: %v\n", name, err)
			continue
		}
		fmt.Printf("secret %s: ok\n", name)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d secrets could not be resolved", failed, len(store.Names()))
	}
	return nil
}

func caCmd(args []string) error {
	fs, configPath := newFlagSet("ca")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	key, err := unlock(*configPath, cfg)
	if err != nil {
		return err
	}
	authority, err := ca.LoadOrCreate(cfg.CADir, key)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(authority.CertPEM())
	return err
}
