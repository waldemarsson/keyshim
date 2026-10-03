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
	"github.com/waldemarsson/fullmakt/internal/proxy"
	"github.com/waldemarsson/fullmakt/internal/ui"
)

var version = "dev"

const usage = `Usage: fullmakt <command> [flags]

Commands:
  run      Start the proxy
  check    Validate the configuration; -resolve also fetches every secret
  ca       Print the CA certificate (PEM) for client trust stores
  version  Print the version

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

// setup loads the configuration and compiles it.
func setup(path string) (*config.Config, *app.Runtime, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	rt, err := app.Build(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, rt, nil
}

func runCmd(args []string) error {
	fs, configPath := newFlagSet("run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, rt, err := setup(*configPath)
	if err != nil {
		return err
	}
	authority, err := ca.LoadOrCreate(cfg.CADir)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	events := audit.NewLog(1000)

	p := proxy.New(proxy.Options{
		Rules:                rt.Rules,
		Secrets:              rt.Store.Get,
		CA:                   authority,
		Logger:               logger,
		Audit:                events.Add,
		AllowLoopbackTargets: cfg.AllowLoopbackTargets,
	})
	application := app.New(*configPath, cfg, rt, func(rt *app.Runtime) { p.Update(rt.Rules, rt.Store.Get) })

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
		"rules", len(cfg.Rules), "secrets", len(cfg.Secrets), "version", version)

	if !cfg.UI.Disabled {
		uiServer, err := ui.New(ui.Options{
			App:         application,
			Audit:       events,
			CA:          authority,
			Listen:      cfg.UI.Listen,
			ProxyListen: proxyAddr.String(),
			Version:     version,
			Logger:      logger,
		})
		if err != nil {
			return err
		}
		if _, err := serve(cfg.UI.Listen, uiServer); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\nOpen the fullmakt UI (this link works until fullmakt stops):\n  %s\n\n", uiServer.LoginURL())
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
	cfg, rt, err := setup(*configPath)
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
	authority, err := ca.LoadOrCreate(cfg.CADir)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(authority.CertPEM())
	return err
}
