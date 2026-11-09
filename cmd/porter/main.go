package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	logger "github.com/soulteary/logger-kit/v3"
	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/diagnostic"
	"github.com/soulteary/porter/internal/gateway"
	"github.com/soulteary/porter/internal/operations"
	"github.com/soulteary/porter/internal/provider"
	"github.com/soulteary/porter/internal/store"
	versionkit "github.com/soulteary/version-kit/v4"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := run(ctx, os.Args[1:], os.Stdout, os.Stderr); e != nil {
		logger.NewDefault().Error().Str("reason", e.Error()).Msg("porter_failed")
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out, logs io.Writer) error {
	command := "serve"
	if len(args) > 0 && args[0] == "--version" {
		command = "version"
		args = args[1:]
	} else if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	switch command {
	case "serve", "version", "check-config", "doctor":
	default:
		return errors.New("unknown command; use serve, version, check-config, or doctor")
	}
	flags := flag.NewFlagSet("porter "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "porter.json", "private configuration path")
	asJSON := flags.Bool("json", false, "print machine-readable command output")
	var network bool
	if command == "doctor" {
		flags.BoolVar(&network, "network", false, "probe Stargate readiness without sending credentials")
	}
	if e := flags.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			flags.SetOutput(out)
			flags.PrintDefaults()
			return nil
		}
		return errors.New("invalid command flags")
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	info := versionkit.New(version, commit, buildDate)
	if command == "version" {
		if *asJSON {
			_, e := fmt.Fprintln(out, info.JSON())
			return e
		}
		_, e := fmt.Fprintln(out, info.Full())
		return e
	}
	c, e := config.Load(*path)
	if e != nil {
		if command != "serve" {
			report := diagnostic.Report{OK: false, Checks: []diagnostic.Check{{Name: "configuration", Level: "error", Message: diagnostic.ConfigurationProblem(e), Hint: "check JSON syntax, required fields and file access"}}}
			if err := diagnostic.Print(out, report, *asJSON); err != nil {
				return err
			}
		}
		return errors.New(diagnostic.ConfigurationProblem(e))
	}
	switch command {
	case "check-config":
		if *asJSON {
			_, e = io.WriteString(out, "{\"ok\":true}\n")
		} else {
			_, e = io.WriteString(out, "configuration valid\n")
		}
		return e
	case "doctor":
		report := diagnostic.Run(ctx, c, network)
		if e = diagnostic.Print(out, report, *asJSON); e != nil {
			return e
		}
		if !report.OK {
			return errors.New("deployment checks failed")
		}
		return nil
	}
	return serve(ctx, c, info, logs)
}
func serve(ctx context.Context, c config.Config, info *versionkit.Info, logs io.Writer) error {
	db, e := store.Open(c.Database)
	if e != nil {
		return errors.New("session storage initialization failed")
	}
	defer db.Close()
	if e = db.Prune(time.Now()); e != nil {
		return errors.New("session storage maintenance failed")
	}
	active := map[string]bool{}
	for _, binding := range c.Bindings {
		active[binding.Revision()] = true
	}
	if e = db.ReconcileBindings(active); e != nil {
		return errors.New("identity binding reconciliation failed")
	}
	ops, e := operations.New(c, db.Check, info, logs)
	if e != nil {
		return e
	}
	defer func() {
		if e := ops.Close(); e != nil {
			ops.Log.Error().Msg("audit_shutdown_failed")
		}
	}()
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	adapters := map[string]provider.Adapter{}
	for name, p := range c.Providers {
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		a, err := provider.New(bounded, name, p, c.PublicURL+"/callback/"+name, client)
		cancel()
		if err != nil {
			ops.Log.Error().Str("provider", name).Msg("provider_initialization_failed")
			return errors.New("provider initialization failed")
		}
		adapters[name] = a
	}
	publicListener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return errors.New("public listener unavailable")
	}
	defer publicListener.Close()
	managementListener, e := net.Listen("tcp", c.Operations.Listen)
	if e != nil {
		return errors.New("management listener unavailable")
	}
	defer managementListener.Close()
	server := func(address string, handler http.Handler) *http.Server {
		return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	}
	public := server(c.Listen, gateway.New(c, db, adapters, ops).Handler())
	management := server(c.Operations.Listen, ops.Handler(c, info))
	done := make(chan error, 2)
	go func() { done <- public.Serve(publicListener) }()
	go func() { done <- management.Serve(managementListener) }()
	ops.Log.Info().Int("providers", len(adapters)).Int("bindings", len(c.Bindings)).Msg("porter_started")
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	var serveError error
selectLoop:
	for {
		select {
		case e = <-done:
			if !errors.Is(e, http.ErrServerClosed) {
				serveError = errors.New("HTTP server stopped unexpectedly")
			}
			break selectLoop
		case <-tick.C:
			ops.Maintenance(db.Prune(time.Now()))
		case <-ctx.Done():
			break selectLoop
		}
	}
	ops.Drain()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e = public.Shutdown(shutdown); e != nil {
		_ = public.Close()
		serveError = errors.New("public server shutdown timed out")
	}
	managementShutdown, managementCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer managementCancel()
	if e = management.Shutdown(managementShutdown); e != nil {
		_ = management.Close()
		serveError = errors.New("management server shutdown timed out")
	}
	ops.Log.Info().Msg("porter_stopped")
	return serveError
}
