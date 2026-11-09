package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/gateway"
	"github.com/soulteary/porter/internal/provider"
	"github.com/soulteary/porter/internal/store"
)

func main() {
	if e := run(); e != nil {
		slog.Error("Porter stopped", "reason", e.Error())
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "porter.json", "configuration path")
	flag.Parse()
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	db, e := store.Open(c.Database)
	if e != nil {
		return e
	}
	defer db.Close()
	if e = db.Prune(time.Now()); e != nil {
		return e
	}
	// Never follow upstream redirects carrying credentials or tokens.
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	adapters := map[string]provider.Adapter{}
	for name, p := range c.Providers {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		a, err := provider.New(ctx, name, p, c.PublicURL+"/callback/"+name, client)
		cancel()
		if err != nil {
			return err
		}
		adapters[name] = a
	}
	srv := &http.Server{Addr: c.Listen, Handler: gateway.New(c, db, adapters).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case e = <-done:
			if e == http.ErrServerClosed {
				return nil
			}
			return e
		case <-tick.C:
			if e = db.Prune(time.Now()); e != nil {
				slog.Error("storage maintenance failed")
			}
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return srv.Shutdown(shutdown)
		}
	}
}
