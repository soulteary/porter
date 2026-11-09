package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/config"
	versionkit "github.com/soulteary/version-kit/v4"
)

func configuration(t *testing.T) config.Config {
	t.Helper()
	c := config.Config{PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", Database: filepath.Join(t.TempDir(), "porter.db"), ProxyKey: strings.Repeat("p", 32), Providers: map[string]config.Provider{"github": {ClientID: "app", ClientSecret: "SECRET"}}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c
}
func writeConfig(t *testing.T, c config.Config) string {
	t.Helper()
	p := filepath.Join(filepath.Dir(c.Database), "porter.json")
	data, _ := json.Marshal(c)
	if e := os.WriteFile(p, data, 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestCommandsDoNotStartService(t *testing.T) {
	c := configuration(t)
	path := writeConfig(t, c)
	for _, args := range [][]string{{"version", "--json", "--config", "does-not-exist"}, {"--version"}, {"check-config", "--config", path, "--json"}, {"doctor", "--config", path, "--json"}} {
		var out, logs bytes.Buffer
		if e := run(context.Background(), args, &out, &logs); e != nil {
			t.Fatal(args, e)
		}
		if out.Len() == 0 || strings.Contains(out.String()+logs.String(), "SECRET") {
			t.Fatal(out.String(), logs.String())
		}
		if _, e := os.Stat(c.Database); !os.IsNotExist(e) {
			t.Fatal("command opened database")
		}
		if _, e := os.Stat(c.Operations.AuditFile); !os.IsNotExist(e) {
			t.Fatal("command initialized audit")
		}
	}
}
func TestInvalidConfigurationOutputIsRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SECRET-config.json")
	if e := os.WriteFile(path, []byte(`{"SECRET":"SECRET"}`), 0600); e != nil {
		t.Fatal(e)
	}
	var out, logs bytes.Buffer
	e := run(context.Background(), []string{"check-config", "--config", path, "--json"}, &out, &logs)
	if e == nil || !strings.Contains(out.String(), `"ok":false`) || strings.Contains(out.String()+logs.String()+e.Error(), "SECRET") {
		t.Fatal(e, out.String())
	}
	if e = run(context.Background(), []string{"SECRET-command"}, &out, &logs); e == nil || strings.Contains(e.Error(), "SECRET") {
		t.Fatal(e)
	}
}

type signalLog struct {
	mu sync.Mutex
	bytes.Buffer
	once    sync.Once
	started chan struct{}
}

func (w *signalLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if bytes.Contains(p, []byte("porter_started")) {
		w.once.Do(func() { close(w.started) })
	}
	return w.Buffer.Write(p)
}
func TestServeStopsBothListenersAndFlushesAudit(t *testing.T) {
	c := configuration(t)
	public, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	management, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	c.Listen = public.Addr().String()
	c.Operations.Listen = management.Addr().String()
	public.Close()
	management.Close()
	logs := &signalLog{started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, c, versionkit.New("test", "abc123", "unknown"), logs) }()
	select {
	case <-logs.started:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(5 * time.Second):
		t.Fatal("service did not start")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	for _, path := range []string{"/readyz", "/version", "/metrics"} {
		resp, e := client.Get("http://" + c.Operations.Listen + path)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal(path, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest("GET", "http://"+c.Listen+"/metrics", nil)
	req.Host = "porter.test"
	resp, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("management endpoint on public listener")
	}
	req, _ = http.NewRequest("POST", "http://"+c.Listen+"/login/github", nil)
	req.Host = "porter.test"
	req.Header.Set("Origin", c.PublicURL)
	resp, e = client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("login changed", resp.StatusCode)
	}
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("service did not stop")
	}
	data, e := os.ReadFile(c.Operations.AuditFile)
	if e != nil || !bytes.Contains(data, []byte("login_started")) {
		t.Fatal("audit not drained", e, string(data))
	}
	for _, address := range []string{c.Listen, c.Operations.Listen} {
		conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			t.Fatal("listener survived shutdown")
		}
	}
}

func TestCheckConfigExplainsRulesWithoutEchoingValues(t *testing.T) {
	c := configuration(t)
	c.Operations.Listen = "0.0.0.0:9093"
	c.Operations.Key = ""
	path := writeConfig(t, c)
	var out, logs bytes.Buffer
	if e := run(context.Background(), []string{"check-config", "--config", path, "--json"}, &out, &logs); e == nil || !strings.Contains(out.String(), "operations.key") || strings.Contains(out.String(), "SECRET") {
		t.Fatal(e, out.String())
	}
}
