package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/store"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConfigSourcePrecedenceAndVersionIsolation(t *testing.T) {
	c := configuration(t)
	path := writeConfig(t, c)
	t.Setenv("PORTER_CONFIG_FILE", "SECRET-missing")
	for _, args := range [][]string{{"version", "--json"}, {"check-config", "--config", path}, {"doctor", "--config", path, "--json"}} {
		var out, logs bytes.Buffer
		if err := run(context.Background(), args, &out, &logs); err != nil {
			t.Fatal(args, err)
		}
	}
	t.Setenv("PORTER_CONFIG_FILE", path)
	for _, command := range []string{"check-config", "doctor"} {
		var out, logs bytes.Buffer
		if err := run(context.Background(), []string{command, "--json"}, &out, &logs); err != nil {
			t.Fatal(command, err)
		}
	}
	var out, logs bytes.Buffer
	if err := run(context.Background(), []string{"check-config", "--config", "SECRET-missing", "--json"}, &out, &logs); err == nil || strings.Contains(out.String()+logs.String()+err.Error(), "SECRET") {
		t.Fatal("explicit CLI source was ignored or exposed", err)
	}
}
func TestEveryConfigCommandRejectsSecretSourcesWithoutDisclosure(t *testing.T) {
	c := configuration(t)
	dir := filepath.Dir(c.Database)
	c.ProxyKey = ""
	c.ProxyKeyFile = filepath.Join(dir, "SECRET-missing")
	path := writeConfig(t, c)
	for _, command := range []string{"serve", "check-config", "doctor"} {
		var out, logs bytes.Buffer
		err := run(context.Background(), []string{command, "--config", path}, &out, &logs)
		if err == nil || strings.Contains(out.String()+logs.String()+err.Error(), "SECRET") || strings.Contains(out.String()+err.Error(), dir) {
			t.Fatal("command accepted or exposed secret file failure", command, err)
		}
	}
	if _, err := os.Stat(c.Database); !os.IsNotExist(err) {
		t.Fatal("invalid secret initialized database")
	}
	if _, err := os.Stat(c.Operations.AuditFile); !os.IsNotExist(err) {
		t.Fatal("invalid secret initialized audit")
	}
}
func TestSecretCommandsHaveNoRuntimeSideEffects(t *testing.T) {
	c := configuration(t)
	secret := c.ProxyKey
	c.ProxyKey = ""
	c.ProxyKeyFile = "proxy-key"
	if err := os.WriteFile(filepath.Join(filepath.Dir(c.Database), c.ProxyKeyFile), []byte(secret+"\n"), 0400); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(c.Database), "porter.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"check-config", "doctor"} {
		var out, logs bytes.Buffer
		if err = run(context.Background(), []string{command, "--config", path, "--json"}, &out, &logs); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String()+logs.String(), secret) {
			t.Fatal("resolved secret printed")
		}
	}
	if _, err = os.Stat(c.Database); !os.IsNotExist(err) {
		t.Fatal("diagnostic created database")
	}
}

func TestFileSecretRestartPreservesSessionAndPinsLoadedKey(t *testing.T) {
	c := configuration(t)
	c.Bindings = []config.Binding{{Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Mail: "fixture@example.test"}}
	db, err := store.Open(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Hour)
	if err = db.Start("state", "browser", "", store.Record{Provider: "github", Expires: deadline}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Consume("state", "browser", "github")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("C", 43)
	if err = db.RotateSession(token, "", store.Record{Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Binding: c.Bindings[0].Revision(), Browser: tx.Browser, Expires: deadline}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	address := func() string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		value := listener.Addr().String()
		listener.Close()
		return value
	}
	c.Listen = address()
	c.Operations.Listen = address()
	old := c.ProxyKey
	dir := filepath.Dir(c.Database)
	c.ProxyKeyFile = "proxy-key"
	c.ProxyKey = ""
	keyPath := filepath.Join(dir, c.ProxyKeyFile)
	writeKey := func(value string) {
		if err := os.WriteFile(keyPath, []byte(value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeKey(old)
	p := c.Providers["github"]
	p.ClientSecretFile = "provider-key"
	p.ClientSecret = ""
	c.Providers["github"] = p
	if err = os.WriteFile(filepath.Join(dir, p.ClientSecretFile), []byte("provider-SECRET\n"), 0400); err != nil {
		t.Fatal(err)
	}
	c.Operations.KeyFile = "management-key"
	management := strings.Repeat("m", 32)
	if err = os.WriteFile(filepath.Join(dir, c.Operations.KeyFile), []byte(management), 0400); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, c)
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request := func(method, route, key string, expected int) {
		req, _ := http.NewRequest(method, "http://"+c.Listen+route, nil)
		req.Host = "porter.test"
		req.Header.Set("Origin", c.PublicURL)
		req.Header.Set("Authorization", "Bearer "+key)
		req.AddCookie(&http.Cookie{Name: "__Host-porter_session", Value: token})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != expected {
			t.Fatalf("%s returned %d, want %d", route, resp.StatusCode, expected)
		}
	}
	launch := func() func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		logs := &signalLog{started: make(chan struct{})}
		go func() { done <- run(ctx, []string{"serve", "--config", path}, io.Discard, logs) }()
		select {
		case <-logs.started:
		case err := <-done:
			cancel()
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("file-secret service did not start")
		}
		var once sync.Once
		stop := func() {
			once.Do(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("file-secret service did not stop")
				}
				logs.mu.Lock()
				defer logs.mu.Unlock()
				for _, value := range []string{old, strings.Repeat("x", 32), management, "provider-SECRET", token} {
					if strings.Contains(logs.Buffer.String(), value) {
						t.Error("secret in runtime logs")
					}
				}
			})
		}
		t.Cleanup(stop)
		return stop
	}
	stop := launch()
	request("GET", "/identity", old, 200)
	next := strings.Repeat("x", 32)
	writeKey(next)
	request("GET", "/identity", old, 200) // Files are not hot-reloaded.
	stop()
	stop = launch()
	request("GET", "/identity", old, 401)
	request("GET", "/identity", next, 200)
	request("POST", "/logout", next, 303)
	stop()
	stop = launch()
	request("GET", "/identity", next, 401)
	stop()
	db, err = store.Open(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Session(token); !errors.Is(err, store.ErrMissing) {
		t.Fatal("restart revived revoked session", err)
	}
}
