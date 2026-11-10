// Test-only peer and volume initializer. All credentials and identities are synthetic.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/store"
)

var oldKey = strings.Repeat("m", 32)
var nextKey = strings.Repeat("n", 32)

func must(err error) {
	if err != nil {
		panic("operations fixture failed")
	}
}
func write(path string, data []byte, mode os.FileMode) {
	must(os.WriteFile(path, data, mode))
	must(os.Chmod(path, mode))
	must(os.Chown(path, 65532, 65534))
}
func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	switch os.Args[1] {
	case "init":
		must(os.Chmod("/fixture", 0750))
		must(os.Chown("/fixture", 65532, 65534))
		must(os.MkdirAll("/fixture/secrets", 0750))
		must(os.Chown("/fixture/secrets", 65532, 65534))
		must(os.Chmod("/data", 0700))
		must(os.Chown("/data", 65532, 65532))
		c := config.Config{Listen: ":8083", PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", Database: "/data/porter.db", ProxyKey: strings.Repeat("p", 32), Providers: map[string]config.Provider{"github": {ClientID: "app", ClientSecret: "provider-SECRET"}}, Bindings: []config.Binding{{Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Mail: "fixture@example.test"}}, Operations: config.Operations{Listen: os.Args[2] + ":9093", KeyFile: "secrets/management-key", AuditFile: "/data/audit.jsonl"}}
		// Validate resolved equivalent, then serialize file references only.
		c.Operations.Key = oldKey
		must(c.Validate())
		c.Operations.Key = ""
		data, err := json.Marshal(c)
		must(err)
		write("/fixture/porter.json", data, 0600)
		write("/fixture/secrets/management-key", []byte(oldKey), 0440)
		db, err := store.Open(c.Database)
		must(err)
		expiry := time.Now().Add(time.Hour)
		must(db.Start("state", "browser", "", store.Record{Expires: expiry, Provider: "github"}))
		tx, err := db.Consume("state", "browser", "github")
		must(err)
		must(db.RotateSession(strings.Repeat("C", 43), "", store.Record{Expires: expiry, Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Binding: c.Bindings[0].Revision(), Browser: tx.Browser}))
		must(db.Close())
		must(os.Chown(c.Database, 65532, 65532))
	case "rotate":
		write("/fixture/secrets/management-key", []byte(nextKey), 0440)
	case "request":
		req, err := http.NewRequest(os.Args[2], os.Args[3], nil)
		must(err)
		req.Host = "porter.test"
		req.Header.Set("Origin", "https://porter.test")
		if len(os.Args) > 4 {
			switch os.Args[4] {
			case "old":
				req.Header.Set("Authorization", "Bearer "+oldKey)
			case "new":
				req.Header.Set("Authorization", "Bearer "+nextKey)
			case "proxy":
				req.Header.Set("Authorization", "Bearer "+strings.Repeat("p", 32))
				req.AddCookie(&http.Cookie{Name: "__Host-porter_session", Value: strings.Repeat("C", 43)})
			}
		}
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(`{"status":0,"body":"unreachable"}`)
			return
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		must(err)
		must(json.NewEncoder(os.Stdout).Encode(map[string]any{"status": resp.StatusCode, "body": string(data)}))
	case "configure":
		// Configuration paths contain no credentials. Retain the repository rules,
		// shortening only their hold time for the isolated integration test.
		data, err := os.ReadFile("/source/prometheus.yml")
		must(err)
		text := strings.ReplaceAll(string(data), "30s", "5s")
		text = strings.ReplaceAll(text, "/etc/prometheus/porter.rules.yml", "/fixture/porter.rules.yml")
		text = strings.ReplaceAll(text, "/run/secrets/porter-management-key", "/fixture/secrets/management-key")
		text = strings.ReplaceAll(text, "porter:9093", os.Args[2]+":9093")
		text = strings.ReplaceAll(text, "blackbox:9115", os.Args[3]+":9115")
		write("/fixture/prometheus.yml", []byte(text), 0644)
		data, err = os.ReadFile("/source/blackbox.yml")
		must(err)
		write("/fixture/blackbox.yml", []byte(strings.ReplaceAll(string(data), "/run/secrets/porter-management-key", "/fixture/secrets/management-key")), 0644)
		data, err = os.ReadFile("/source/porter.rules.yml")
		must(err)
		write(filepath.Join("/fixture", "porter.rules.yml"), []byte(strings.ReplaceAll(string(data), "for: 2m", "for: 2s")), 0644)
	default:
		os.Exit(1)
	}
}
