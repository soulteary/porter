// Test-only initializer and private-network peer. No real application credentials.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/store"
)

const uid = "porter-fixture-user"

func must(err error) {
	if err != nil {
		panic("contract fixture failed")
	}
}
func write(path string, data []byte, mode os.FileMode, owner int) {
	must(os.WriteFile(path, data, mode))
	must(os.Chmod(path, mode))
	must(os.Chown(path, owner, owner))
}
func users(id, status string) {
	data, err := json.Marshal([]map[string]any{{"user_id": id, "mail": "fixture@example.test", "status": status, "role": "user", "scope": []string{"read"}, "name": "Fixture"}})
	must(err)
	write("/fixture/users.json", data, 0644, 10001)
}
func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	switch os.Args[1] {
	case "init":
		must(os.Chmod("/fixture", 0755))
		must(os.Chmod("/data", 0700))
		must(os.Chown("/data", 65532, 65532))
		c := config.Config{Listen: ":8083", PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", Database: "/data/porter.db", ProxyKey: strings.Repeat("p", 32), StargateURL: "http://stargate:8080/_auth", StargateSecret: strings.Repeat("s", 32), AllowInsecureStargate: true, Providers: map[string]config.Provider{"github": {ClientID: "app", ClientSecret: "provider-SECRET"}}, Bindings: []config.Binding{{Provider: "github", Namespace: "app", Subject: "subject", UserID: uid, Mail: "fixture@example.test"}}, Operations: config.Operations{Listen: "127.0.0.1:9093", AuditFile: "/data/audit.jsonl"}}
		must(c.Validate())
		data, err := json.Marshal(c)
		must(err)
		write("/fixture/porter.json", data, 0600, 65532)
		users(uid, "active")
		db, err := store.Open(c.Database)
		must(err)
		expiry := time.Now().Add(time.Hour)
		must(db.Start("state", "browser", "", store.Record{Expires: expiry, Provider: "github"}))
		tx, err := db.Consume("state", "browser", "github")
		must(err)
		must(db.RotateSession(strings.Repeat("T", 43), "", store.Record{Expires: expiry, Provider: "github", Namespace: "app", Subject: "subject", UserID: uid, Binding: c.Bindings[0].Revision(), Browser: tx.Browser}))
		must(db.Close())
		must(os.Chown(c.Database, 65532, 65532))
	case "reassign":
		users("reassigned-user", "active")
	case "disable":
		users(uid, "inactive")
	case "restore":
		users(uid, "active")
	case "request":
		req, err := http.NewRequest(os.Args[2], os.Args[3], nil)
		must(err)
		req.Host = "porter.test"
		req.Header.Set("Origin", "https://porter.test")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Forwarded-Uri", "/app")
		req.Header.Set("X-Forwarded-Method", "GET")
		req.Header.Set("X-Forwarded-Host", "porter.test")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-User-Mail", "attacker@example.test")
		req.Header.Set("X-Auth-User", "attacker")
		req.Header.Set("X-Forwarded-User", "attacker")
		req.Header.Set("X-Stargate-Header-Auth", "attacker")
		mode := ""
		if len(os.Args) > 4 {
			mode = os.Args[4]
		}
		if mode == "proxy" || mode == "proxy-only" || mode == "wrong-context" {
			req.Header.Set("Authorization", "Bearer "+strings.Repeat("p", 32))
		}
		if mode == "wrong-proxy" {
			req.Header.Set("Authorization", "Bearer attacker")
		}
		if mode == "proxy" || mode == "session-only" || mode == "wrong-proxy" || mode == "wrong-context" {
			req.AddCookie(&http.Cookie{Name: "__Host-porter_session", Value: strings.Repeat("T", 43)})
		}
		if mode == "wrong-context" {
			req.Header.Set("X-Forwarded-Host", "attacker.invalid")
		}
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(`{"status":0}`)
			return
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		// Capture only the output contract, never request credentials or cookies.
		headers := map[string]string{}
		for _, key := range []string{"X-Auth-User", "X-Forwarded-User", "X-Auth-Email", "X-Auth-Phone", "X-Auth-Name", "X-Auth-Role", "X-Auth-Scopes"} {
			if value := resp.Header.Get(key); value != "" {
				headers[key] = value
			}
		}
		// Report every header name/count, including empty or duplicate sensitive
		// headers, without printing their values to acceptance diagnostics.
		counts := map[string]int{}
		for name, values := range resp.Header {
			counts[strings.ToLower(name)] = len(values)
		}
		must(json.NewEncoder(os.Stdout).Encode(map[string]any{"status": resp.StatusCode, "headers": headers, "header_counts": counts}))
	default:
		os.Exit(1)
	}
}
