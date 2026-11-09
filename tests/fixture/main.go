// This test-only helper is compiled against the pinned baseline, never shipped
// in Porter's production image. All identities and credentials are synthetic.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/store"
)

const dir = "/data"

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func write(path string, value any) {
	data, err := json.Marshal(value)
	must(err)
	must(os.WriteFile(path, data, 0600))
	must(os.Chown(path, 65532, 65532))
}
func load() config.Config { c, err := config.Load(dir + "/porter.json"); must(err); return c }
func main() {
	if len(os.Args) != 2 {
		panic("expected fixture command")
	}
	switch os.Args[1] {
	case "unsafe-audit":
		must(os.Chmod(dir+"/audit.jsonl", 0644))
	case "seed":
		seed()
	case "verify":
		verify()
	case "change-binding", "restore-binding":
		c := load()
		c.Bindings[0].UserID = "changed-user"
		if os.Args[1] == "restore-binding" {
			c.Bindings[0].UserID = "u1"
		}
		write(dir+"/porter.json", c)
	default:
		panic("unknown fixture command")
	}
}
func seed() {
	must(os.Chown(dir, 65532, 65532))
	must(os.Chmod(dir, 0700))
	c := config.Config{Listen: ":8083", PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", Database: dir + "/porter.db", ProxyKey: strings.Repeat("p", 32), Providers: map[string]config.Provider{"github": {ClientID: "app", ClientSecret: "FIXTURE_SECRET"}}, Bindings: []config.Binding{{Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Mail: "fixture@example.test"}}, Operations: config.Operations{Listen: "0.0.0.0:9093", Key: strings.Repeat("m", 32), AuditFile: dir + "/audit.jsonl"}}
	must(c.Validate())
	write(dir+"/porter.json", c)
	db, err := store.Open(c.Database)
	must(err)
	expires := time.Now().UTC().Add(time.Hour)
	for _, token := range []string{"L", "C", "R", "E"} {
		state, browser := strings.Repeat(token+"s", 22), strings.Repeat(token+"b", 22)
		record := store.Record{Expires: expires, Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Binding: c.Bindings[0].Revision()}
		must(db.Start(state, browser, "", record))
		tx, err := db.Consume(state, browser, "github")
		must(err)
		record.Browser = tx.Browser
		must(db.RotateSession(strings.Repeat(token, 43), "", record))
		if token == "R" {
			must(db.Revoke(strings.Repeat(token, 43), ""))
		}
		if token == "E" {
			record.Expires = time.Now().Add(-time.Hour)
			must(db.Put("sessions", strings.Repeat(token, 43), record))
		}
	}
	must(db.Start(strings.Repeat("P", 43), strings.Repeat("B", 43), "", store.Record{Expires: expires, Provider: "github", Verifier: "baseline-verifier", Nonce: "baseline-nonce"}))
	must(db.Close())
	must(os.Chown(c.Database, 65532, 65532))
	write(dir+"/expected.json", expires)
	fmt.Println("baseline fixture created")
}
func verify() {
	c := load()
	db, err := store.Open(c.Database)
	must(err)
	defer db.Close()
	data, err := os.ReadFile(dir + "/expected.json")
	must(err)
	var expected time.Time
	must(json.Unmarshal(data, &expected))
	session, err := db.Session(strings.Repeat("C", 43))
	must(err)
	if !session.Expires.Equal(expected) {
		panic("session expiry changed across upgrade")
	}
	for _, token := range []string{"L", "R", "E"} {
		if _, err := db.Session(strings.Repeat(token, 43)); !errors.Is(err, store.ErrMissing) {
			panic("revoked or expired session revived")
		}
	}
	tx, err := db.Consume(strings.Repeat("P", 43), strings.Repeat("B", 43), "github")
	must(err)
	if !tx.Expires.Equal(expected) || tx.Verifier != "baseline-verifier" || tx.Nonce != "baseline-nonce" {
		panic("pending transaction changed")
	}
	if _, err := db.Consume(strings.Repeat("P", 43), strings.Repeat("B", 43), "github"); !errors.Is(err, store.ErrMissing) {
		panic("transaction replay accepted")
	}
	data, err = os.ReadFile(dir + "/audit.jsonl")
	must(err)
	if !strings.Contains(string(data), "login_started") || !strings.Contains(string(data), `"event_type":"logout"`) {
		panic("audit not flushed")
	}
	for _, secret := range []string{"FIXTURE_SECRET", "fixture@example.test", strings.Repeat("L", 43), strings.Repeat("p", 32), strings.Repeat("m", 32)} {
		if strings.Contains(string(data), secret) {
			panic("audit disclosed sensitive data")
		}
	}
	for _, name := range []string{"porter.db", "audit.jsonl"} {
		st, err := os.Stat(filepath.Join(dir, name))
		must(err)
		if st.Mode().Perm() != 0600 {
			panic("private file permissions changed")
		}
	}
	fmt.Println("baseline verified expiry, revocation, pending transaction and private audit")
}
