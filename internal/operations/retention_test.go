package operations

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/observe"
	"github.com/soulteary/porter/internal/store"
	version "github.com/soulteary/version-kit/v4"
)

func TestAuditRestartAfterOfflineRotationKeepsSessionDeadline(t *testing.T) {
	c := configuration(t)
	binding := config.Binding{Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Mail: "fixture@example.test"}
	db, err := store.Open(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	deadline := time.Now().Add(time.Hour)
	if err = db.Start("state", "browser", "", store.Record{Provider: "github", Expires: deadline}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Consume("state", "browser", "github")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.RotateSession("token", "", store.Record{Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Binding: binding.Revision(), Browser: tx.Browser, Expires: deadline}); err != nil {
		t.Fatal(err)
	}
	start := func() *Runtime {
		r, err := New(c, db.Check, version.New("test", "test", "unknown"), &logBuffer{})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := start()
	r.Observe(context.Background(), observe.Event{Action: "login_start", Route: "/login/{provider}", Method: "POST", Provider: "github", Result: "success", Reason: "ok", Status: 200})
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(c.Operations.AuditFile)
	if err != nil {
		t.Fatal(err)
	}
	archive := c.Operations.AuditFile + ".20261110T000000000000Z"
	if err = os.Rename(c.Operations.AuditFile, archive); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.Operations.AuditFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	r = start()
	r.Observe(context.Background(), observe.Event{Action: "logout", Route: "/logout", Method: "POST", Provider: "none", Result: "success", Reason: "ok", Status: 303})
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(archive)
	if err != nil || string(old) != string(before) {
		t.Fatal("closed archive changed", err)
	}
	current, err := os.ReadFile(c.Operations.AuditFile)
	if err != nil || !strings.Contains(string(current), `"event_type":"logout"`) || strings.Contains(string(current), "login_started") {
		t.Fatal("restart did not use new journal", err)
	}
	session, err := db.Session("token")
	if err != nil || !session.Expires.Equal(deadline) {
		t.Fatal("audit rotation changed session state", err)
	}
}
