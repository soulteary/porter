package operations

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
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

func TestOfflineRetentionRefusesAnOpenBboltDatabase(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for retention integration")
	}
	c := configuration(t)
	if err := os.Chmod(filepath.Dir(c.Database), 0700); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	original := []byte("SECRET audit content\n")
	if err = os.WriteFile(c.Operations.AuditFile, original, 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func() ([]byte, error) {
		return exec.Command(python, "../../tools/audit-retention.py", "--directory", filepath.Dir(c.Database), "--journal", filepath.Base(c.Operations.AuditFile), "--database", filepath.Base(c.Database), "--rotate", "--apply", "--stopped").CombinedOutput()
	}
	output, err := invoke()
	if err == nil || !strings.Contains(string(output), "database is in use") {
		t.Fatal("retention did not reject the open bbolt database with a safe busy diagnostic")
	}
	if strings.Contains(string(output), "SECRET") || strings.Contains(string(output), filepath.Dir(c.Database)) {
		t.Fatal("retention disclosed sensitive context")
	}
	current, err := os.ReadFile(c.Operations.AuditFile)
	if err != nil || string(current) != string(original) {
		t.Fatal("locked database did not prevent journal changes", err)
	}
	before, err := os.ReadFile(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err = invoke(); err != nil {
		t.Fatalf("retention failed after bbolt closed: %s", output)
	}
	after, err := os.ReadFile(c.Database)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retention changed database contents", err)
	}
}
