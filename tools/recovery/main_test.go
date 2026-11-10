package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/soulteary/porter/internal/store"
	bolt "go.etcd.io/bbolt"
)

func directory(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	return d
}
func seed(t *testing.T, path string) *store.Store {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour)
	if err = db.Start("state-SECRET", "browser-SECRET", "", store.Record{Provider: "github", Expires: expiry}); err != nil {
		t.Fatal(err)
	}
	if err = db.RotateSession("session-SECRET", "", store.Record{UserID: "u1", Binding: "binding", Browser: store.Key("browser-SECRET"), Expires: expiry}); err != nil {
		t.Fatal(err)
	}
	return db
}
func TestRecoveryInvalidatesSnapshotLoginState(t *testing.T) {
	d := directory(t)
	source := filepath.Join(d, "source.db")
	snapshot := filepath.Join(d, "snapshot.db")
	output := filepath.Join(d, "recovered.db")
	db := seed(t, source)
	if _, err := operate("backup", source, snapshot, "", true); err == nil {
		t.Fatal("live writer backed up")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(source)
	sum, err := operate("backup", source, snapshot, "", true)
	if err != nil {
		t.Fatal(err)
	}
	afterBackup, _ := os.ReadFile(source)
	if !bytes.Equal(before, afterBackup) {
		t.Fatal("backup changed source")
	}
	snapBefore, _ := os.ReadFile(snapshot)
	db, err = store.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Revoke("session-SECRET", "browser-SECRET"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	// Snapshot predates logout, so ordinary restoration would resurrect the session.
	old, err := store.Open(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = old.Session("session-SECRET"); err != nil {
		t.Fatal("fixture has no live snapshot session", err)
	}
	old.Close()
	// Opening through store can update database metadata; restore the original fixture.
	if err = os.WriteFile(snapshot, snapBefore, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = operate("restore", snapshot, output, sum, true); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recovered.Session("session-SECRET"); !errors.Is(err, store.ErrMissing) {
		t.Fatal("snapshot session revived", err)
	}
	if _, err = recovered.Consume("state-SECRET", "browser-SECRET", "github"); !errors.Is(err, store.ErrMissing) {
		t.Fatal("pending callback revived", err)
	}
	// Restored database still supports a new, normal login and persistent logout.
	expiry := time.Now().Add(time.Hour)
	if err = recovered.Start("new-state", "new-browser", "", store.Record{Expires: expiry, Provider: "github"}); err != nil {
		t.Fatal(err)
	}
	tx, err := recovered.Consume("new-state", "new-browser", "github")
	if err != nil {
		t.Fatal(err)
	}
	if err = recovered.RotateSession("new-session", "", store.Record{Expires: expiry, UserID: "u1", Binding: "binding", Browser: tx.Browser}); err != nil {
		t.Fatal(err)
	}
	if err = recovered.Revoke("new-session", ""); err != nil {
		t.Fatal(err)
	}
	recovered.Close()
	recovered, err = store.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if _, err = recovered.Session("new-session"); !errors.Is(err, store.ErrMissing) {
		t.Fatal("new logout lost", err)
	}
	snapAfter, _ := os.ReadFile(snapshot)
	if !bytes.Equal(snapBefore, snapAfter) {
		t.Fatal("snapshot modified")
	}
	st, _ := os.Stat(output)
	if st.Mode().Perm() != 0600 {
		t.Fatal("unsafe restore mode")
	}
}
func TestRefusesUnsafeOrInvalidRecovery(t *testing.T) {
	d := directory(t)
	source := filepath.Join(d, "source.db")
	db := seed(t, source)
	db.Close()
	snapshot := filepath.Join(d, "snapshot.db")
	sum, err := operate("backup", source, snapshot, "", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command, src, dst, hash string
		stopped                       bool
	}{
		{"confirmation", "backup", source, filepath.Join(d, "none.db"), "", false},
		{"overwrite", "backup", source, snapshot, "", true},
		{"alias", "backup", source, source, "", true},
		{"checksum", "restore", snapshot, filepath.Join(d, "bad.db"), strings.Repeat("0", 64), true},
		{"missing checksum", "restore", snapshot, filepath.Join(d, "missing.db"), "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := operate(tc.command, tc.src, tc.dst, tc.hash, tc.stopped); err == nil {
				t.Fatal("unsafe operation accepted")
			}
		})
	}
	linked := filepath.Join(d, "linked.db")
	os.Symlink(source, linked)
	if _, err := operate("backup", linked, filepath.Join(d, "link-output.db"), "", true); err == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(snapshot, 0644)
	if _, err := operate("restore", snapshot, filepath.Join(d, "public.db"), sum, true); err == nil {
		t.Fatal("public snapshot accepted")
	}
	os.Chmod(snapshot, 0600)
	data, _ := os.ReadFile(snapshot)
	data[len(data)/2] ^= 1
	os.WriteFile(snapshot, data, 0600)
	if _, err := operate("restore", snapshot, filepath.Join(d, "corrupt.db"), sum, true); err == nil {
		t.Fatal("corruption accepted")
	}
	output := new(bytes.Buffer)
	if err := run([]string{"restore", "--source", source, "--destination", filepath.Join(d, "redacted.db"), "--sha256", "SECRET", "--stopped"}, output); err == nil || strings.Contains(err.Error()+output.String(), d) || strings.Contains(err.Error()+output.String(), "SECRET") {
		t.Fatal("unsafe diagnostic", err)
	}
	files, _ := filepath.Glob(filepath.Join(d, ".porter-recovery-*"))
	if len(files) != 0 {
		t.Fatal("temporary outputs leaked")
	}
}
func TestRejectsUnknownSchema(t *testing.T) {
	d := directory(t)
	source := filepath.Join(d, "future.db")
	db := seed(t, source)
	db.Close()
	b, err := bolt.Open(source, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = b.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket([]byte("future")); return err })
	b.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = operate("backup", source, filepath.Join(d, "out.db"), "", true); err == nil {
		t.Fatal("unknown schema accepted")
	}
}
