package main

import (
	"bytes"
	"errors"
	"github.com/soulteary/porter/internal/config"
	"github.com/soulteary/porter/internal/gateway"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

func TestRestoreDoesNotRetainAuthenticationPages(t *testing.T) {
	d := directory(t)
	source := filepath.Join(d, "source.db")
	snapshot := filepath.Join(d, "snapshot.db")
	output := filepath.Join(d, "recovered.db")
	db := seed(t, source)
	db.Close()
	sum, err := operate("backup", source, snapshot, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = operate("restore", snapshot, output, sum, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{store.Key("session-SECRET"), store.Key("state-SECRET"), store.Key("browser-SECRET")} {
		if bytes.Contains(data, []byte(key)) {
			t.Fatal("recovered file retains old authentication pages")
		}
	}
}

func TestRestoreMetaFallbackCannotReviveSnapshotSession(t *testing.T) {
	d := directory(t)
	source := filepath.Join(d, "source.db")
	snapshot := filepath.Join(d, "snapshot.db")
	output := filepath.Join(d, "recovered.db")
	db := seed(t, source)
	db.Close()
	sum, err := operate("backup", source, snapshot, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = operate("restore", snapshot, output, sum, true); err != nil {
		t.Fatal(err)
	}
	damageNewestMeta(t, output)
	recovered, err := store.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if _, err = recovered.Session("session-SECRET"); !errors.Is(err, store.ErrMissing) {
		t.Fatal("meta fallback revived snapshot session", err)
	}
	if _, err = recovered.Consume("state-SECRET", "browser-SECRET", "github"); !errors.Is(err, store.ErrMissing) {
		t.Fatal("meta fallback revived pending callback", err)
	}
}

func damageNewestMeta(t *testing.T, path string) {
	t.Helper()
	raw, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var offset int64
	err = raw.View(func(tx *bolt.Tx) error { offset = int64(tx.ID()%2)*int64(raw.Info().PageSize) + 16; return nil })
	raw.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Damage only the newest meta page's magic. bbolt may select the other
	// valid page, which must never refer to the snapshot's login records.
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	_, err = f.ReadAt(one, offset)
	if err != nil {
		t.Fatal(err)
	}
	one[0] ^= 0xff
	_, err = f.WriteAt(one, offset)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestRecoveredMetaFallbackRejectsIdentityAndStargate(t *testing.T) {
	d := directory(t)
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-Stargate-Header-Auth") != strings.Repeat("s", 32) || r.Header.Get("X-User-Mail") != "owner@example.test" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("Stargate credential or identity boundary changed")
		}
		w.Header().Set("X-Auth-User", "u1")
		w.Header().Set("X-Forwarded-User", "u1")
		w.Header().Set("Set-Cookie", "SECRET=upstream")
	}))
	defer upstream.Close()
	binding := config.Binding{Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Mail: "owner@example.test"}
	c := config.Config{PublicURL: "https://porter.test", LandingURL: "https://porter.test/app", Database: filepath.Join(d, "source.db"), ProxyKey: strings.Repeat("p", 32), StargateURL: upstream.URL + "/_auth", StargateSecret: strings.Repeat("s", 32), Providers: map[string]config.Provider{"github": {ClientID: "app", ClientSecret: "SECRET"}}, Bindings: []config.Binding{binding}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	token, browser := strings.Repeat("T", 43), strings.Repeat("B", 43)
	expiry := time.Now().Add(time.Hour)
	if err = db.Start("pending", browser, "", store.Record{Provider: "github", Expires: expiry}); err != nil {
		t.Fatal(err)
	}
	if err = db.RotateSession(token, "", store.Record{Provider: "github", Namespace: "app", Subject: "subject", UserID: "u1", Binding: binding.Revision(), Browser: store.Key(browser), Expires: expiry}); err != nil {
		t.Fatal(err)
	}
	checkGateway := func(s *store.Store, status int) {
		t.Helper()
		g := gateway.New(c, s, nil)
		defer g.CloseIdleConnections()
		for _, route := range []string{"/identity", "/auth"} {
			req := httptest.NewRequest("GET", c.PublicURL+route, nil)
			req.AddCookie(&http.Cookie{Name: "__Host-porter_session", Value: token})
			req.Header.Set("Authorization", "Bearer "+c.ProxyKey)
			req.Header.Set("X-User-Mail", "attacker@example.test")
			req.Header.Set("X-Stargate-Header-Auth", "attacker")
			req.Header.Set("X-Forwarded-Uri", "/app")
			req.Header.Set("X-Forwarded-Method", "GET")
			req.Header.Set("X-Forwarded-Host", "porter.test")
			req.Header.Set("X-Forwarded-Proto", "https")
			response := httptest.NewRecorder()
			g.Handler().ServeHTTP(response, req)
			if response.Code != status || response.Header().Get("Set-Cookie") != "" {
				t.Fatal("unexpected proxy response", route, response.Code)
			}
		}
	}
	checkGateway(db, 200)
	db.Close()
	snapshot, output := filepath.Join(d, "snapshot.db"), filepath.Join(d, "recovered.db")
	sum, err := operate("backup", c.Database, snapshot, "", true)
	if err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Revoke(token, browser); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err = operate("restore", snapshot, output, sum, true); err != nil {
		t.Fatal(err)
	}
	damageNewestMeta(t, output)
	recovered, err := store.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	checkGateway(recovered, 401)
	if hits.Load() != 1 {
		t.Fatal("recovered snapshot delegated revoked identity to Stargate")
	}
}
