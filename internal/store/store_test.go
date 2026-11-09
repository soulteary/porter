package store

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConsumeAtomicAndBound(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r := Record{Expires: time.Now().Add(time.Minute), Provider: "github", Browser: Key("browser")}
	if e = s.Start("state", "browser", "", r); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][2]string{{"wrong", "github"}, {"browser", "qq"}} {
		if _, e = s.Consume("state", args[0], args[1]); !errors.Is(e, ErrMissing) {
			t.Fatal(e)
		}
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, e := s.Consume("state", "browser", "github"); e == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("consumed %d times", successes.Load())
	}
}
func TestPersistenceExpiryAndRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Put("sessions", "session", Record{Expires: time.Now().Add(time.Hour), Subject: "123"}); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if r, e := s.Get("sessions", "session"); e != nil || r.Subject != "123" {
		t.Fatal(r, e)
	}
	if e = s.Delete("sessions", "session"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get("sessions", "session"); !errors.Is(e, ErrMissing) {
		t.Fatal(e)
	}
	if e = s.Put("sessions", "expired", Record{Expires: time.Now().Add(-time.Second)}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get("sessions", "expired"); !errors.Is(e, ErrMissing) {
		t.Fatal(e)
	}
	if e = s.Prune(time.Now()); e != nil {
		t.Fatal(e)
	}
}

func TestFamilyRevocationAndAtomicRotation(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	expiry := time.Now().Add(time.Hour)
	if e = s.Start("state", "browser", "", Record{Expires: expiry, Provider: "github"}); e != nil {
		t.Fatal(e)
	}
	tx, e := s.Consume("state", "browser", "github")
	if e != nil {
		t.Fatal(e)
	}
	r := Record{Expires: expiry, Browser: tx.Browser, UserID: "u1", Binding: "revision"}
	if e = s.RotateSession("old", "", r); e != nil {
		t.Fatal(e)
	}
	if e = s.RotateSession("new", "old", r); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Session("old"); !errors.Is(e, ErrMissing) {
		t.Fatal("old session survived", e)
	}
	if _, e = s.Session("new"); e != nil {
		t.Fatal(e)
	}
	if e = s.Revoke("", "browser"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Session("new"); !errors.Is(e, ErrMissing) {
		t.Fatal("revoked family survived", e)
	}
	if e = s.RotateSession("after-logout", "", r); !errors.Is(e, ErrMissing) {
		t.Fatal("revoked callback issued session", e)
	}
}

func TestBindingRemovalCannotBeUndoneByConfigRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	expiry := time.Now().Add(time.Hour)
	if e = s.Start("state", "browser", "", Record{Expires: expiry, Provider: "github"}); e != nil {
		t.Fatal(e)
	}
	if e = s.RotateSession("session", "", Record{Expires: expiry, UserID: "u1", Binding: "original", Browser: Key("browser")}); e != nil {
		t.Fatal(e)
	}
	if e = s.ReconcileBindings(map[string]bool{}); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.ReconcileBindings(map[string]bool{"original": true}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Session("session"); !errors.Is(e, ErrMissing) {
		t.Fatal("configuration rollback revived a revoked identity", e)
	}
}

func TestSessionPersistenceAndFamilyExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	expiry := time.Now().Add(time.Hour)
	if e = s.Start("state", "browser", "", Record{Expires: expiry, Provider: "github"}); e != nil {
		t.Fatal(e)
	}
	if e = s.RotateSession("session", "", Record{Expires: expiry, UserID: "u1", Binding: "revision", Browser: Key("browser")}); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if r, e := s.Session("session"); e != nil || r.UserID != "u1" || !r.Expires.Equal(expiry) {
		t.Fatal("session changed across restart", e)
	}
	if e = s.Put("families", "browser", Record{Expires: time.Now().Add(-time.Second)}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Session("session"); !errors.Is(e, ErrMissing) {
		t.Fatal("expired family authorized", e)
	}
}
