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
	if e = s.Put("transactions", "state", r); e != nil {
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
