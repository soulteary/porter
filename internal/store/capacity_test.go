package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Batch-fill fixtures without 10,000 individual filesystem syncs. Production
// writes still exercise the real cap and transaction rollback below.
func fill(t testing.TB, s *Store, bucket string, count int, expiry time.Time) {
	t.Helper()
	data, err := json.Marshal(Record{Expires: expiry})
	if err != nil {
		t.Fatal(err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		for i := 0; i < count; i++ {
			if err := b.Put([]byte(Key(fmt.Sprintf("capacity-%d", i))), data); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestCapacityFailureIsAtomicAndPruneRestoresAvailability(t *testing.T) {
	for _, bucket := range []string{"transactions", "families", "sessions"} {
		t.Run(bucket, func(t *testing.T) {
			s, err := Open(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			expiry := time.Now().Add(time.Hour)
			if err = s.Start("old-state", "old-browser", "", Record{Provider: "github", Expires: expiry}); err != nil {
				t.Fatal(err)
			}
			if err = s.RotateSession("old-session", "", Record{UserID: "u1", Binding: "binding", Browser: Key("old-browser"), Expires: expiry}); err != nil {
				t.Fatal(err)
			}
			// Exactly 10,000 records, including the original family/transaction/session.
			fill(t, s, bucket, 9999, time.Now().Add(-time.Hour))
			if bucket == "sessions" {
				err = s.RotateSession("new-session", "", Record{UserID: "u1", Binding: "binding", Browser: Key("old-browser"), Expires: expiry})
			} else {
				err = s.Start("new-state", "new-browser", "old-browser", Record{Provider: "github", Expires: expiry})
			}
			if !errors.Is(err, ErrCapacity) {
				t.Fatal("capacity not enforced", err)
			}
			if _, err = s.Session("old-session"); err != nil {
				t.Fatal("failed operation changed existing session", err)
			}
			if bucket != "sessions" {
				if _, err = s.Consume("old-state", "old-browser", "github"); err != nil {
					t.Fatal("failed start revoked previous family", err)
				}
			}
			if err = s.Prune(time.Now()); err != nil {
				t.Fatal(err)
			}
			if err = s.Start("after-prune", "after-browser", "", Record{Provider: "github", Expires: expiry}); err != nil {
				t.Fatal("cleanup did not restore capacity", err)
			}
		})
	}
}
func TestFullSessionBucketRefusesReplacementWithoutRevokingOld(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	expiry := time.Now().Add(time.Hour)
	if err = s.Start("state", "browser", "", Record{Expires: expiry, Provider: "github"}); err != nil {
		t.Fatal(err)
	}
	record := Record{Expires: expiry, UserID: "u1", Binding: "binding", Browser: Key("browser")}
	if err = s.RotateSession("old", "", record); err != nil {
		t.Fatal(err)
	}
	fill(t, s, "sessions", 9999, expiry)
	if err = s.RotateSession("new", "old", record); !errors.Is(err, ErrCapacity) {
		t.Fatal("full bucket accepted replacement", err)
	}
	if _, err = s.Session("new"); !errors.Is(err, ErrMissing) {
		t.Fatal("partial replacement issued a session", err)
	}
	current, err := s.Session("old")
	if err != nil || !current.Expires.Equal(expiry) {
		t.Fatal("failed replacement changed existing session", err)
	}
}
func BenchmarkSessionRead(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	expiry := time.Now().Add(time.Hour)
	if err = s.Start("state", "browser", "", Record{Expires: expiry}); err != nil {
		b.Fatal(err)
	}
	if err = s.RotateSession("session", "", Record{Expires: expiry, UserID: "u1", Binding: "binding", Browser: Key("browser")}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := s.Session("session"); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
func BenchmarkLoginLogout(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "state.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expiry := time.Now().Add(time.Hour)
		if err := s.Start("state", "browser", "", Record{Expires: expiry, Provider: "github"}); err != nil {
			b.Fatal(err)
		}
		tx, err := s.Consume("state", "browser", "github")
		if err != nil {
			b.Fatal(err)
		}
		if err = s.RotateSession("session", "", Record{Expires: expiry, UserID: "u1", Binding: "binding", Browser: tx.Browser}); err != nil {
			b.Fatal(err)
		}
		if err = s.Revoke("session", ""); err != nil {
			b.Fatal(err)
		}
	}
}
