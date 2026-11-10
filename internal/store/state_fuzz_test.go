package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func FuzzSessionRevocationAcrossRestart(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 1, 2, 5, 4})
	f.Add([]byte{0, 3, 2, 1, 4, 5})
	f.Add([]byte{0, 1, 2, 5, 4, 2})
	f.Fuzz(func(t *testing.T, steps []byte) {
		if len(steps) > 32 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "state.db")
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { s.Close() }()
		expiry := time.Now().Add(time.Hour)
		family, transaction, session := false, false, false
		for _, step := range steps {
			switch step % 6 {
			case 0:
				err = s.Start("state", "browser", "", Record{Provider: "github", Expires: expiry})
				if err != nil {
					t.Fatal(err)
				}
				family, transaction = true, true
			case 1:
				_, err = s.Consume("state", "browser", "github")
				if (err == nil) != (family && transaction) {
					t.Fatal("transaction consumption disagrees with model")
				}
				if err == nil {
					transaction = false
				}
			case 2:
				err = s.RotateSession("session", "", Record{UserID: "u1", Binding: "revision", Browser: Key("browser"), Expires: expiry})
				if (err == nil) != family {
					t.Fatal("revoked family issued a session")
				}
				if err == nil {
					session = true
				}
			case 3:
				if err = s.Revoke("session", "browser"); err != nil {
					t.Fatal(err)
				}
				family, session = false, false
			case 4:
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = Open(path)
				if err != nil {
					t.Fatal(err)
				}
			case 5:
				if err = s.ReconcileBindings(map[string]bool{}); err != nil {
					t.Fatal(err)
				}
				if session {
					family = false
				}
				session = false
			}
			current, err := s.Session("session")
			if (err == nil) != (family && session) {
				t.Fatal("session validity disagrees with revocation model")
			}
			if err != nil && !errors.Is(err, ErrMissing) {
				t.Fatal(err)
			}
			if err == nil && !current.Expires.Equal(expiry) {
				t.Fatal("operation changed the absolute deadline")
			}
		}
	})
}
