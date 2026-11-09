// Package store persists opaque sessions and single-use browser transactions.
// A database is owned by one Porter process; records never contain upstream tokens.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var ErrMissing = errors.New("record missing or expired")
var ErrCapacity = errors.New("record capacity reached")

type Record struct {
	UserID    string    `json:"user_id,omitempty"`
	Binding   string    `json:"binding,omitempty"`
	Expires   time.Time `json:"expires"`
	Provider  string    `json:"provider"`
	Namespace string    `json:"namespace,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Browser   string    `json:"browser,omitempty"`
	Verifier  string    `json:"verifier,omitempty"`
	Nonce     string    `json:"nonce,omitempty"`
}
type Store struct{ db *bolt.DB }

func Open(path string) (*Store, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("database must be a regular owner-only file")
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	db, e := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	s := &Store{db: db}
	e = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"transactions", "sessions", "families"} {
			if _, e := tx.CreateBucketIfNotExists([]byte(name)); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func Key(value string) string { h := sha256.Sum256([]byte(value)); return hex.EncodeToString(h[:]) }
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Put(bucket, key string, r Record) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket([]byte(bucket))
		if bk == nil {
			return errors.New("invalid bucket")
		}
		if bk.Stats().KeyN >= 10000 {
			return ErrCapacity
		}
		return bk.Put([]byte(Key(key)), b)
	})
}
func (s *Store) Get(bucket, key string) (Record, error) {
	var r Record
	e := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return ErrMissing
		}
		v := b.Get([]byte(Key(key)))
		if v == nil {
			return ErrMissing
		}
		return json.Unmarshal(v, &r)
	})
	if e == nil && !time.Now().Before(r.Expires) {
		e = ErrMissing
	}
	return r, e
}

// Consume validates the browser and provider before deleting the transaction atomically.
func (s *Store) Consume(key, browser, provider string) (Record, error) {
	var r Record
	e := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("transactions"))
		v := b.Get([]byte(Key(key)))
		if v == nil {
			return ErrMissing
		}
		if e := json.Unmarshal(v, &r); e != nil {
			return e
		}
		if !time.Now().Before(r.Expires) || r.Browser != Key(browser) || r.Provider != provider || !liveFamily(tx, r.Browser) {
			return ErrMissing
		}
		return b.Delete([]byte(Key(key)))
	})
	return r, e
}
func (s *Store) Delete(bucket, key string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(bucket)).Delete([]byte(Key(key))) })
}
func (s *Store) Prune(now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"transactions", "sessions", "families"} {
			b := tx.Bucket([]byte(name))
			c := b.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var r Record
				if e := json.Unmarshal(v, &r); e != nil {
					return e
				}
				if !now.Before(r.Expires) {
					if e := c.Delete(); e != nil {
						return e
					}
				}
			}
		}
		return nil
	})
}

func liveFamily(tx *bolt.Tx, key string) bool {
	var r Record
	data := tx.Bucket([]byte("families")).Get([]byte(key))
	return data != nil && json.Unmarshal(data, &r) == nil && time.Now().Before(r.Expires)
}

// Start atomically creates a transaction and a revocable browser login family.
func (s *Store) Start(state, browser, previous string, r Record) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		t, f := tx.Bucket([]byte("transactions")), tx.Bucket([]byte("families"))
		if previous != "" {
			if e := f.Delete([]byte(Key(previous))); e != nil {
				return e
			}
		}
		if t.Stats().KeyN >= 10000 || f.Stats().KeyN >= 10000 {
			return ErrCapacity
		}
		r.Browser = Key(browser)
		data, e := json.Marshal(r)
		if e != nil {
			return e
		}
		if e = t.Put([]byte(Key(state)), data); e != nil {
			return e
		}
		family, e := json.Marshal(Record{Expires: r.Expires})
		if e != nil {
			return e
		}
		return f.Put([]byte(r.Browser), family)
	})
}

// RotateSession commits account switching and family expiry in one transaction.
// A logout that revokes the family during an upstream exchange prevents issuance.
func (s *Store) RotateSession(token, old string, r Record) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if r.UserID == "" || r.Binding == "" || !liveFamily(tx, r.Browser) {
			return ErrMissing
		}
		sessions, families := tx.Bucket([]byte("sessions")), tx.Bucket([]byte("families"))
		if old != "" {
			if data := sessions.Get([]byte(Key(old))); data != nil {
				var previous Record
				if e := json.Unmarshal(data, &previous); e != nil {
					return e
				}
				if previous.Browser != r.Browser {
					if e := families.Delete([]byte(previous.Browser)); e != nil {
						return e
					}
				}
				if e := sessions.Delete([]byte(Key(old))); e != nil {
					return e
				}
			}
		}
		if sessions.Stats().KeyN >= 10000 {
			return ErrCapacity
		}
		data, e := json.Marshal(r)
		if e != nil {
			return e
		}
		if e = sessions.Put([]byte(Key(token)), data); e != nil {
			return e
		}
		family, e := json.Marshal(Record{Expires: r.Expires})
		if e != nil {
			return e
		}
		return families.Put([]byte(r.Browser), family)
	})
}
func (s *Store) Session(token string) (Record, error) {
	var r Record
	e := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket([]byte("sessions")).Get([]byte(Key(token)))
		if data == nil {
			return ErrMissing
		}
		if e := json.Unmarshal(data, &r); e != nil {
			return e
		}
		if r.UserID == "" || r.Binding == "" || !time.Now().Before(r.Expires) || !liveFamily(tx, r.Browser) {
			return ErrMissing
		}
		return nil
	})
	return r, e
}

// Revoke also invalidates any callback already exchanging a code for this browser.
func (s *Store) Revoke(token, browser string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		sessions, families := tx.Bucket([]byte("sessions")), tx.Bucket([]byte("families"))
		if browser != "" {
			if e := families.Delete([]byte(Key(browser))); e != nil {
				return e
			}
		}
		if token != "" {
			if data := sessions.Get([]byte(Key(token))); data != nil {
				var r Record
				if e := json.Unmarshal(data, &r); e != nil {
					return e
				}
				if e := families.Delete([]byte(r.Browser)); e != nil {
					return e
				}
			}
			return sessions.Delete([]byte(Key(token)))
		}
		return nil
	})
}

// ReconcileBindings makes removals and edits durable across later config rollback.
// Re-adding a mapping must not revive a previously invalidated session.
func (s *Store) ReconcileBindings(active map[string]bool) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		sessions, families := tx.Bucket([]byte("sessions")), tx.Bucket([]byte("families"))
		cursor := sessions.Cursor()
		for key, data := cursor.First(); key != nil; key, data = cursor.Next() {
			var r Record
			if e := json.Unmarshal(data, &r); e != nil {
				return e
			}
			if !active[r.Binding] {
				if r.Browser != "" {
					if e := families.Delete([]byte(r.Browser)); e != nil {
						return e
					}
				}
				if e := cursor.Delete(); e != nil {
					return e
				}
			}
		}
		return nil
	})
}

// Check performs a read-only structural probe. It does not create, extend,
// consume or revoke any authentication record.
func (s *Store) Check(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	return s.db.View(func(tx *bolt.Tx) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		for _, name := range []string{"transactions", "sessions", "families"} {
			if tx.Bucket([]byte(name)) == nil {
				return errors.New("storage bucket unavailable")
			}
		}
		return nil
	})
}
