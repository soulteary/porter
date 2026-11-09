// Package store persists opaque sessions and single-use browser transactions.
// A database is owned by one Porter process; records never contain upstream tokens.
package store

import (
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
		for _, name := range []string{"transactions", "sessions"} {
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
		if !time.Now().Before(r.Expires) || r.Browser != Key(browser) || r.Provider != provider {
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
		for _, name := range []string{"transactions", "sessions"} {
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
