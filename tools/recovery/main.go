// Command recovery creates offline bbolt snapshots and restores without login state.
// It is an operator tool, not part of Porter's production image or HTTP API.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var refused = errors.New("recovery operation refused; check private files, database availability and snapshot integrity")
var buckets = []string{"transactions", "sessions", "families"}

func privateDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return refused
	}
	return nil
}
func privateFile(path string) error {
	if privateDir(filepath.Dir(path)) != nil {
		return refused
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return refused
	}
	return nil
}
func check(db *bolt.DB) error {
	return db.View(func(tx *bolt.Tx) error {
		// Drain all structural errors before returning: Check sends from a goroutine.
		bad := false
		for range tx.Check() {
			bad = true
		}
		if bad {
			return refused
		}
		count := 0
		err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			found := false
			for _, allowed := range buckets {
				if string(name) == allowed {
					found = true
				}
			}
			if !found {
				return refused
			}
			count++
			return nil
		})
		if err != nil || count != len(buckets) {
			return refused
		}
		return nil
	})
}
func digest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", refused
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", refused
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// operate never overwrites a destination. Both directories must be controlled by
// the operator; concurrent path replacement by other writers is unsupported.
func operate(command, source, destination, expected string, stopped bool) (string, error) {
	if !stopped || (command != "backup" && command != "restore") || privateFile(source) != nil || privateDir(filepath.Dir(destination)) != nil {
		return "", refused
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return "", refused
	}
	if command == "restore" {
		decoded, err := hex.DecodeString(expected)
		if err != nil || len(decoded) != sha256.Size {
			return "", refused
		}
	}
	// Read-only bbolt holds a shared lock for the entire copy. A live Porter holds
	// an exclusive lock, so a running writer cannot be copied as a plain file.
	db, err := bolt.Open(source, 0600, &bolt.Options{ReadOnly: true, Timeout: 100 * time.Millisecond})
	if err != nil {
		return "", refused
	}
	defer db.Close()
	if check(db) != nil {
		return "", refused
	}
	f, err := os.CreateTemp(filepath.Dir(destination), ".porter-recovery-*")
	if err != nil {
		return "", refused
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return "", refused
	}
	// Restore hashes and copies the original bytes under the same database lock.
	// Backup uses bbolt's supported transaction snapshot writer.
	if command == "restore" {
		var input *os.File
		input, err = os.Open(source)
		if err == nil {
			h := sha256.New()
			_, err = io.Copy(io.MultiWriter(f, h), input)
			input.Close()
			if err == nil && hex.EncodeToString(h.Sum(nil)) != expected {
				err = refused
			}
		}
	} else {
		err = db.View(func(tx *bolt.Tx) error { _, err := tx.WriteTo(f); return err })
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return "", refused
	}
	if command == "restore" {
		// Every recovery deliberately invalidates sessions, browser families and
		// pending callbacks, including records revoked after the snapshot was taken.
		restored, err := bolt.Open(temp, 0600, &bolt.Options{Timeout: time.Second})
		if err != nil {
			return "", refused
		}
		err = check(restored)
		if err == nil {
			err = restored.Update(func(tx *bolt.Tx) error {
				for _, name := range buckets {
					if err := tx.DeleteBucket([]byte(name)); err != nil {
						return err
					}
					if _, err := tx.CreateBucket([]byte(name)); err != nil {
						return err
					}
				}
				return nil
			})
		}
		closeErr := restored.Close()
		if err != nil || closeErr != nil {
			return "", refused
		}
	}
	sum, err := digest(temp)
	if err != nil {
		return "", refused
	}
	// Link is an atomic, no-overwrite publication on the same local filesystem.
	if err = os.Link(temp, destination); err != nil {
		return "", refused
	}
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return "", refused
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return "", refused
	} // A published output may exist; never auto-delete it.
	return sum, nil
}
func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return refused
	}
	fs := flag.NewFlagSet("recovery", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	source := fs.String("source", "", "private source database")
	destination := fs.String("destination", "", "new private output path")
	sum := fs.String("sha256", "", "trusted snapshot digest, required for restore")
	stopped := fs.Bool("stopped", false, "operator confirms Porter is stopped")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *source == "" || *destination == "" {
		return refused
	}
	value, err := operate(args[0], *source, *destination, *sum, *stopped)
	if err != nil {
		return refused
	}
	_, err = fmt.Fprintln(out, "sha256="+value)
	return err
}
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, refused)
		os.Exit(1)
	}
}
