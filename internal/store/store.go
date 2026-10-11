// Package store persists the application database as an atomically-written JSON file.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CautiousCapsLock/certsmith/internal/model"
)

const maxEvents = 300

// maxAudit is how many administrative actions are remembered. More than the certificate events: they
// are few, and the record is worth more the longer it goes back.
const maxAudit = 2000

type Store struct {
	mu   sync.RWMutex
	path string
	db   model.DB
}

func Open(dataDir string) (*Store, error) {
	s := &Store{path: filepath.Join(dataDir, "db.json")}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.db.Settings = model.DefaultSettings()
		s.db.Alerts = map[string]time.Time{}
		return s, s.save()
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &s.db); err != nil {
		return nil, err
	}
	if s.db.Alerts == nil {
		s.db.Alerts = map[string]time.Time{}
	}
	// older versions had one shared password: it becomes the user "admin"
	if len(s.db.Users) == 0 && s.db.AdminHash != "" {
		s.db.Users = []model.User{{Name: "admin", Hash: s.db.AdminHash, Created: time.Now()}}
		s.db.AdminHash = ""
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	// targets that deployed before the "first deploy is manual" rule existed keep renewing automatically
	migrated := false
	for i := range s.db.Targets {
		if t := &s.db.Targets[i]; t.DeployedSerial != "" && !t.AutoDeploy {
			t.AutoDeploy, migrated = true, true
		}
	}
	if migrated {
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// View runs fn with read access to a snapshot-safe view. fn must not retain the pointer.
func (s *Store) View(fn func(db *model.DB)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.db)
}

// Snapshot returns a deep copy of the database.
func (s *Store) Snapshot() model.DB {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(&s.db)
	var out model.DB
	_ = json.Unmarshal(b, &out)
	return out
}

// Update runs fn under the write lock and persists the result if fn succeeds.
func (s *Store) Update(fn func(db *model.DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.db); err != nil {
		return err
	}
	return s.save()
}

// AddEvent appends to the capped event log.
func (s *Store) AddEvent(level, subject, msg string) {
	_ = s.Update(func(db *model.DB) error {
		db.Events = append(db.Events, model.Event{Time: time.Now(), Level: level, Subject: subject, Message: msg})
		if n := len(db.Events); n > maxEvents {
			db.Events = append([]model.Event(nil), db.Events[n-maxEvents:]...)
		}
		return nil
	})
}

// AddAudit records an administrative action.
func (s *Store) AddAudit(e model.AuditEntry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	_ = s.Update(func(db *model.DB) error {
		db.Audit = append(db.Audit, e)
		if n := len(db.Audit); n > maxAudit {
			db.Audit = append([]model.AuditEntry(nil), db.Audit[n-maxAudit:]...)
		}
		return nil
	})
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(&s.db, "", "  ")
	if err != nil {
		return err
	}
	// write, flush to disk, then rename: a crash or power cut leaves the old file or the new one, never half
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(s.path)); err == nil { // make the rename itself durable
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func NewID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
