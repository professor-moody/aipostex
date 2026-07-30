package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Session struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	Status    string    `json:"status"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Targets   []string  `json:"targets,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	Findings  int       `json:"findings"`
	// Dir is the engagement dossier directory that finding-emitting commands
	// auto-accumulate into while this session is active.
	Dir string `json:"dir,omitempty"`
}

type Store struct {
	dir string
	mu  sync.Mutex
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating session directory: %w", err)
	}
	return &Store{dir: dir}, nil
}

func DefaultStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home directory: %w", err)
	}
	return NewStore(filepath.Join(home, ".aipostex", "sessions"))
}

func newSessionID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("ses-%d", time.Now().UnixNano())
	}
	return "ses-" + hex.EncodeToString(buf)
}

func (s *Store) Start(name, dir string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := &Session{
		ID:        newSessionID(),
		Name:      name,
		Status:    "active",
		StartTime: time.Now().UTC(),
		Dir:       dir,
	}
	if err := s.write(sess); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Store) Stop(id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, err := s.read(id)
	if err != nil {
		return nil, err
	}
	if sess.Status == "stopped" {
		return sess, nil
	}
	sess.Status = "stopped"
	sess.EndTime = time.Now().UTC()
	if err := s.write(sess); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Store) Get(id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(id)
}

func (s *Store) List() ([]*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	var sessions []*Session
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		sess, err := s.read(id)
		if err != nil {
			continue
		}
		sessions = append(sessions, sess)
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartTime.After(sessions[j].StartTime)
	})
	return sessions, nil
}

func (s *Store) Active() (*Session, error) {
	sessions, err := s.List()
	if err != nil {
		return nil, err
	}
	for _, sess := range sessions {
		if sess.Status == "active" {
			return sess, nil
		}
	}
	return nil, nil
}

func (s *Store) AddTarget(id, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, err := s.read(id)
	if err != nil {
		return err
	}
	target = strings.TrimSpace(target)
	for _, t := range sess.Targets {
		if t == target {
			return nil
		}
	}
	sess.Targets = append(sess.Targets, target)
	return s.write(sess)
}

func (s *Store) IncrementFindings(id string, count int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, err := s.read(id)
	if err != nil {
		return err
	}
	sess.Findings += count
	return s.write(sess)
}

func (s *Store) SetNotes(id, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, err := s.read(id)
	if err != nil {
		return err
	}
	sess.Notes = notes
	return s.write(sess)
}

func (s *Store) AppendNotes(id, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, err := s.read(id)
	if err != nil {
		return err
	}
	if sess.Notes != "" {
		sess.Notes += "\n" + text
	} else {
		sess.Notes = text
	}
	return s.write(sess)
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path(id)); err != nil {
		return fmt.Errorf("deleting session %s: %w", id, err)
	}
	return nil
}

func (s *Store) path(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func (s *Store) read(id string) (*Session, error) {
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, fmt.Errorf("reading session %s: %w", id, err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("parsing session %s: %w", id, err)
	}
	return &sess, nil
}

func (s *Store) write(sess *Session) error {
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}
	return os.WriteFile(s.path(sess.ID), data, 0o600)
}
