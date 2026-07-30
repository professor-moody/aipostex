package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStartAndStop(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	sess, err := store.Start("test-session", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if sess.Status != "active" {
		t.Errorf("expected status active, got %s", sess.Status)
	}
	if sess.Name != "test-session" {
		t.Errorf("expected name test-session, got %s", sess.Name)
	}
	stopped, err := store.Stop(sess.ID)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if stopped.Status != "stopped" {
		t.Errorf("expected status stopped, got %s", stopped.Status)
	}
	if stopped.EndTime.IsZero() {
		t.Error("expected EndTime to be set")
	}
}

func TestActive(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	active, err := store.Active()
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if active != nil {
		t.Errorf("expected nil active session, got %v", active)
	}
	sess, _ := store.Start("active-test", "")
	active, _ = store.Active()
	if active == nil || active.ID != sess.ID {
		t.Errorf("expected active session %s, got %v", sess.ID, active)
	}
}

func TestSetNotes(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	sess, _ := store.Start("notes-test", "")
	if err := store.SetNotes(sess.ID, "first note"); err != nil {
		t.Fatalf("SetNotes: %v", err)
	}
	got, _ := store.Get(sess.ID)
	if got.Notes != "first note" {
		t.Errorf("expected 'first note', got %q", got.Notes)
	}
	if err := store.SetNotes(sess.ID, "replaced"); err != nil {
		t.Fatalf("SetNotes: %v", err)
	}
	got, _ = store.Get(sess.ID)
	if got.Notes != "replaced" {
		t.Errorf("expected 'replaced', got %q", got.Notes)
	}
}

func TestAppendNotes(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	sess, _ := store.Start("append-test", "")
	if err := store.AppendNotes(sess.ID, "line1"); err != nil {
		t.Fatalf("AppendNotes: %v", err)
	}
	if err := store.AppendNotes(sess.ID, "line2"); err != nil {
		t.Fatalf("AppendNotes: %v", err)
	}
	got, _ := store.Get(sess.ID)
	if got.Notes != "line1\nline2" {
		t.Errorf("expected 'line1\\nline2', got %q", got.Notes)
	}
}

func TestAddTargetDedup(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	sess, _ := store.Start("target-test", "")
	_ = store.AddTarget(sess.ID, "http://10.0.0.1")
	_ = store.AddTarget(sess.ID, "http://10.0.0.1")
	_ = store.AddTarget(sess.ID, "http://10.0.0.2")
	got, _ := store.Get(sess.ID)
	if len(got.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d: %v", len(got.Targets), got.Targets)
	}
}

func TestIncrementFindings(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	sess, _ := store.Start("findings-test", "")
	_ = store.IncrementFindings(sess.ID, 3)
	_ = store.IncrementFindings(sess.ID, 2)
	got, _ := store.Get(sess.ID)
	if got.Findings != 5 {
		t.Errorf("expected 5 findings, got %d", got.Findings)
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.Start("first", "")
	store.Start("second", "")
	sessions, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	if sessions[0].Name != "second" {
		t.Errorf("expected 'second' first, got %q", sessions[0].Name)
	}
}

func TestSessionFilePermissions(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	sess, _ := store.Start("perms-test", "")
	path := filepath.Join(dir, sess.ID+".json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected file permissions 0600, got %o", perm)
	}
}
