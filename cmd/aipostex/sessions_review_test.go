package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// #3 regression: findings written to the dossier by NON-exploit modules
// (discover/scan/assess) were never tagged with session_id, so `sessions export`
// (which filters by session_id) silently dropped them. The write layer must stamp it.
func TestDossierWriterStampsSessionID(t *testing.T) {
	oldSID := cfg.SessionID
	t.Cleanup(func() { cfg.SessionID = oldSID })
	cfg.SessionID = "ses-fixtest"

	dir := t.TempDir()
	w, err := newDossierWriter(dir)
	if err != nil {
		t.Fatalf("newDossierWriter: %v", err)
	}
	// A discovery-style finding with no session_id (as discover/scan produce).
	if err := w.WriteFinding(report.Finding{
		ID: "f-1", Source: "discover", Target: "http://172.16.50.20:8265",
		Title: "Ray dashboard exposed", Severity: "high",
	}); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if err := w.WriteFooter(nil); err != nil {
		t.Fatalf("WriteFooter/flush: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "findings.jsonl"))
	if err != nil {
		t.Fatalf("read findings.jsonl: %v", err)
	}
	if !strings.Contains(string(data), `"session_id":"ses-fixtest"`) {
		t.Errorf("discovery finding must carry session_id in the dossier, got:\n%s", data)
	}
}

// #2 regression: `sessions start <name>` on a dir that already holds findings would
// silently merge two engagements. It must refuse without --force.
func TestSessionsStartRefusesPopulatedDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, "engagements", "acme")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "findings.jsonl"), []byte(`{"id":"f-1"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Save/restore the globals runSessionsStart reads.
	oldName, oldDir, oldForce := sessionName, sessionDir, sessionForce
	t.Cleanup(func() { sessionName, sessionDir, sessionForce = oldName, oldDir, oldForce })
	sessionName, sessionDir, sessionForce = "", "", false

	if err := runSessionsStart(nil, []string{"acme"}); err == nil {
		t.Fatal("expected refusal reusing a populated engagement dir without --force")
	} else if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error should mention --force, got: %v", err)
	}

	// --force allows reuse.
	sessionForce = true
	if err := runSessionsStart(nil, []string{"acme"}); err != nil {
		t.Errorf("--force should allow reusing the dir, got: %v", err)
	}
}
