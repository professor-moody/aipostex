package main

import (
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/report"
)

// Two `--format dossier -o <dir>` commands must build ONE combined dossier — the
// second must not overwrite the first. This is what removes the demo's `>>`.
func TestDossierWriterAccumulatesAcrossCommands(t *testing.T) {
	dir := t.TempDir()
	mk := func(id, src, target, title string) report.Finding {
		return report.Finding{
			ID: id, Source: src, Target: target, Title: title,
			Severity: report.SeverityHigh, Timestamp: time.Unix(0, 0).UTC(),
			Metadata: map[string]interface{}{},
		}
	}

	write := func(f report.Finding) {
		w, err := newDossierWriter(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteHeader(); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteFinding(f); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteFooter(nil); err != nil {
			t.Fatal(err)
		}
	}

	write(mk("a1", "mcp", "http://10.0.0.1:3000", "mcp finding"))     // first command
	write(mk("b1", "ollama", "http://10.0.0.1:11434", "ollama loot")) // second command, same dir

	coll, err := loadFindingCollection(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range coll.Findings {
		ids[f.ID] = true
	}
	if !ids["a1"] || !ids["b1"] {
		t.Fatalf("dossier must accumulate both commands' findings; got %v", ids)
	}

	// Re-running the same command must not duplicate its finding.
	write(mk("a1", "mcp", "http://10.0.0.1:3000", "mcp finding"))
	coll, _ = loadFindingCollection(dir)
	count := 0
	for _, f := range coll.Findings {
		if f.ID == "a1" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("re-run must dedup, got %d copies of a1", count)
	}
}
