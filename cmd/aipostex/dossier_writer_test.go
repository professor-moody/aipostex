package main

import (
	"os"
	"path/filepath"
	"testing"
)

// `--format dossier -o <dir>` must write the whole operator folder via getWriterMode,
// using the same writeDossier that backs `report view --dossier-dir`, and it must tee
// (a non-empty -o wraps the console writer) so the run still prints findings.
func TestGetWriterModeDossierWritesFolder(t *testing.T) {
	withTestConfig(t, func() {
		dir := filepath.Join(t.TempDir(), "engagement")
		cfg.Format = "dossier"
		cfg.OutputFile = dir
		cfg.Verbose = false

		w, err := getWriterMode(false)
		if err != nil {
			t.Fatalf("getWriterMode(dossier): %v", err)
		}
		if err := w.WriteHeader(); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if err := w.WriteFinding(rayLeakFinding()); err != nil {
			t.Fatalf("WriteFinding: %v", err)
		}
		if err := w.WriteFinding(mlflowProofFinding()); err != nil {
			t.Fatalf("WriteFinding: %v", err)
		}
		if err := w.WriteFooter(map[string]int{"total": 2}); err != nil {
			t.Fatalf("WriteFooter: %v", err)
		}
		// The dossier must be on disk after WriteFooter (whose error every command
		// checks) — not deferred to Close (whose error every command drops).
		if _, err := os.Stat(filepath.Join(dir, "findings.jsonl")); err != nil {
			t.Fatalf("expected the dossier written by WriteFooter, not only Close: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		for _, name := range []string{"findings.jsonl", "credentials.json", "commands.sh", "README.md"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatalf("expected dossier file %s to exist: %v", name, err)
			}
		}

		// The dossier's findings.jsonl round-trips straight back through report view
		// (loadFindingCollection detects the directory).
		coll, err := loadFindingCollection(dir)
		if err != nil {
			t.Fatalf("loadFindingCollection(dossier dir): %v", err)
		}
		if len(coll.Findings) != 2 {
			t.Fatalf("expected 2 findings loaded from the dossier dir, got %d", len(coll.Findings))
		}
	})
}

// Empty -o must error like the pdf format, never silently write a folder into cwd.
func TestGetWriterModeDossierRequiresOutputDir(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "dossier"
		cfg.OutputFile = ""
		if _, err := getWriterMode(false); err == nil {
			t.Fatalf("expected --format dossier with no -o to error")
		}
	})
}

// The reported bug: `--format dossier -o <existing-file>` printed findings and no
// error while writing no dossier (the os.MkdirAll failure was dropped by defer
// Close). Creating the dir at construction makes it fail fast at getWriter, whose
// error every command checks — so the operator is never told a dossier was saved
// when it wasn't.
func TestGetWriterModeDossierRejectsExistingFilePath(t *testing.T) {
	withTestConfig(t, func() {
		file := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.Format = "dossier"
		cfg.OutputFile = file
		if _, err := getWriterMode(false); err == nil {
			t.Fatalf("expected --format dossier -o <existing-file> to error, not silently write no dossier")
		}
		// The file must be untouched — no dossier was silently written over it.
		if info, err := os.Stat(file); err != nil || info.IsDir() {
			t.Fatalf("expected the existing file left intact, got err=%v isDir=%v", err, info != nil && info.IsDir())
		}
	})
}
