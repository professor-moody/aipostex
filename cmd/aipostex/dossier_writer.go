package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/professor-moody/aipostex/pkg/report"
)

// dossierWriter is an output.Writer that buffers findings as they stream and flushes
// them as an operator dossier DIRECTORY (credentials, commands.sh, targets,
// evidence/, findings.jsonl, README) via the same writeDossier that backs
// `report view --dossier-dir`. It lets `<run> --format dossier -o <dir>` produce the
// whole organized folder in one command. Because every findings-producing command
// routes through getWriterMode, this lands everywhere with no per-command hooking;
// and because getWriterMode tees a console writer alongside any -o target, the run
// still prints findings live while the folder is written.
//
// The real file I/O happens in WriteFooter, NOT Close: every command checks
// WriteFooter's error but defers Close() and drops its error, so a failure surfaced
// only from Close() would silently leave no dossier while the operator believed an
// engagement was saved.
type dossierWriter struct {
	dir      string
	findings []report.Finding
	flushed  bool
}

func newDossierWriter(dir string) (*dossierWriter, error) {
	if strings.TrimSpace(dir) == "" || dir == "-" {
		return nil, fmt.Errorf("dossier output requires --output <dir>")
	}
	// Create the dossier directory up front so an unusable -o (e.g. a path that is
	// an existing regular file) fails fast HERE — getWriter's error is checked by
	// every command — instead of after the whole run, or silently in a deferred
	// Close().
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("dossier output directory %q: %w", dir, err)
	}
	return &dossierWriter{dir: dir}, nil
}

func (d *dossierWriter) WriteHeader() error { return nil }

func (d *dossierWriter) WriteFinding(f report.Finding) error {
	// Stamp the active session's ID on EVERY accumulated finding. Exploit findings get
	// it in newExploitFinding, but discover/scan/assess findings do not — without it,
	// `sessions export` (which filters by session_id) silently drops them. Only fill when
	// absent so an explicit tag is preserved.
	if sid := resolveSessionID(); sid != "" {
		if existing, _ := f.Metadata["session_id"].(string); existing == "" {
			if f.Metadata == nil {
				f.Metadata = map[string]interface{}{}
			}
			f.Metadata["session_id"] = sid
		}
	}
	d.findings = append(d.findings, f)
	return nil
}

// WriteFooter flushes the dossier to disk. Its error IS checked by every command,
// so a write failure is surfaced rather than swallowed.
func (d *dossierWriter) WriteFooter(map[string]int) error {
	return d.flush()
}

// Close flushes as a fallback for paths that error out before WriteFooter, so the
// dossier is still attempted. flush() is idempotent, so the normal
// WriteFooter-then-Close sequence writes exactly once.
func (d *dossierWriter) Close() error {
	return d.flush()
}

func (d *dossierWriter) flush() error {
	if d.flushed {
		return nil
	}
	d.flushed = true
	// Accumulate: merge with any findings already in this dossier so that multiple
	// `--format dossier -o <dir>` commands build ONE combined engagement dossier
	// instead of each command overwriting the previous one. Findings from any
	// enumeration land in their appropriate places; report view <dir> reads the union.
	all := d.findings
	if existing := d.existingFindings(); len(existing) > 0 {
		all = dedupeAndSortFindings(append(existing, d.findings...))
	}
	collection := report.NewCollection()
	for _, f := range all {
		collection.Add(f)
	}
	return writeDossier(d.dir, all, *collection)
}

// existingFindings loads the findings already accumulated in this dossier (empty on
// the first write, before findings.jsonl exists). A missing/unreadable file is
// treated as "no prior findings" so the first command still writes a fresh dossier.
func (d *dossierWriter) existingFindings() []report.Finding {
	path := filepath.Join(d.dir, "findings.jsonl")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	collection, err := loadFindingCollection(path)
	if err != nil {
		return nil
	}
	return collection.Findings
}
