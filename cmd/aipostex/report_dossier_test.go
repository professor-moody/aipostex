package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// dossierTestFindings returns a small, realistic findings set: a Jupyter token
// finding carrying a chainable extracted credential + landed/stage, plus a
// second finding on a different target that has evidence but no credentials.
func dossierTestFindings() []report.Finding {
	return []report.Finding{
		{
			ID:       "jupyter-token-1",
			Source:   report.SourceJupyter,
			Target:   "http://172.16.50.10:8888",
			Title:    "Jupyter server exposes an unauthenticated API token",
			Severity: report.SeverityCritical,
			Evidence: "GET /api/sessions -> 200\nX-Jupyter-Token: dev-token-abcdef123456",
			Metadata: map[string]interface{}{
				"service": "jupyter",
				"stage":   "confirmed",
				"landed":  "confirmed-usable",
				"extracted_credentials": []interface{}{
					map[string]interface{}{
						"type":       "jupyter-token",
						"name":       "JUPYTER_TOKEN",
						"value":      "dev-token-abcdef123456",
						"target_url": "http://172.16.50.10:8888",
						"chainable":  true,
						"note":       "grants API + terminal access",
					},
				},
			},
		},
		{
			ID:       "mlflow-open-1",
			Source:   report.SourceMLflow,
			Target:   "http://172.16.50.20:5000",
			Title:    "MLflow tracking server is unauthenticated",
			Severity: report.SeverityHigh,
			Evidence: "GET /api/2.0/mlflow/experiments/list -> 200 (no auth)",
			Metadata: map[string]interface{}{
				"service": "mlflow",
			},
		},
	}
}

func readDossierFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

func TestWriteDossierProducesOperatorFiles(t *testing.T) {
	findings := dossierTestFindings()
	dir := filepath.Join(t.TempDir(), "dossier")

	if err := writeDossier(dir, findings, report.FindingCollection{Findings: findings}); err != nil {
		t.Fatalf("writeDossier: %v", err)
	}

	// credentials.json parses and carries landed/stage + source finding.
	var creds []dossierCredential
	if err := json.Unmarshal([]byte(readDossierFile(t, dir, "credentials.json")), &creds); err != nil {
		t.Fatalf("credentials.json invalid JSON: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d: %+v", len(creds), creds)
	}
	c := creds[0]
	if c.Value != "dev-token-abcdef123456" {
		t.Fatalf("unexpected credential value: %q", c.Value)
	}
	if c.Landed != "confirmed-usable" || c.Stage != "confirmed" {
		t.Fatalf("credential missing landed/stage: stage=%q strength=%q", c.Stage, c.Landed)
	}
	if c.SourceFinding != "jupyter-token-1" {
		t.Fatalf("credential missing source finding: %q", c.SourceFinding)
	}
	if !c.Chainable {
		t.Fatalf("expected credential to be chainable")
	}

	// credentials.csv + credentials.txt exist and carry the value.
	if csv := readDossierFile(t, dir, "credentials.csv"); !strings.Contains(csv, "dev-token-abcdef123456") ||
		!strings.Contains(csv, "landed") {
		t.Fatalf("credentials.csv missing value or proof column:\n%s", csv)
	}
	if txt := readDossierFile(t, dir, "credentials.txt"); !strings.Contains(txt, "JUPYTER_TOKEN=dev-token-abcdef123456") {
		t.Fatalf("credentials.txt missing copy-ready credential:\n%s", txt)
	}

	// commands.sh is executable, bash-clean, and credential-injected.
	commandsPath := filepath.Join(dir, "commands.sh")
	info, err := os.Stat(commandsPath)
	if err != nil {
		t.Fatalf("stat commands.sh: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("commands.sh mode = %v, want 0700 (owner-only; it embeds credentials)", info.Mode().Perm())
	}
	commands := readDossierFile(t, dir, "commands.sh")
	if !strings.HasPrefix(commands, "#!/usr/bin/env bash") {
		t.Fatalf("commands.sh missing shebang:\n%s", commands)
	}
	if !strings.Contains(commands, "dev-token-abcdef123456") {
		t.Fatalf("commands.sh not credential-injected:\n%s", commands)
	}
	if _, err := exec.LookPath("bash"); err == nil {
		if out, err := exec.Command("bash", "-n", commandsPath).CombinedOutput(); err != nil {
			t.Fatalf("bash -n commands.sh failed: %v\n%s", err, out)
		}
	}

	// targets.csv lists both unique targets with their worst severity.
	targets := readDossierFile(t, dir, "targets.csv")
	for _, want := range []string{"http://172.16.50.10:8888", "http://172.16.50.20:5000", "critical", "high"} {
		if !strings.Contains(targets, want) {
			t.Fatalf("targets.csv missing %q:\n%s", want, targets)
		}
	}

	// evidence/<id>.txt written per finding that has evidence.
	ev := readDossierFile(t, dir, filepath.Join("evidence", "jupyter-token-1.txt"))
	if !strings.Contains(ev, "X-Jupyter-Token: dev-token-abcdef123456") {
		t.Fatalf("evidence file missing raw evidence:\n%s", ev)
	}

	// findings.jsonl has one line per finding.
	lines := strings.Split(strings.TrimSpace(readDossierFile(t, dir, "findings.jsonl")), "\n")
	if len(lines) != len(findings) {
		t.Fatalf("findings.jsonl has %d lines, want %d", len(lines), len(findings))
	}

	// README.md summarizes the counts.
	readme := readDossierFile(t, dir, "README.md")
	for _, want := range []string{"aipostex dossier", "Credentials:", "Targets:"} {
		if !strings.Contains(readme, want) {
			t.Fatalf("README.md missing %q:\n%s", want, readme)
		}
	}
}

func TestWriteDossierNoCredentials(t *testing.T) {
	findings := []report.Finding{
		{
			ID:       "mlflow-open-1",
			Source:   report.SourceMLflow,
			Target:   "http://172.16.50.20:5000",
			Title:    "MLflow tracking server is unauthenticated",
			Severity: report.SeverityHigh,
			Evidence: "GET /api/2.0/mlflow/experiments/list -> 200 (no auth)",
		},
	}
	dir := filepath.Join(t.TempDir(), "dossier")
	if err := writeDossier(dir, findings, report.FindingCollection{Findings: findings}); err != nil {
		t.Fatalf("writeDossier: %v", err)
	}

	// Empty but valid credentials.json.
	credsRaw := strings.TrimSpace(readDossierFile(t, dir, "credentials.json"))
	if credsRaw != "[]" {
		t.Fatalf("expected empty credentials.json to be [], got %q", credsRaw)
	}
	var creds []dossierCredential
	if err := json.Unmarshal([]byte(credsRaw), &creds); err != nil || len(creds) != 0 {
		t.Fatalf("credentials.json not a valid empty array: %v (%d)", err, len(creds))
	}

	// commands.sh explains there is nothing to run.
	commands := readDossierFile(t, dir, "commands.sh")
	if !strings.Contains(commands, "No chainable credentials") {
		t.Fatalf("commands.sh missing no-credentials note:\n%s", commands)
	}

	// Non-credential files are still written.
	for _, name := range []string{"targets.csv", "findings.jsonl", "README.md"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to be written: %v", name, err)
		}
	}
	ev := readDossierFile(t, dir, filepath.Join("evidence", "mlflow-open-1.txt"))
	if !strings.Contains(ev, "no auth") {
		t.Fatalf("evidence file missing content:\n%s", ev)
	}
}

func TestRunReportViewDossierFlagWritesDirNotConsole(t *testing.T) {
	findings := dossierTestFindings()
	path := writeJSONLFindings(t, findings)
	dir := filepath.Join(t.TempDir(), "dossier")

	resetReportViewFlags(t)
	reportViewDossierDir = dir

	// Capture the status stream (infof) too — the summary is a status line.
	var status strings.Builder
	stderrWriterMu.Lock()
	prevStderr := stderrWriter
	stderrWriter = &status
	stderrWriterMu.Unlock()
	t.Cleanup(func() {
		stderrWriterMu.Lock()
		stderrWriter = prevStderr
		stderrWriterMu.Unlock()
	})

	out := captureStdout(t, func() {
		if err := runReportView(nil, []string{path}); err != nil {
			t.Fatalf("runReportView returned error: %v", err)
		}
	})

	// Summary line printed to the status stream; no console credential dump.
	if !strings.Contains(status.String(), "wrote dossier to") {
		t.Fatalf("expected dossier summary line, got:\n%s", status.String())
	}
	if strings.Contains(out, "dev-token-abcdef123456") {
		t.Fatalf("did not expect credential value dumped to console:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatalf("expected dossier dir written: %v", err)
	}
}

func TestRunReportViewServiceAliasScopesDossier(t *testing.T) {
	// dossierTestFindings has one jupyter finding and one mlflow finding.
	findings := dossierTestFindings()
	path := writeJSONLFindings(t, findings)
	dir := filepath.Join(t.TempDir(), "dossier")

	resetReportViewFlags(t)
	reportViewService = "mlflow" // alias for --source
	reportViewDossierDir = dir

	_ = captureStdout(t, func() {
		if err := runReportView(nil, []string{path}); err != nil {
			t.Fatalf("runReportView returned error: %v", err)
		}
	})

	// Only the mlflow finding should have been written to the dossier.
	lines := strings.Split(strings.TrimSpace(readDossierFile(t, dir, "findings.jsonl")), "\n")
	if len(lines) != 1 {
		t.Fatalf("--service mlflow should scope to 1 finding, got %d lines", len(lines))
	}
	if !strings.Contains(lines[0], "mlflow") || strings.Contains(lines[0], "jupyter") {
		t.Fatalf("--service scoped to the wrong finding:\n%s", lines[0])
	}
	targets := readDossierFile(t, dir, "targets.csv")
	if strings.Contains(targets, "8888") { // the jupyter target
		t.Fatalf("--service mlflow leaked the jupyter target into the dossier:\n%s", targets)
	}
}

func TestReportViewHelpDocumentsDossier(t *testing.T) {
	// The long help must actually explain the dossier and the --service alias,
	// and the examples must show a --dossier-dir invocation.
	for _, want := range []string{"Dossier", "--dossier-dir", "credentials.json", "--service", "owner-only"} {
		if !strings.Contains(reportViewCmd.Long, want) {
			t.Fatalf("report view --help (Long) missing %q:\n%s", want, reportViewCmd.Long)
		}
	}
	if !strings.Contains(reportViewCmd.Example, "--dossier-dir") {
		t.Fatalf("report view examples missing a --dossier-dir example:\n%s", reportViewCmd.Example)
	}
	if reportViewCmd.Flags().Lookup("service") == nil {
		t.Fatalf("report view should register a --service flag")
	}
}
