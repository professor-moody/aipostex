package main

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func writeJSONLFindings(t *testing.T, findings []report.Finding) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "findings.jsonl")
	var b strings.Builder
	for _, finding := range findings {
		line, err := json.Marshal(finding)
		if err != nil {
			t.Fatalf("marshal finding: %v", err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write jsonl: %v", err)
	}
	return path
}

func TestLoadFindingCollectionInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadFindingCollection(path)
	if err == nil || !strings.Contains(err.Error(), "parsing") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestLoadFindingCollectionSupportsJSONL(t *testing.T) {
	path := writeJSONLFindings(t, []report.Finding{
		{ID: "finding-1", Source: report.SourceVulnCheck, Target: "http://10.0.0.5:11434", Title: "Ollama No Auth", Severity: report.SeverityCritical},
		{ID: "finding-2", Source: report.SourceFileDiscovery, Target: "/tmp/secrets.env", Title: "Secret file", Severity: report.SeverityHigh},
	})

	collection, err := loadFindingCollection(path)
	if err != nil {
		t.Fatalf("loadFindingCollection returned error: %v", err)
	}
	if len(collection.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(collection.Findings))
	}
	if collection.EngagementID == "" {
		t.Fatal("expected synthetic engagement id for JSONL input")
	}
	if !collection.StartTime.IsZero() || !collection.EndTime.IsZero() {
		t.Fatalf("expected zero-value start/end times for JSONL input, got start=%v end=%v", collection.StartTime, collection.EndTime)
	}
}

func TestRunMergeSupportsJSONLInput(t *testing.T) {
	withTestConfig(t, func() {
		inputA := writeJSONLFindings(t, []report.Finding{
			{ID: "finding-1", Source: report.SourceVulnCheck, Target: "http://10.0.0.5:11434", Title: "A", Severity: report.SeverityHigh},
		})
		inputB := writeJSONLFindings(t, []report.Finding{
			{ID: "finding-2", Source: report.SourceVulnCheck, Target: "http://10.0.0.6:11434", Title: "B", Severity: report.SeverityMedium},
		})

		cfg.OutputFile = filepath.Join(t.TempDir(), "merged.json")
		if err := runMerge(nil, []string{inputA, inputB}); err != nil {
			t.Fatalf("runMerge returned error: %v", err)
		}

		data, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatalf("read merged output: %v", err)
		}
		var collection report.FindingCollection
		if err := json.Unmarshal(data, &collection); err != nil {
			t.Fatalf("unmarshal merged output: %v", err)
		}
		if len(collection.Findings) != 2 {
			t.Fatalf("expected 2 merged findings, got %d", len(collection.Findings))
		}
		if collection.EngagementID == "" || collection.StartTime.IsZero() {
			t.Fatalf("expected generated collection metadata, got %+v", collection)
		}
	})
}

func TestRunSummarySupportsJSONLInput(t *testing.T) {
	prevErr := stderrWriter
	defer func() {
		stderrWriter = prevErr
	}()

	withTestConfig(t, func() {
		input := writeJSONLFindings(t, []report.Finding{
			{ID: "finding-1", Source: report.SourceVulnCheck, Target: "http://10.0.0.5:11434", Title: "A", Severity: report.SeverityCritical},
		})

		cfg.OutputFile = filepath.Join(t.TempDir(), "summary.json")
		var stderr strings.Builder
		stderrWriter = &stderr

		if err := runSummary(nil, []string{input}); err != nil {
			t.Fatalf("runSummary returned error: %v", err)
		}

		data, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatalf("read summary output: %v", err)
		}
		var summary map[string]any
		if err := json.Unmarshal(data, &summary); err != nil {
			t.Fatalf("unmarshal summary output: %v", err)
		}
		if got := int(summary["total_findings"].(float64)); got != 1 {
			t.Fatalf("expected total_findings=1, got %d", got)
		}
	})
}

func TestRunReportSupportsJSONLInput(t *testing.T) {
	prevFormat := reportRenderFormat
	defer func() {
		reportRenderFormat = prevFormat
	}()

	withTestConfig(t, func() {
		input := writeJSONLFindings(t, []report.Finding{
			{ID: "finding-1", Source: report.SourceVulnCheck, Target: "http://10.0.0.5:11434", Title: "Ollama No Auth", Severity: report.SeverityCritical},
		})

		cfg.OutputFile = filepath.Join(t.TempDir(), "report.md")
		reportRenderFormat = "markdown"

		if err := runReport(nil, []string{input}); err != nil {
			t.Fatalf("runReport returned error: %v", err)
		}

		data, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatalf("read report output: %v", err)
		}
		if !strings.Contains(string(data), "Ollama No Auth") {
			t.Fatalf("expected markdown report to include finding title, got %q", string(data))
		}
	})
}

func TestRunGraphSupportsJSONLInput(t *testing.T) {
	prevInput := graphInput
	prevFormat := graphFormat
	defer func() {
		graphInput = prevInput
		graphFormat = prevFormat
	}()

	withTestConfig(t, func() {
		graphInput = writeJSONLFindings(t, []report.Finding{
			{ID: "finding-1", Source: report.SourceVulnCheck, Target: "http://10.0.0.5:11434", Title: "Ollama No Auth", Severity: report.SeverityCritical},
		})
		graphFormat = "mermaid"
		cfg.OutputFile = filepath.Join(t.TempDir(), "graph.mmd")

		if err := runGraph(nil, nil); err != nil {
			t.Fatalf("runGraph returned error: %v", err)
		}

		data, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatalf("read graph output: %v", err)
		}
		rendered := string(data)
		if !strings.Contains(rendered, "flowchart TD") || !strings.Contains(rendered, "10.0.0.5") {
			t.Fatalf("expected Mermaid graph output, got %q", rendered)
		}
	})
}

func TestRunBundleSupportsJSONLInput(t *testing.T) {
	prevInput := bundleInput
	defer func() {
		bundleInput = prevInput
	}()

	withTestConfig(t, func() {
		bundleInput = writeJSONLFindings(t, []report.Finding{
			{ID: "finding-1", Source: report.SourceVulnCheck, Target: "http://10.0.0.5:11434", Title: "Ollama No Auth", Severity: report.SeverityCritical, Evidence: strings.Repeat("A", 250)},
		})
		cfg.OutputFile = filepath.Join(t.TempDir(), "bundle.zip")

		if err := runBundle(nil, nil); err != nil {
			t.Fatalf("runBundle returned error: %v", err)
		}

		reader, err := zip.OpenReader(cfg.OutputFile)
		if err != nil {
			t.Fatalf("open bundle zip: %v", err)
		}
		defer reader.Close()

		foundReport := false
		for _, f := range reader.File {
			if strings.HasSuffix(f.Name, "/report.json") {
				foundReport = true
				break
			}
		}
		if !foundReport {
			t.Fatalf("expected bundled report.json in %q", cfg.OutputFile)
		}
	})
}
