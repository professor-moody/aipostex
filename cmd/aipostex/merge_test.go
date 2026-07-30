package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestDeduplicateFindingsPreservesMateriallyDistinctFindings(t *testing.T) {
	now := time.Now().UTC()
	findings := []report.Finding{
		{
			Timestamp:   now,
			Source:      report.SourceVulnCheck,
			TemplateID:  "tmpl-a",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    report.SeverityHigh,
			Description: "desc",
			Remediation: "fix a",
			Evidence:    "same evidence",
			Metadata:    map[string]interface{}{"source": "a"},
		},
		{
			Timestamp:   now.Add(time.Second),
			Source:      report.SourceMLflow,
			TemplateID:  "tmpl-b",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    report.SeverityCritical,
			Description: "desc",
			Remediation: "fix b",
			Evidence:    "same evidence",
			Metadata:    map[string]interface{}{"source": "b"},
		},
	}

	deduped := deduplicateFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("expected materially distinct findings to be preserved, got %#v", deduped)
	}
}

func TestDeduplicateFindingsCollapsesIdenticalContent(t *testing.T) {
	now := time.Now().UTC()
	findings := []report.Finding{
		{
			Timestamp:   now,
			ID:          "a",
			Source:      report.SourceVulnCheck,
			TemplateID:  "tmpl",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    "HIGH",
			Description: "desc",
			Remediation: "fix",
			Evidence:    "response body",
			Tags:        []string{"b", "a"},
			References:  []string{"https://b", "https://a"},
			Metadata:    map[string]interface{}{"x": "y"},
		},
		{
			Timestamp:   now.Add(time.Second),
			ID:          "b",
			Source:      report.SourceVulnCheck,
			TemplateID:  "tmpl",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    report.SeverityHigh,
			Description: "desc",
			Remediation: "fix",
			Evidence:    "response body",
			Tags:        []string{"a", "b"},
			References:  []string{"https://a", "https://b"},
			Metadata:    map[string]interface{}{"x": "y"},
		},
	}

	deduped := deduplicateFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected identical findings to deduplicate, got %#v", deduped)
	}
}

func TestDeduplicateFindingsCollapsesWithDifferentEvidence(t *testing.T) {
	now := time.Now().UTC()
	findings := []report.Finding{
		{
			Timestamp:   now,
			Source:      report.SourceVulnCheck,
			TemplateID:  "tmpl",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    report.SeverityHigh,
			Description: "desc",
			Remediation: "fix",
			Evidence:    "request/response A",
		},
		{
			Timestamp:   now.Add(time.Second),
			Source:      report.SourceVulnCheck,
			TemplateID:  "tmpl",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    report.SeverityHigh,
			Description: "desc",
			Remediation: "fix",
			Evidence:    "request/response B",
		},
	}

	deduped := deduplicateFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected findings with different evidence to collapse (evidence excluded from hash), got %d", len(deduped))
	}
	if deduped[0].Evidence != "request/response B" {
		t.Fatalf("expected merge to keep the newest duplicate's evidence, got %q", deduped[0].Evidence)
	}
}

func TestDeduplicateFindingsCollapsesWithDifferentMetadata(t *testing.T) {
	now := time.Now().UTC()
	findings := []report.Finding{
		{
			Timestamp:   now,
			Source:      report.SourceVulnCheck,
			TemplateID:  "tmpl",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    report.SeverityHigh,
			Description: "desc",
			Remediation: "fix",
			Metadata:    map[string]interface{}{"runtime": "alpha"},
		},
		{
			Timestamp:   now.Add(time.Second),
			Source:      report.SourceVulnCheck,
			TemplateID:  "tmpl",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    report.SeverityHigh,
			Description: "desc",
			Remediation: "fix",
			Metadata:    map[string]interface{}{"runtime": "beta"},
		},
	}

	deduped := deduplicateFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected findings with different metadata to collapse (metadata excluded from hash), got %d", len(deduped))
	}
}

func TestDeduplicateFindingsIgnoresWorkflowOnlyMetadataDifferences(t *testing.T) {
	now := time.Now().UTC()
	findings := []report.Finding{
		{
			Timestamp:   now,
			Source:      report.SourceVulnCheck,
			TemplateID:  "tmpl",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    report.SeverityHigh,
			Description: "desc",
			Remediation: "fix",
			Evidence:    "same evidence",
			Metadata: map[string]interface{}{
				"record_id": "alpha",
				"workflow":  map[string]interface{}{"stage": "discovery"},
			},
		},
		{
			Timestamp:   now.Add(time.Second),
			Source:      report.SourceVulnCheck,
			TemplateID:  "tmpl",
			Target:      "http://target",
			Title:       "Same title",
			Severity:    report.SeverityHigh,
			Description: "desc",
			Remediation: "fix",
			Evidence:    "same evidence",
			Metadata: map[string]interface{}{
				"record_id": "alpha",
				"workflow":  map[string]interface{}{"stage": "correlation"},
			},
		},
	}

	deduped := deduplicateFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected workflow-only metadata differences to collapse, got %#v", deduped)
	}
}

// ---------------------------------------------------------------------------
// runMerge — integration tests
// ---------------------------------------------------------------------------

func TestRunMergeWithTempFiles(t *testing.T) {
	tmpDir := t.TempDir()
	now := time.Now().UTC()

	col1 := report.FindingCollection{
		EngagementID: "eng-1",
		StartTime:    now,
		Findings: []report.Finding{
			{ID: "f1", Source: report.SourceVulnCheck, Target: "http://a:1",
				Title: "Vuln A", Severity: report.SeverityHigh, Description: "desc A"},
		},
	}
	col2 := report.FindingCollection{
		EngagementID: "eng-2",
		StartTime:    now.Add(-time.Hour),
		Findings: []report.Finding{
			{ID: "f2", Source: report.SourceOllama, Target: "http://b:2",
				Title: "Vuln B", Severity: report.SeverityCritical, Description: "desc B"},
		},
	}

	path1 := filepath.Join(tmpDir, "col1.json")
	path2 := filepath.Join(tmpDir, "col2.json")
	outputPath := filepath.Join(tmpDir, "merged.json")

	for path, col := range map[string]report.FindingCollection{path1: col1, path2: col2} {
		data, err := json.Marshal(col)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	withTestConfig(t, func() {
		cfg.OutputFile = outputPath

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		if err := runMerge(nil, []string{path1, path2}); err != nil {
			t.Fatalf("runMerge error: %v", err)
		}

		raw, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("read output: %v", err)
		}

		var result report.FindingCollection
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("unmarshal output: %v", err)
		}
		if len(result.Findings) != 2 {
			t.Fatalf("expected 2 merged findings, got %d", len(result.Findings))
		}
	})
}

func TestRunMergeOutputToStdout(t *testing.T) {
	tmpDir := t.TempDir()
	col := report.FindingCollection{
		EngagementID: "eng-stdout",
		Findings: []report.Finding{
			{ID: "f1", Source: report.SourceVulnCheck, Target: "http://a:1",
				Title: "Test", Severity: report.SeverityInfo, Description: "desc"},
		},
	}
	path := filepath.Join(tmpDir, "input.json")
	data, _ := json.Marshal(col)
	_ = os.WriteFile(path, data, 0o600)

	withTestConfig(t, func() {
		cfg.OutputFile = ""
		if err := runMerge(nil, []string{path}); err != nil {
			t.Fatalf("runMerge stdout error: %v", err)
		}
	})
}

func TestRunMergeDeduplicates(t *testing.T) {
	tmpDir := t.TempDir()
	now := time.Now().UTC()
	col := report.FindingCollection{
		EngagementID: "eng-dup",
		StartTime:    now,
		Findings: []report.Finding{
			{ID: "f1", Source: report.SourceVulnCheck, Target: "http://a:1",
				Title: "Same", Severity: report.SeverityHigh, Description: "same desc",
				Timestamp: now},
			{ID: "f2", Source: report.SourceVulnCheck, Target: "http://a:1",
				Title: "Same", Severity: report.SeverityHigh, Description: "same desc",
				Timestamp: now.Add(time.Second)},
		},
	}
	path := filepath.Join(tmpDir, "input.json")
	data, _ := json.Marshal(col)
	_ = os.WriteFile(path, data, 0o600)
	outputPath := filepath.Join(tmpDir, "merged.json")

	withTestConfig(t, func() {
		cfg.OutputFile = outputPath

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		if err := runMerge(nil, []string{path}); err != nil {
			t.Fatalf("runMerge error: %v", err)
		}

		raw, _ := os.ReadFile(outputPath)
		var result report.FindingCollection
		_ = json.Unmarshal(raw, &result)
		if len(result.Findings) != 1 {
			t.Fatalf("expected 1 deduplicated finding, got %d", len(result.Findings))
		}
	})
}
