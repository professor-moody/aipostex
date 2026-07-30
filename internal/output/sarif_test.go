package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestSARIFWriterProducesValidStructure(t *testing.T) {
	var out strings.Builder
	sw := &SARIFWriter{w: nopWriteCloser{&out}}

	_ = sw.WriteFinding(report.Finding{
		Source:      report.SourceVulnCheck,
		TemplateID:  "ollama-auth-001",
		Target:      "http://10.0.0.5:11434",
		Title:       "Ollama Unauthenticated",
		Severity:    report.SeverityHigh,
		Description: "No auth required",
		Remediation: "Enable auth",
		Tags:        []string{"ollama", "auth"},
	})
	_ = sw.WriteFinding(report.Finding{
		Source:   report.SourceOllama,
		Target:   "http://10.0.0.5:11434",
		Title:    "Ollama Enum",
		Severity: report.SeverityInfo,
	})
	_ = sw.WriteFooter(nil)

	var log sarifLog
	if err := json.Unmarshal([]byte(out.String()), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("expected version 2.1.0, got %s", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "aipostex" {
		t.Fatalf("expected tool name aipostex, got %s", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestSARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{report.SeverityCritical, "error"},
		{report.SeverityHigh, "error"},
		{report.SeverityMedium, "warning"},
		{report.SeverityLow, "note"},
		{report.SeverityInfo, "note"},
	}
	for _, tc := range tests {
		got := sarifLevel(tc.severity)
		if got != tc.expected {
			t.Errorf("sarifLevel(%s) = %s, want %s", tc.severity, got, tc.expected)
		}
	}
}

func TestSARIFRuleDeduplication(t *testing.T) {
	var out strings.Builder
	sw := &SARIFWriter{w: nopWriteCloser{&out}}

	for i := 0; i < 3; i++ {
		_ = sw.WriteFinding(report.Finding{
			Source:     report.SourceVulnCheck,
			TemplateID: "mcp-auth-001",
			Target:     "http://10.0.0.5:3000",
			Title:      "MCP Unauthenticated",
			Severity:   report.SeverityHigh,
		})
	}
	_ = sw.WriteFooter(nil)

	var log sarifLog
	if err := json.Unmarshal([]byte(out.String()), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule (deduped), got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
	if len(log.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(log.Runs[0].Results))
	}
	for _, r := range log.Runs[0].Results {
		if r.RuleIndex != 0 {
			t.Fatalf("expected all results to reference rule index 0, got %d", r.RuleIndex)
		}
	}
}

func TestSARIFSecuritySeverityFromCVSS(t *testing.T) {
	got := sarifSecuritySeverity(report.Finding{CVSS: 7.5, Severity: report.SeverityCritical})
	if got != "7.5" {
		t.Fatalf("expected CVSS-based severity 7.5, got %s", got)
	}
}

func TestSARIFRuleIDFallback(t *testing.T) {
	got := sarifRuleID(report.Finding{Source: "ollama", Title: "Enum Found"})
	if got != "ollama/enum-found" {
		t.Fatalf("expected ollama/enum-found, got %s", got)
	}
}

func TestSARIFLocationsPresent(t *testing.T) {
	var out strings.Builder
	sw := &SARIFWriter{w: nopWriteCloser{&out}}

	_ = sw.WriteFinding(report.Finding{
		Source:     report.SourceVulnCheck,
		TemplateID: "test-001",
		Target:     "http://10.0.0.5:8080",
		Title:      "Test",
		Severity:   report.SeverityMedium,
	})
	_ = sw.WriteFooter(nil)

	var log sarifLog
	_ = json.Unmarshal([]byte(out.String()), &log)
	if len(log.Runs[0].Results[0].Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(log.Runs[0].Results[0].Locations))
	}
	uri := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri != "http://10.0.0.5:8080" {
		t.Fatalf("expected target URI, got %s", uri)
	}
}

func TestSARIFWriterNoOpWriteHeader(t *testing.T) {
	sw := &SARIFWriter{w: nopWriteCloser{&strings.Builder{}}}
	if err := sw.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader should be no-op, got %v", err)
	}
}

func TestSARIFWriterCloseNonStdout(t *testing.T) {
	path := t.TempDir() + "/sarif.json"
	sw, err := NewSARIFWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = sw.WriteFooter(nil)
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewSARIFWriter(t *testing.T) {
	path := t.TempDir() + "/test-sarif.json"
	sw, err := NewSARIFWriter(path)
	if err != nil {
		t.Fatalf("NewSARIFWriter: %v", err)
	}
	if sw == nil {
		t.Fatal("expected non-nil writer")
	}
	_ = sw.Close()
}

func TestSARIFSecuritySeverityDefaults(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{report.SeverityCritical, "9.5"},
		{report.SeverityHigh, "8.0"},
		{report.SeverityMedium, "5.5"},
		{report.SeverityLow, "2.5"},
		{report.SeverityInfo, "1.0"},
		{"unknown", "1.0"},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			got := sarifSecuritySeverity(report.Finding{Severity: tc.severity})
			if got != tc.want {
				t.Errorf("sarifSecuritySeverity(sev=%q) = %q, want %q", tc.severity, got, tc.want)
			}
		})
	}
}

func TestSARIFWriterFullPipeline(t *testing.T) {
	var out strings.Builder
	sw := &SARIFWriter{w: nopWriteCloser{&out}}

	_ = sw.WriteHeader()
	_ = sw.WriteFinding(report.Finding{
		ID:          "f-1",
		Source:      report.SourceOllama,
		Target:      "http://10.0.0.1:11434",
		Title:       "RCE via Ollama",
		Severity:    report.SeverityCritical,
		CVSS:        9.8,
		Description: "Remote code execution",
		Evidence:    "bash output here",
		Remediation: "Enable auth",
		Tags:        []string{"ollama", "rce"},
		Metadata:    map[string]interface{}{"action": "exploit"},
	})
	_ = sw.WriteFooter(nil)

	var log sarifLog
	if err := json.Unmarshal([]byte(out.String()), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	result := log.Runs[0].Results[0]
	if result.Properties["source"] != "ollama" {
		t.Fatalf("expected source in properties, got %v", result.Properties)
	}
	if result.Properties["cvss"] != 9.8 {
		t.Fatalf("expected cvss in properties, got %v", result.Properties)
	}
	if result.Properties["finding_id"] != "f-1" {
		t.Fatalf("expected finding_id, got %v", result.Properties)
	}
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.Help == nil || rule.Help.Text != "Enable auth" {
		t.Fatalf("expected remediation in rule help, got %v", rule.Help)
	}
	if result.Message.Markdown == "" {
		t.Fatal("expected markdown evidence in message")
	}
}

func TestSARIFWriterCreateAndClose(t *testing.T) {
	path := t.TempDir() + "/test-close.sarif"
	sw, err := NewSARIFWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = sw.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://10.0.0.1:8080",
		Title:    "Test",
		Severity: report.SeverityMedium,
	})
	if err := sw.WriteFooter(nil); err != nil {
		t.Fatal(err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

type nopWriteCloser struct{ *strings.Builder }

func (nopWriteCloser) Close() error { return nil }
