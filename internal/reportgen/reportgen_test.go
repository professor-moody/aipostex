package reportgen

import (
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/report"
)

func sampleCollection() report.FindingCollection {
	return report.FindingCollection{
		EngagementID: "test-engagement-001",
		StartTime:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		EndTime:      time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC),
		Findings: []report.Finding{
			{
				ID:       "f1",
				Source:   "fingerprint",
				Target:   "http://10.0.0.1:11434",
				Title:    "Ollama detected",
				Severity: "info",
				Tags:     []string{"AML.T0010"},
			},
			{
				ID:          "f2",
				Source:      "vulncheck",
				Target:      "http://10.0.0.1:11434",
				Title:       "Unauthenticated model access",
				Severity:    "high",
				Description: "Models are publicly accessible",
				Remediation: "Enable authentication",
				References:  []string{"https://atlas.mitre.org/techniques/AML.T0024"},
			},
			{
				ID:       "f3",
				Source:   "exploit",
				Target:   "http://10.0.0.2:8265",
				Title:    "Ray dashboard exposed",
				Severity: "critical",
			},
		},
	}
}

func TestGenerate(t *testing.T) {
	fc := sampleCollection()
	r := Generate(fc)

	if r.EngagementID != "test-engagement-001" {
		t.Errorf("EngagementID = %q, want test-engagement-001", r.EngagementID)
	}
	if r.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3", r.TotalFindings)
	}
	if r.Stats[report.SeverityCritical] != 1 {
		t.Errorf("critical count = %d, want 1", r.Stats[report.SeverityCritical])
	}
	if r.Stats[report.SeverityHigh] != 1 {
		t.Errorf("high count = %d, want 1", r.Stats[report.SeverityHigh])
	}
	if r.Stats[report.SeverityInfo] != 1 {
		t.Errorf("info count = %d, want 1", r.Stats[report.SeverityInfo])
	}
	if len(r.TargetCounts) != 2 {
		t.Errorf("target count = %d, want 2", len(r.TargetCounts))
	}
	if len(r.SourceCounts) != 3 {
		t.Errorf("source count = %d, want 3", len(r.SourceCounts))
	}
	if r.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}
}

func TestGenerateATLASCoverage(t *testing.T) {
	fc := sampleCollection()
	r := Generate(fc)

	if len(r.ATLASCoverage) == 0 {
		t.Fatal("expected ATLAS coverage entries")
	}
	if _, ok := r.ATLASCoverage["AML.T0010"]; !ok {
		t.Error("expected AML.T0010 from tags")
	}
	if _, ok := r.ATLASCoverage["AML.T0024"]; !ok {
		t.Error("expected AML.T0024 from references")
	}
}

func TestGenerateEmptyCollection(t *testing.T) {
	fc := report.FindingCollection{}
	r := Generate(fc)

	if r.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", r.TotalFindings)
	}
	if len(r.SourceCounts) != 0 {
		t.Errorf("SourceCounts should be empty, got %v", r.SourceCounts)
	}
}

func TestRenderMarkdown(t *testing.T) {
	fc := sampleCollection()
	r := Generate(fc)
	md := RenderMarkdown(r)

	checks := []string{
		"# aipostex Engagement Report",
		"test-engagement-001",
		"## Executive Summary",
		"**Total Findings:** 3",
		"### Severity Breakdown",
		"## Findings by Target",
		"Ollama detected",
		"Unauthenticated model access",
		"Ray dashboard exposed",
		"Enable authentication",
		"MITRE ATLAS Coverage",
		"AML.T0010",
	}
	for _, check := range checks {
		if !strings.Contains(md, check) {
			t.Errorf("markdown missing %q", check)
		}
	}
}

func TestRenderMarkdownEmpty(t *testing.T) {
	r := Generate(report.FindingCollection{})
	md := RenderMarkdown(r)

	if !strings.Contains(md, "**Total Findings:** 0") {
		t.Error("expected total findings 0 in empty report")
	}
	if strings.Contains(md, "MITRE ATLAS Coverage") {
		t.Error("should not contain ATLAS section when no techniques found")
	}
}

func TestRenderHTML(t *testing.T) {
	fc := sampleCollection()
	r := Generate(fc)
	html := RenderHTML(r)

	if html == "" {
		t.Fatal("RenderHTML returned empty string")
	}
	if !strings.Contains(html, "aipostex") {
		t.Error("HTML should contain aipostex branding")
	}
	if !strings.Contains(html, "Ollama detected") {
		t.Error("HTML should contain finding title")
	}
}

func TestExtractScanMode(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		r := Report{
			TargetCounts: map[string]int{"http://host:80": 1},
			FindingsByTarget: map[string][]report.Finding{
				"http://host:80": {
					{Metadata: map[string]interface{}{"scan_mode": "assess-network"}},
				},
			},
		}
		got := extractScanMode(r)
		if got != "assess-network" {
			t.Errorf("extractScanMode = %q, want assess-network", got)
		}
	})

	t.Run("absent", func(t *testing.T) {
		r := Report{
			TargetCounts: map[string]int{"http://host:80": 1},
			FindingsByTarget: map[string][]report.Finding{
				"http://host:80": {
					{Metadata: map[string]interface{}{}},
				},
			},
		}
		got := extractScanMode(r)
		if got != "" {
			t.Errorf("extractScanMode = %q, want empty", got)
		}
	})
}
