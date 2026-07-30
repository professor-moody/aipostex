package main

import (
	"strings"
	"testing"

	"github.com/fatih/color"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestBuildSummaryRiskScore(t *testing.T) {
	findings := []report.Finding{
		{Target: "http://10.0.0.5:11434", Severity: report.SeverityCritical, Source: report.SourceVulnCheck, Title: "RCE"},
		{Target: "http://10.0.0.5:11434", Severity: report.SeverityHigh, Source: report.SourceVulnCheck, Title: "Auth Bypass"},
		{Target: "http://10.0.0.5:8888", Severity: report.SeverityMedium, Source: report.SourceVulnCheck, Title: "Info Leak"},
		{Target: "http://10.0.0.5:8888", Severity: report.SeverityLow, Source: report.SourceVulnCheck, Title: "Version"},
	}

	s := buildSummary(findings)

	expected := 10.0 + 5.0 + 2.0 + 0.5
	if s.RiskScore != expected {
		t.Fatalf("expected risk score %.1f, got %.1f", expected, s.RiskScore)
	}
	if s.RiskGrade != "A-" {
		t.Fatalf("expected grade A-, got %s", s.RiskGrade)
	}
}

func TestBuildSummaryRiskScoreCapped(t *testing.T) {
	var findings []report.Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, report.Finding{
			Target: "http://10.0.0.5:11434", Severity: report.SeverityCritical,
			Source: report.SourceVulnCheck, Title: "RCE",
		})
	}

	s := buildSummary(findings)
	if s.RiskScore != 100 {
		t.Fatalf("expected capped risk score 100, got %.1f", s.RiskScore)
	}
	if s.RiskGrade != "F" {
		t.Fatalf("expected grade F, got %s", s.RiskGrade)
	}
}

func TestBuildSummaryCoverageGaps(t *testing.T) {
	findings := []report.Finding{
		{
			Target:   "http://10.0.0.5:11434",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Title:    "Ollama Detected",
			Metadata: map[string]interface{}{"service": "ollama"},
		},
		{
			Target:   "http://10.0.0.5:8888",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Title:    "Jupyter Detected",
			Metadata: map[string]interface{}{"service": "jupyter"},
		},
		{
			Target:   "http://10.0.0.5:11434",
			Severity: report.SeverityHigh,
			Source:   report.SourceVulnCheck,
			Title:    "Ollama No Auth",
		},
	}

	s := buildSummary(findings)
	if len(s.CoverageGaps) != 1 {
		t.Fatalf("expected 1 coverage gap, got %d: %v", len(s.CoverageGaps), s.CoverageGaps)
	}
	if s.CoverageGaps[0] != "http://10.0.0.5:8888" {
		t.Fatalf("expected jupyter gap, got %s", s.CoverageGaps[0])
	}
}

func TestBuildSummaryBucketsFileDiscoveryUnderLocalFiles(t *testing.T) {
	s := buildSummary([]report.Finding{
		{Target: "/tmp/a.env", Severity: report.SeverityHigh, Source: report.SourceFileDiscovery, Title: "Secrets A"},
		{Target: "/tmp/b.env", Severity: report.SeverityMedium, Source: report.SourceFileDiscovery, Title: "Secrets B"},
		{Target: "http://10.0.0.5:11434", Severity: report.SeverityCritical, Source: report.SourceVulnCheck, Title: "Ollama No Auth"},
	})

	if s.Hosts != 2 {
		t.Fatalf("expected file-discovery paths to collapse into one host bucket, got %d hosts", s.Hosts)
	}
}

func TestBuildSummaryRemediationPriority(t *testing.T) {
	findings := []report.Finding{
		{Target: "http://10.0.0.5:11434", Severity: report.SeverityCritical, Source: report.SourceVulnCheck,
			Title: "RCE", Remediation: "Enable auth"},
		{Target: "http://10.0.0.6:11434", Severity: report.SeverityHigh, Source: report.SourceVulnCheck,
			Title: "Auth Bypass", Remediation: "Enable auth"},
		{Target: "http://10.0.0.5:8888", Severity: report.SeverityMedium, Source: report.SourceVulnCheck,
			Title: "Info Leak", Remediation: "Restrict access"},
	}

	s := buildSummary(findings)
	if len(s.Remediations) != 2 {
		t.Fatalf("expected 2 remediations, got %d", len(s.Remediations))
	}
	if s.Remediations[0].Text != "Enable auth" {
		t.Fatalf("expected 'Enable auth' first, got %s", s.Remediations[0].Text)
	}
	if s.Remediations[0].AffectedCount != 2 {
		t.Fatalf("expected 2 affected, got %d", s.Remediations[0].AffectedCount)
	}
}

func TestBuildSummaryNormalizesMixedCaseSeverities(t *testing.T) {
	findings := []report.Finding{
		{Target: "http://10.0.0.5:11434", Severity: "Critical", Source: report.SourceVulnCheck, Title: "RCE"},
		{Target: "http://10.0.0.6:11434", Severity: "HIGH", Source: report.SourceVulnCheck, Title: "Auth Bypass"},
	}

	s := buildSummary(findings)

	if s.Stats[report.SeverityCritical] != 1 {
		t.Fatalf("expected 1 critical finding, got %d", s.Stats[report.SeverityCritical])
	}
	if s.Stats[report.SeverityHigh] != 1 {
		t.Fatalf("expected 1 high finding, got %d", s.Stats[report.SeverityHigh])
	}
}

func TestBuildSummaryMixedCaseMatchesCanonicalRiskAndRanking(t *testing.T) {
	canonical := []report.Finding{
		{
			Target:      "http://10.0.0.5:11434",
			Severity:    report.SeverityCritical,
			Source:      report.SourceVulnCheck,
			Title:       "RCE",
			Remediation: "Enable auth",
			Metadata: map[string]interface{}{
				"stage":  "own",
				"landed": "takeover-capable",
			},
		},
		{
			Target:      "http://10.0.0.5:11434",
			Severity:    report.SeverityHigh,
			Source:      report.SourceVulnCheck,
			Title:       "Auth Bypass",
			Remediation: "Enable auth",
			Metadata: map[string]interface{}{
				"stage":  "impact",
				"landed": "read-confirmed",
			},
		},
	}
	mixedCase := []report.Finding{
		{
			Target:      "http://10.0.0.5:11434",
			Severity:    "Critical",
			Source:      report.SourceVulnCheck,
			Title:       "RCE",
			Remediation: "Enable auth",
			Metadata: map[string]interface{}{
				"stage":  "own",
				"landed": "takeover-capable",
			},
		},
		{
			Target:      "http://10.0.0.5:11434",
			Severity:    "HIGH",
			Source:      report.SourceVulnCheck,
			Title:       "Auth Bypass",
			Remediation: "Enable auth",
			Metadata: map[string]interface{}{
				"stage":  "impact",
				"landed": "read-confirmed",
			},
		},
	}

	canonicalSummary := buildSummary(canonical)
	mixedCaseSummary := buildSummary(mixedCase)

	if mixedCaseSummary.RiskScore != canonicalSummary.RiskScore {
		t.Fatalf("expected risk score %.1f, got %.1f", canonicalSummary.RiskScore, mixedCaseSummary.RiskScore)
	}
	if mixedCaseSummary.RiskGrade != canonicalSummary.RiskGrade {
		t.Fatalf("expected risk grade %s, got %s", canonicalSummary.RiskGrade, mixedCaseSummary.RiskGrade)
	}
	if len(mixedCaseSummary.TopChains) != 1 {
		t.Fatalf("expected 1 top chain, got %d", len(mixedCaseSummary.TopChains))
	}
	if mixedCaseSummary.TopChains[0].CritCount != canonicalSummary.TopChains[0].CritCount {
		t.Fatalf("expected crit count %d, got %d", canonicalSummary.TopChains[0].CritCount, mixedCaseSummary.TopChains[0].CritCount)
	}
	if mixedCaseSummary.TopChains[0].HighCount != canonicalSummary.TopChains[0].HighCount {
		t.Fatalf("expected high count %d, got %d", canonicalSummary.TopChains[0].HighCount, mixedCaseSummary.TopChains[0].HighCount)
	}
	if len(mixedCaseSummary.Remediations) != 1 {
		t.Fatalf("expected 1 remediation, got %d", len(mixedCaseSummary.Remediations))
	}
	if mixedCaseSummary.Remediations[0].HighestSeverity != canonicalSummary.Remediations[0].HighestSeverity {
		t.Fatalf("expected remediation severity %s, got %s", canonicalSummary.Remediations[0].HighestSeverity, mixedCaseSummary.Remediations[0].HighestSeverity)
	}
}

func TestPrintConsoleSummary(t *testing.T) {
	s := buildSummary([]report.Finding{
		{Target: "http://10.0.0.5:11434", Severity: report.SeverityCritical, Source: report.SourceVulnCheck, Title: "RCE"},
	})

	var out strings.Builder
	printConsoleSummary(&out, s)

	rendered := out.String()
	if !strings.Contains(rendered, "Executive Summary") {
		t.Fatalf("expected Executive Summary header")
	}
	if !strings.Contains(rendered, "Risk Score") {
		t.Fatalf("expected Risk Score line")
	}
}

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score float64
		grade string
	}{
		{0, "A"},
		{15, "A-"},
		{35, "B"},
		{55, "C"},
		{75, "D"},
		{95, "F"},
	}
	for _, tc := range tests {
		got := gradeFromScore(tc.score)
		if got != tc.grade {
			t.Errorf("gradeFromScore(%.0f) = %s, want %s", tc.score, got, tc.grade)
		}
	}
}

func TestPrintConsoleSummaryWithChains(t *testing.T) {
	s := buildSummary([]report.Finding{
		{
			Target: "http://10.0.0.5:11434", Severity: report.SeverityCritical,
			Source: report.SourceVulnCheck, Title: "RCE Confirmed",
			Metadata: map[string]interface{}{"stage": "own", "landed": "execution-confirmed"},
		},
		{
			Target: "http://10.0.0.5:11434", Severity: report.SeverityHigh,
			Source: report.SourceVulnCheck, Title: "Auth Bypass",
			Metadata: map[string]interface{}{"stage": "impact", "landed": "read-confirmed"},
		},
	})

	var out strings.Builder
	printConsoleSummary(&out, s)
	rendered := out.String()

	if !strings.Contains(rendered, "Top Critical Chains") {
		t.Fatal("expected Top Critical Chains section")
	}
	if !strings.Contains(rendered, "RCE Confirmed") {
		t.Fatal("expected top finding title in chains")
	}
}

func TestPrintConsoleSummaryWithRemediations(t *testing.T) {
	s := buildSummary([]report.Finding{
		{
			Target: "http://10.0.0.5:11434", Severity: report.SeverityCritical,
			Source: report.SourceVulnCheck, Title: "RCE",
			Remediation: "Enable authentication on Ollama API endpoints",
		},
		{
			Target: "http://10.0.0.6:11434", Severity: report.SeverityHigh,
			Source: report.SourceVulnCheck, Title: "Auth Bypass",
			Remediation: "Enable authentication on Ollama API endpoints",
		},
	})

	var out strings.Builder
	printConsoleSummary(&out, s)
	rendered := out.String()

	if !strings.Contains(rendered, "Remediation Priorities") {
		t.Fatal("expected Remediation Priorities section")
	}
	if !strings.Contains(rendered, "Enable authentication") {
		t.Fatal("expected remediation text")
	}
}

func TestPrintConsoleSummaryWithCoverageGaps(t *testing.T) {
	s := buildSummary([]report.Finding{
		{
			Target: "http://10.0.0.5:11434", Severity: report.SeverityInfo,
			Source: report.SourceFingerprint, Title: "Ollama Detected",
			Metadata: map[string]interface{}{"service": "ollama"},
		},
	})

	var out strings.Builder
	printConsoleSummary(&out, s)
	rendered := out.String()

	if !strings.Contains(rendered, "Coverage Gaps") {
		t.Fatal("expected Coverage Gaps section")
	}
	if !strings.Contains(rendered, "http://10.0.0.5:11434") {
		t.Fatal("expected gap target in output")
	}
}

func TestPrintConsoleSummaryLowRiskScore(t *testing.T) {
	s := buildSummary([]report.Finding{
		{Target: "http://10.0.0.5:11434", Severity: report.SeverityInfo,
			Source: report.SourceVulnCheck, Title: "Version"},
	})

	var out strings.Builder
	printConsoleSummary(&out, s)
	rendered := out.String()

	if !strings.Contains(rendered, "A") {
		t.Fatal("expected grade A for low risk")
	}
}

func TestPrintConsoleSummaryHighRiskScore(t *testing.T) {
	var findings []report.Finding
	for i := 0; i < 15; i++ {
		findings = append(findings, report.Finding{
			Target: "http://10.0.0.5:11434", Severity: report.SeverityCritical,
			Source: report.SourceVulnCheck, Title: "Critical Vuln",
		})
	}

	s := buildSummary(findings)

	var out strings.Builder
	printConsoleSummary(&out, s)
	rendered := out.String()

	if !strings.Contains(rendered, "F") {
		t.Fatal("expected grade F for max risk")
	}
}

func TestPrintBarTruncation(t *testing.T) {
	var out strings.Builder
	printBar(&out, "TEST", 50, color.New(color.FgWhite))
	rendered := out.String()
	if !strings.Contains(rendered, "…") {
		t.Fatal("expected truncated bar for count > 40")
	}
}

func TestPrintBarNormal(t *testing.T) {
	var out strings.Builder
	printBar(&out, "CRIT", 5, color.New(color.FgRed))
	rendered := out.String()
	if !strings.Contains(rendered, "CRIT") {
		t.Fatal("expected label in output")
	}
	if !strings.Contains(rendered, "5") {
		t.Fatal("expected count in output")
	}
}

func TestSeverityRankForSummary(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{report.SeverityCritical, 0},
		{report.SeverityHigh, 1},
		{report.SeverityMedium, 2},
		{report.SeverityLow, 3},
		{report.SeverityInfo, 4},
		{"unknown", 5},
		{"", 5},
	}
	for _, tc := range tests {
		if got := severityRankForSummary(tc.sev); got != tc.want {
			t.Errorf("severityRankForSummary(%q) = %d, want %d", tc.sev, got, tc.want)
		}
	}
}

func TestBuildSummaryToJSON(t *testing.T) {
	s := buildSummary([]report.Finding{
		{Target: "http://10.0.0.5:11434", Severity: report.SeverityCritical,
			Source: report.SourceVulnCheck, Title: "RCE"},
	})

	j := s.toJSON()
	if j["total_findings"].(int) != 1 {
		t.Fatalf("expected total_findings=1, got %v", j["total_findings"])
	}
	if j["risk_grade"].(string) == "" {
		t.Fatal("expected non-empty risk grade")
	}
}
