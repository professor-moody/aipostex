package output

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestHTMLWriterProducesValidReport(t *testing.T) {
	path := t.TempDir() + "/report.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatalf("NewHTMLWriter: %v", err)
	}
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if err := w.WriteFinding(report.Finding{
		Timestamp:   time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Source:      report.SourceVulnCheck,
		TemplateID:  "chroma-auth-001",
		Target:      "http://10.0.0.1:8000",
		Title:       "ChromaDB Unauthenticated",
		Severity:    report.SeverityHigh,
		Description: "No authentication on API.",
		Tags:        []string{"chromadb", "auth"},
		Evidence:    "collections: [\"test\"]",
	}); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if err := w.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Title:    "Low finding",
		Target:   "http://10.0.0.2:8000",
		Severity: report.SeverityLow,
	}); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}

	stats := map[string]int{
		report.SeverityCritical: 0,
		report.SeverityHigh:     1,
		report.SeverityMedium:   0,
		report.SeverityLow:      1,
		report.SeverityInfo:     0,
	}
	if err := w.WriteFooter(stats); err != nil {
		t.Fatalf("WriteFooter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	content := string(data)

	for _, expected := range []string{
		"<!DOCTYPE html>",
		"AI Infrastructure Security Assessment",
		"ChromaDB Unauthenticated",
		"chroma-auth-001",
		"sev-high",
		"chromadb",
		"host-card",
		"exec-summary",
		"Executive Summary",
		"sev-bar",
		"sidebar",
		"sb-link",
		"filterToolbar",
		"findSearch",
		"detail-row",
		"toggleDetail",
		"beforeprint",
		"</html>",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected HTML to contain %q", expected)
		}
	}
}

func TestHTMLWriterEscapesSpecialChars(t *testing.T) {
	path := t.TempDir() + "/escape.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatalf("NewHTMLWriter: %v", err)
	}
	if err := w.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Title:    "<script>alert('xss')</script>",
		Target:   "http://evil.test/",
		Severity: report.SeverityInfo,
	}); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if err := w.WriteFooter(map[string]int{report.SeverityInfo: 1}); err != nil {
		t.Fatalf("WriteFooter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "<script>alert") {
		t.Fatalf("expected HTML-escaped output, found raw script tag")
	}
	if !strings.Contains(content, "&lt;script&gt;") {
		t.Fatalf("expected escaped script tag in output")
	}
}

func TestHTMLWriterExpandableDetail(t *testing.T) {
	path := t.TempDir() + "/detail.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{
		Source:      report.SourceVulnCheck,
		Target:      "http://10.0.0.1:11434",
		Title:       "Proof of Concept",
		Severity:    report.SeverityCritical,
		Description: "This is a test description",
		Remediation: "Apply patch immediately",
		Evidence:    strings.Repeat("E", 500),
		References:  []string{"https://example.com/ref"},
	})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1})
	_ = w.Close()

	data, _ := os.ReadFile(path)
	content := string(data)

	for _, expect := range []string{
		"detail-row",
		"detail-panel",
		"finding-row",
		`class="evidence"`,
		"remediation-callout",
		"Apply patch immediately",
		"https://example.com/ref",
		"This is a test description",
	} {
		if !strings.Contains(content, expect) {
			t.Fatalf("expected HTML to contain %q", expect)
		}
	}
}

func TestHTMLCellReferencesRendersHTTPLinks(t *testing.T) {
	rendered := htmlCellReferences([]string{
		"http://example.com/advisory",
		"https://example.com/reference",
	}, func(s string) string { return s })

	if strings.Count(rendered, "<a href=") != 2 {
		t.Fatalf("expected both HTTP(S) references to render as links, got %q", rendered)
	}
	if !strings.Contains(rendered, `href="http://example.com/advisory"`) {
		t.Fatalf("expected http reference to be linkified, got %q", rendered)
	}
	if !strings.Contains(rendered, `href="https://example.com/reference"`) {
		t.Fatalf("expected https reference to be linkified, got %q", rendered)
	}
}

func TestHTMLCellReferencesRejectsJavascriptScheme(t *testing.T) {
	rendered := htmlCellReferences([]string{"javascript:alert(1)"}, func(s string) string { return s })

	if strings.Contains(rendered, "<a href=") {
		t.Fatalf("expected javascript scheme to remain plain text, got %q", rendered)
	}
	if !strings.Contains(rendered, "<li>javascript:alert(1)</li>") {
		t.Fatalf("expected javascript scheme to render as list text, got %q", rendered)
	}
}

func TestHTMLWriterEngagementStrip(t *testing.T) {
	path := t.TempDir() + "/eng.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatalf("NewHTMLWriter: %v", err)
	}
	w.EngagementID = "eng-test123"
	w.EngagementStart = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	if err := w.WriteFooter(map[string]int{}); err != nil {
		t.Fatalf("WriteFooter: %v", err)
	}
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "eng-test123") {
		t.Fatal("expected engagement id in output")
	}
	if !strings.Contains(content, "eng-strip") {
		t.Fatal("expected eng-strip block")
	}
}

func TestHTMLWriterPrintCSS(t *testing.T) {
	path := t.TempDir() + "/print.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFooter(map[string]int{})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "@media print") {
		t.Fatal("expected print media rules")
	}
	if !strings.Contains(content, "no-print") {
		t.Fatal("expected no-print utility class")
	}
	if !strings.Contains(content, "beforeprint") {
		t.Fatal("expected beforeprint JS handler")
	}
}

func TestHTMLWriterTopFindingsNormalizesMixedCaseSeverity(t *testing.T) {
	path := t.TempDir() + "/mixed-case.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://a:1", Title: "Critical Finding", Severity: "CRITICAL"})
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://a:2", Title: "High Finding", Severity: "High"})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1, report.SeverityHigh: 1})
	_ = w.Close()

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "Critical Finding") || !strings.Contains(content, "High Finding") {
		t.Fatalf("expected mixed-case severities to appear in top findings, got %q", content)
	}
}

func TestHTMLWriterSeverityBar(t *testing.T) {
	path := t.TempDir() + "/bar.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://a:1", Title: "C", Severity: report.SeverityCritical})
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://a:1", Title: "H", Severity: report.SeverityHigh})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1, report.SeverityHigh: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "sev-bar") {
		t.Fatal("expected sev-bar div")
	}
	if !strings.Contains(content, "seg-critical") {
		t.Fatal("expected critical segment in bar")
	}
	if !strings.Contains(content, "sev-legend") {
		t.Fatal("expected sev-legend")
	}
}

func TestHTMLWriterExecSummary(t *testing.T) {
	path := t.TempDir() + "/exec.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://a:1", Title: "RCE Bug",
		Severity: report.SeverityCritical, Description: "Remote code execution via unauthenticated endpoint",
		Metadata: map[string]interface{}{"service": "ollama"},
	})
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://b:2", Title: "Info Leak", Severity: report.SeverityInfo})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1, report.SeverityInfo: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)

	for _, expected := range []string{
		"Executive Summary",
		"risk-verdict",
		"stat-cards",
		"stat-card",
		"RCE Bug",
		"Remote code execution",
		"risk-host-tbl",
		"tf-card",
		"top-findings",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected HTML to contain %q", expected)
		}
	}
}

func TestHTMLWriterExecSummaryStatCards(t *testing.T) {
	path := t.TempDir() + "/stat.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://10.0.0.1:8080", Title: "A", Severity: report.SeverityCritical})
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://10.0.0.1:8080", Title: "B", Severity: report.SeverityHigh})
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://10.0.0.2:9090", Title: "C", Severity: report.SeverityMedium})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1, report.SeverityHigh: 1, report.SeverityMedium: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "stat-critical") {
		t.Fatal("expected critical stat card class")
	}
	if !strings.Contains(content, "stat-high") {
		t.Fatal("expected high stat card class")
	}
	if !strings.Contains(content, "Hosts Assessed") {
		t.Fatal("expected 'Hosts Assessed' label")
	}
}

func TestHTMLWriterAttackSurface(t *testing.T) {
	path := t.TempDir() + "/surface.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{
		Source: report.SourceFingerprint, Target: "http://10.0.0.1:11434",
		Title: "ollama found", Severity: report.SeverityInfo,
		Metadata: map[string]interface{}{"service": "ollama"},
	})
	_ = w.WriteFinding(report.Finding{
		Source: report.SourceFingerprint, Target: "http://10.0.0.2:8000",
		Title: "chromadb found", Severity: report.SeverityInfo,
		Metadata: map[string]interface{}{"service": "chromadb"},
	})
	_ = w.WriteFooter(map[string]int{report.SeverityInfo: 2})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "attack-surface") {
		t.Fatal("expected attack-surface section")
	}
	if !strings.Contains(content, "LLM Inference") {
		t.Fatal("expected 'LLM Inference' service category")
	}
	if !strings.Contains(content, "Vector Database") {
		t.Fatal("expected 'Vector Database' service category")
	}
}

func TestHTMLWriterRiskByHost(t *testing.T) {
	path := t.TempDir() + "/risk.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://10.0.0.1:8080", Title: "Critical RCE", Severity: report.SeverityCritical})
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://10.0.0.2:9090", Title: "Info Disclosure", Severity: report.SeverityInfo})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1, report.SeverityInfo: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "risk-host-tbl") {
		t.Fatal("expected risk-by-host table")
	}
	if !strings.Contains(content, "10.0.0.1") {
		t.Fatal("expected host 10.0.0.1 in risk table")
	}
	if !strings.Contains(content, "Critical RCE") {
		t.Fatal("expected top finding for host in risk table")
	}
}

func TestHTMLWriterNoFindings(t *testing.T) {
	path := t.TempDir() + "/empty.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFooter(map[string]int{})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "No findings") {
		t.Fatal("expected 'No findings' message")
	}
}

func TestHTMLWriterHostCards(t *testing.T) {
	path := t.TempDir() + "/cards.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://10.0.0.1:8080/api", Title: "A", Severity: report.SeverityHigh})
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://10.0.0.2:9090/path", Title: "B", Severity: report.SeverityLow})
	_ = w.WriteFooter(map[string]int{report.SeverityHigh: 1, report.SeverityLow: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if count := strings.Count(content, "host-card"); count < 2 {
		t.Fatalf("expected at least 2 host-card sections, got %d occurrences", count)
	}
	if !strings.Contains(content, "host-10-0-0-1") {
		t.Fatal("expected host anchor for 10.0.0.1")
	}
	if !strings.Contains(content, "host-10-0-0-2") {
		t.Fatal("expected host anchor for 10.0.0.2")
	}
}

func TestHTMLWriterATLASCoverage(t *testing.T) {
	path := t.TempDir() + "/atlas.html"
	w, _ := NewHTMLWriter(path)
	w.ATLASCoverage = map[string]int{
		"AML.T0025": 3,
		"AML.T0048": 1,
	}
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://a:1", Title: "X", Severity: report.SeverityCritical})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "MITRE ATLAS Coverage") {
		t.Fatal("expected ATLAS section heading")
	}
	if !strings.Contains(content, "AML.T0025") {
		t.Fatal("expected AML.T0025 technique")
	}
	if !strings.Contains(content, "AML.T0048") {
		t.Fatal("expected AML.T0048 technique")
	}
	if !strings.Contains(content, "atlas.mitre.org") {
		t.Fatal("expected link to atlas.mitre.org")
	}
	if !strings.Contains(content, `id="atlas-section"`) {
		t.Fatal("expected atlas-section id for sidebar linking")
	}
	if !strings.Contains(content, `data-section="atlas-section"`) {
		t.Fatal("expected sidebar link to ATLAS section")
	}
}

func TestHTMLWriterNoATLASWhenEmpty(t *testing.T) {
	path := t.TempDir() + "/noatlas.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFooter(map[string]int{})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "MITRE ATLAS") {
		t.Fatal("ATLAS section should not appear when no coverage data")
	}
}

func TestHTMLWriterExpandCollapseButtons(t *testing.T) {
	path := t.TempDir() + "/ec.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://a:1", Title: "X", Severity: report.SeverityHigh})
	_ = w.WriteFooter(map[string]int{report.SeverityHigh: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	for _, expected := range []string{
		"expandAll",
		"collapseAll",
		"Expand All",
		"Collapse All",
		"bulk-controls",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected HTML to contain %q", expected)
		}
	}
}

func TestHTMLWriterConfidentialNotice(t *testing.T) {
	path := t.TempDir() + "/conf.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFooter(map[string]int{})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "data classification") {
		t.Fatal("expected confidentiality notice")
	}
}

func TestHTMLWriterSidebar(t *testing.T) {
	path := t.TempDir() + "/sb.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://10.0.0.1:8080", Title: "A", Severity: report.SeverityCritical})
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://10.0.0.2:9090", Title: "B", Severity: report.SeverityHigh})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1, report.SeverityHigh: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)

	for _, expected := range []string{
		`class="sidebar`,
		"sb-brand",
		"sb-nav",
		`data-section="exec-summary"`,
		"sb-dot",
		"sb-count",
		"10.0.0.1",
		"10.0.0.2",
		"IntersectionObserver",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("sidebar: expected HTML to contain %q", expected)
		}
	}

	if strings.Contains(content, `class="topbar`) {
		t.Fatal("old topbar should be removed")
	}
}

func TestHTMLWriterSidebarATLASLink(t *testing.T) {
	path := t.TempDir() + "/sb-atlas.html"
	w, _ := NewHTMLWriter(path)
	w.ATLASCoverage = map[string]int{"AML.T0001": 1}
	_ = w.WriteFinding(report.Finding{Source: "test", Target: "http://a:1", Title: "X", Severity: report.SeverityCritical})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, `data-section="atlas-section"`) {
		t.Fatal("sidebar should include ATLAS link when coverage exists")
	}
}

func TestHTMLWriterRiskByHostExploitColumns(t *testing.T) {
	path := t.TempDir() + "/risk-cols.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:3000", Title: "MCP RCE",
		Severity: report.SeverityCritical,
		Metadata: map[string]interface{}{"landed": "execution-confirmed"},
	})
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:8888", Title: "Jupyter No Auth",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{"stage": "impact", "landed": "confirmed"},
	})
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.2:11434", Title: "Ollama Exposed",
		Severity: report.SeverityCritical,
		Metadata: map[string]interface{}{"landed": "execution-confirmed"},
	})
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:11434", Title: "Info Only",
		Severity: report.SeverityInfo,
	})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 2, report.SeverityHigh: 1, report.SeverityInfo: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)

	for _, expected := range []string{
		"risk-host-tbl",
		">Exploited<",
		">Verified<",
		"10.0.0.1",
		"10.0.0.2",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("risk table: expected HTML to contain %q", expected)
		}
	}

	if strings.Contains(content, "exploit-summary") {
		t.Fatal("standalone exploit-summary section should not exist")
	}
	if strings.Contains(content, "Exploitation Summary") {
		t.Fatal("Exploitation Summary heading should not exist")
	}
}

func TestHTMLWriterProvenStatCard(t *testing.T) {
	path := t.TempDir() + "/proven.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:3000", Title: "A",
		Severity: report.SeverityCritical,
		Metadata: map[string]interface{}{"landed": "execution-confirmed"},
	})
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:8888", Title: "B",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{"landed": "confirmed"},
	})
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:11434", Title: "C",
		Severity: report.SeverityMedium,
	})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1, report.SeverityHigh: 1, report.SeverityMedium: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "stat-proven") {
		t.Fatal("expected stat-proven class on proven stat card")
	}
	if !strings.Contains(content, ">Proven<") {
		t.Fatal("expected 'Proven' label on stat card")
	}
}

func TestHTMLWriterCollapsibleHostCards(t *testing.T) {
	path := t.TempDir() + "/collapse.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:8080", Title: "A", Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{"service": "ollama"},
	})
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:3000", Title: "B", Severity: report.SeverityCritical,
		Metadata: map[string]interface{}{"service": "mcp-sse"},
	})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1, report.SeverityHigh: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)

	for _, expected := range []string{
		"hc-chevron",
		"hc-body",
		"toggleHostCard",
		"hc-services",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("collapsible: expected HTML to contain %q", expected)
		}
	}

	if !strings.Contains(content, "mcp-sse") || !strings.Contains(content, "ollama") {
		t.Fatal("expected service names in host card")
	}
}

func TestHTMLWriterProofBadgeInTable(t *testing.T) {
	path := t.TempDir() + "/badges.html"
	w, _ := NewHTMLWriter(path)
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:3000", Title: "MCP RCE",
		Severity: report.SeverityCritical,
		Metadata: map[string]interface{}{"landed": "execution-confirmed"},
	})
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:8888", Title: "Jupyter",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{"stage": "impact", "landed": "read-confirmed"},
	})
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:11434", Title: "Info",
		Severity: report.SeverityInfo,
	})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1, report.SeverityHigh: 1, report.SeverityInfo: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, `proof-badge badge-exploited`) {
		t.Fatal("expected EXPLOITED proof badge in table")
	}
	if !strings.Contains(content, `proof-badge badge-verified`) {
		t.Fatal("expected VERIFIED proof badge in table")
	}
	if !strings.Contains(content, ">EXPLOITED<") {
		t.Fatal("expected EXPLOITED text in badge")
	}
	if !strings.Contains(content, ">VERIFIED<") {
		t.Fatal("expected VERIFIED text in badge")
	}
	if !strings.Contains(content, ">Landed<") {
		t.Fatal("expected Landed column header in table")
	}
	if !strings.Contains(content, `colspan="6"`) {
		t.Fatal("detail rows should span 6 columns")
	}
}

func TestProofBadgeClassEnrichmentVocab(t *testing.T) {
	tests := []struct {
		name      string
		finding   report.Finding
		wantBadge string
	}{
		{"execution-confirmed", report.Finding{Metadata: map[string]interface{}{"landed": "execution-confirmed"}}, badgeExploited},
		{"takeover-capable", report.Finding{Metadata: map[string]interface{}{"landed": "takeover-capable"}}, badgeExploited},
		{"read-confirmed", report.Finding{Metadata: map[string]interface{}{"landed": "read-confirmed"}}, badgeVerified},
		{"influenced", report.Finding{Metadata: map[string]interface{}{"landed": "influenced"}}, badgeVerified},
		{"reachable is no badge", report.Finding{Metadata: map[string]interface{}{"landed": "reachable"}}, ""},
		// Badge by OUTCOME, not intent/source/stage.
		{"bare mutating=true proves nothing", report.Finding{Metadata: map[string]interface{}{"mutating": "true"}}, ""},
		{"failed mutating (influenced) is verified, not exploited", report.Finding{Metadata: map[string]interface{}{"mutating": "true", "landed": "influenced"}}, badgeVerified},
		{"successful mutating (execution-confirmed) is exploited", report.Finding{Metadata: map[string]interface{}{"mutating": "true", "landed": "execution-confirmed"}}, badgeExploited},
		{"bare stage=impact proves nothing", report.Finding{Metadata: map[string]interface{}{"stage": "impact"}}, ""},
		{"bare vulncheck source proves nothing", report.Finding{Source: report.SourceVulnCheck}, ""},
		{"nil metadata", report.Finding{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := proofBadgeClass(tt.finding)
			if got != tt.wantBadge {
				t.Errorf("proofBadgeClass() = %q, want %q", got, tt.wantBadge)
			}
		})
	}
}

func TestHTMLWriterScanModeInEngStrip(t *testing.T) {
	path := t.TempDir() + "/mode-test.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatalf("NewHTMLWriter: %v", err)
	}
	w.ScanMode = "detect"
	_ = w.WriteHeader()
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:11434", Title: "Test Finding",
		Severity: report.SeverityHigh,
	})
	_ = w.WriteFooter(map[string]int{report.SeverityHigh: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "Scan Mode") {
		t.Fatal("expected 'Scan Mode' label in engagement strip")
	}
	if !strings.Contains(content, "Detection Only") {
		t.Fatal("expected 'Detection Only' value in engagement strip")
	}
}

func TestHTMLWriterScanModeFullInEngStrip(t *testing.T) {
	path := t.TempDir() + "/mode-full-test.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatalf("NewHTMLWriter: %v", err)
	}
	w.ScanMode = "full"
	_ = w.WriteHeader()
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:11434", Title: "Test Finding",
		Severity: report.SeverityCritical,
	})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "Full Assessment") {
		t.Fatal("expected 'Full Assessment' value for full mode")
	}
}

func TestHTMLWriterDetectModeVerdict(t *testing.T) {
	path := t.TempDir() + "/verdict-detect.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatalf("NewHTMLWriter: %v", err)
	}
	w.ScanMode = "detect"
	_ = w.WriteHeader()
	_ = w.WriteFinding(report.Finding{
		Source: "test", Target: "http://10.0.0.1:11434", Title: "Critical Finding",
		Severity: report.SeverityCritical,
	})
	_ = w.WriteFooter(map[string]int{report.SeverityCritical: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "detection-only assessment") {
		t.Fatal("expected 'detection-only assessment' in verdict for detect mode")
	}
}

func TestHTMLWriterConcurrentWriteFinding(t *testing.T) {
	path := t.TempDir() + "/concurrent.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatalf("NewHTMLWriter: %v", err)
	}

	const goroutines = 20
	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			_ = w.WriteFinding(report.Finding{
				Source:   report.SourceVulnCheck,
				Target:   "http://10.0.0.1:8080",
				Title:    fmt.Sprintf("Finding-%d", n),
				Severity: report.SeverityHigh,
			})
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}

	stats := map[string]int{report.SeverityHigh: goroutines}
	if err := w.WriteFooter(stats); err != nil {
		t.Fatalf("WriteFooter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	content := string(data)
	for i := 0; i < goroutines; i++ {
		expected := fmt.Sprintf("Finding-%d", i)
		if !strings.Contains(content, expected) {
			t.Fatalf("expected HTML to contain %q", expected)
		}
	}
}

func TestHTMLWriterInitForBuffer(t *testing.T) {
	hw := &HTMLWriter{}
	var buf strings.Builder
	hw.InitForBuffer(&buf)
	_ = hw.WriteFinding(report.Finding{Source: "test", Target: "http://a:1", Title: "X", Severity: report.SeverityInfo})
	_ = hw.WriteFooter(map[string]int{report.SeverityInfo: 1})
	if buf.Len() == 0 {
		t.Fatal("expected buffer to contain HTML")
	}
	if !strings.Contains(buf.String(), "<!DOCTYPE html>") {
		t.Fatal("expected valid HTML in buffer")
	}
}

func TestHTMLWriterCloseFile(t *testing.T) {
	path := t.TempDir() + "/close-test.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatalf("NewHTMLWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	// Closing a second time should fail since the file is already closed.
	if err := w.Close(); err == nil {
		t.Fatal("expected error on second Close")
	}
}

func TestHTMLWriterCloseStdoutIsNoOp(t *testing.T) {
	w, err := NewHTMLWriter("-")
	if err != nil {
		t.Fatalf("NewHTMLWriter(-): %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close on stdout writer should be no-op, got %v", err)
	}
}

func TestHTMLWriterNoOpWriteHeader(t *testing.T) {
	hw := &HTMLWriter{w: &nopStringWriteCloser{&strings.Builder{}}}
	if err := hw.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader should be no-op, got %v", err)
	}
}

func TestCategorizeServiceAllCategories(t *testing.T) {
	tests := []struct {
		service  string
		expected string
	}{
		{"ollama", "LLM Inference"},
		{"vllm", "LLM Inference"},
		{"litellm", "LLM Inference"},
		{"lmstudio", "LLM Inference"},
		{"localai", "LLM Inference"},
		{"openai-compatible", "LLM Inference"},
		{"chromadb", "Vector Database"},
		{"weaviate", "Vector Database"},
		{"qdrant", "Vector Database"},
		{"mlflow", "Experiment Tracking"},
		{"jupyter", "Notebooks"},
		{"mcp-sse", "MCP Server"},
		{"mcp-inspector", "MCP Server"},
		{"mcpjam-inspector", "MCP Server"},
		{"mcp-custom", "MCP Server"},
		{"gradio", "ML App Framework"},
		{"streamlit", "ML App Framework"},
		{"ray", "Distributed Compute"},
		{"open-webui", "AI UI"},
		{"unknownservice", "Unknownservice"},
	}
	for _, tc := range tests {
		t.Run(tc.service, func(t *testing.T) {
			got := categorizeService(tc.service)
			if got != tc.expected {
				t.Errorf("categorizeService(%q) = %q, want %q", tc.service, got, tc.expected)
			}
		})
	}
}

func TestMetaStr(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]interface{}
		key  string
		want string
	}{
		{"nil map", nil, "key", ""},
		{"missing key", map[string]interface{}{"a": "b"}, "key", ""},
		{"string value", map[string]interface{}{"key": "val"}, "key", "val"},
		{"bool true", map[string]interface{}{"key": true}, "key", "true"},
		{"bool false", map[string]interface{}{"key": false}, "key", "false"},
		{"int value", map[string]interface{}{"key": 42}, "key", "42"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := metaStr(tc.m, tc.key)
			if got != tc.want {
				t.Errorf("metaStr(%v, %q) = %q, want %q", tc.m, tc.key, got, tc.want)
			}
		})
	}
}

func TestHTMLCellReferencesEmpty(t *testing.T) {
	result := htmlCellReferences(nil, func(s string) string { return s })
	if !strings.Contains(result, "muted") {
		t.Fatalf("expected muted span for empty refs, got %q", result)
	}
}

func TestHTMLCellReferencesBlankStrings(t *testing.T) {
	result := htmlCellReferences([]string{"", "   "}, func(s string) string { return s })
	if !strings.Contains(result, "muted") {
		t.Fatalf("expected muted span for blank-only refs, got %q", result)
	}
}

func TestHTMLWriterFullPipelineToFile(t *testing.T) {
	path := t.TempDir() + "/full-pipe.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	w.ScanMode = "full"
	w.EngagementID = "test-eng"
	w.EngagementEnd = time.Now().UTC()
	if err := w.WriteHeader(); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFinding(report.Finding{
		Source:      report.SourceVulnCheck,
		Target:      "http://10.0.0.1:3000",
		Title:       "MCP Server Exploit",
		Severity:    report.SeverityCritical,
		CVSS:        9.8,
		Description: "RCE via MCP",
		Remediation: "Patch immediately",
		Evidence:    "proof of concept output",
		Tags:        []string{"mcp", "rce"},
		References:  []string{"https://example.com/cve"},
		Metadata: map[string]interface{}{
			"landed":   "execution-confirmed",
			"service":  "mcp-sse",
			"mutating": "true",
		},
	}); err != nil {
		t.Fatal(err)
	}
	stats := map[string]int{
		report.SeverityCritical: 1,
	}
	if err := w.WriteFooter(stats); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	content := string(data)
	for _, expected := range []string{
		"Full Assessment",
		"test-eng",
		"MCP Server Exploit",
		"9.8",
		"Patch immediately",
		"badge-exploited",
		"EXPLOITED",
		"</html>",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected HTML to contain %q", expected)
		}
	}
}

func TestHTMLWriterRiskVerdictNoCritHigh(t *testing.T) {
	verdict := htmlRiskVerdict(nil, 1, 0, 0, "")
	if !strings.Contains(verdict, "did not identify critical") {
		t.Fatalf("expected no-crit verdict, got %q", verdict)
	}
}

func TestHTMLWriterRiskVerdictFullMode(t *testing.T) {
	cats := []svcCategory{{name: "LLM Inference", hostCount: 1}}
	verdict := htmlRiskVerdict(cats, 2, 1, 3, "full")
	if !strings.Contains(verdict, "full assessment identified and actively validated") {
		t.Fatalf("expected full mode prefix, got %q", verdict)
	}
}

func TestVulncheckFindingAlwaysGetsBadge(t *testing.T) {
	path := t.TempDir() + "/badge-reachable.html"
	w, err := NewHTMLWriter(path)
	if err != nil {
		t.Fatalf("NewHTMLWriter: %v", err)
	}
	_ = w.WriteHeader()
	_ = w.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://10.0.0.1:3000",
		Title:    "MCP Server Exposes File Read Tool",
		Severity: report.SeverityMedium,
		Metadata: map[string]interface{}{
			"stage":  "access",
			"landed": "reachable",
		},
	})
	_ = w.WriteFooter(map[string]int{report.SeverityMedium: 1})
	_ = w.Close()
	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "badge-verified") {
		t.Fatal("expected VERIFIED badge for vulncheck finding with landed: reachable")
	}
}
