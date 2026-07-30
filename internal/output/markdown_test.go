package output

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestMarkdownWriterGroupsByHost(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	_ = mw.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://10.0.0.5:11434",
		Title:    "Ollama No Auth",
		Severity: report.SeverityCritical,
		Tags:     []string{"ollama"},
	})
	_ = mw.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://10.0.0.6:8888",
		Title:    "Jupyter No Auth",
		Severity: report.SeverityHigh,
		Tags:     []string{"jupyter"},
	})

	_ = mw.WriteFooter(map[string]int{
		report.SeverityCritical: 1,
		report.SeverityHigh:     1,
	})

	rendered := out.String()

	if !strings.Contains(rendered, "### 10.0.0.5") {
		t.Fatalf("expected host grouping for 10.0.0.5, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "### 10.0.0.6") {
		t.Fatalf("expected host grouping for 10.0.0.6, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "| CRITICAL | vulncheck |") {
		t.Fatalf("expected finding row with source, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "| Ollama No Auth |") {
		t.Fatalf("expected finding title in row, got:\n%s", rendered)
	}
}

func TestMarkdownSeverityOrdering(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	_ = mw.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://10.0.0.5:11434",
		Title:    "Low Finding",
		Severity: report.SeverityLow,
	})
	_ = mw.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://10.0.0.5:11434",
		Title:    "Critical Finding",
		Severity: report.SeverityCritical,
	})

	_ = mw.WriteFooter(map[string]int{
		report.SeverityCritical: 1,
		report.SeverityLow:      1,
	})

	rendered := out.String()
	critIdx := strings.Index(rendered, "CRITICAL")
	lowIdx := strings.Index(rendered, "LOW")
	if critIdx > lowIdx {
		t.Fatalf("expected critical before low in output")
	}
}

func TestMarkdownRemediationSummary(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	_ = mw.WriteFinding(report.Finding{
		Source:      report.SourceVulnCheck,
		Target:      "http://10.0.0.5:11434",
		Title:       "No Auth",
		Severity:    report.SeverityHigh,
		Remediation: "Enable authentication",
	})
	_ = mw.WriteFinding(report.Finding{
		Source:      report.SourceVulnCheck,
		Target:      "http://10.0.0.6:11434",
		Title:       "No Auth 2",
		Severity:    report.SeverityHigh,
		Remediation: "Enable authentication",
	})

	_ = mw.WriteFooter(map[string]int{report.SeverityHigh: 2})

	rendered := out.String()
	if !strings.Contains(rendered, "## Remediation Summary") {
		t.Fatalf("expected remediation summary section")
	}
	if !strings.Contains(rendered, "Enable authentication | 2") {
		t.Fatalf("expected remediation count of 2, got:\n%s", rendered)
	}
}

func TestMarkdownSummaryTable(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	_ = mw.WriteFooter(map[string]int{
		report.SeverityCritical: 3,
		report.SeverityHigh:     5,
		report.SeverityMedium:   2,
		report.SeverityLow:      0,
		report.SeverityInfo:     1,
	})

	rendered := out.String()
	if !strings.Contains(rendered, "| Critical | 3 |") {
		t.Fatalf("expected Critical count 3, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "| **Total** | **11** |") {
		t.Fatalf("expected total 11, got:\n%s", rendered)
	}
}

func TestMarkdownWriterNoOpWriteHeader(t *testing.T) {
	mw := &MarkdownWriter{w: nopWriteCloser{&strings.Builder{}}}
	if err := mw.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader should be no-op, got %v", err)
	}
}

func TestNewMarkdownWriter(t *testing.T) {
	path := t.TempDir() + "/test.md"
	mw, err := NewMarkdownWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if mw == nil {
		t.Fatal("expected non-nil writer")
	}
	_ = mw.Close()
}

func TestMarkdownWriterCloseNonStdout(t *testing.T) {
	path := t.TempDir() + "/close.md"
	mw, err := NewMarkdownWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = mw.WriteFooter(map[string]int{})
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestMarkdownNextActionsSummary(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	_ = mw.WriteFinding(report.Finding{
		Source:   report.SourceOllama,
		Target:   "http://10.0.0.1:11434",
		Title:    "Ollama Enum",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{
			"workflow": map[string]interface{}{
				"recommendations": []interface{}{
					map[string]interface{}{"command": "aipostex ollama show --model llama3", "gated": false},
					map[string]interface{}{"command": "aipostex ollama generate", "gated": true},
				},
			},
		},
	})
	_ = mw.WriteFinding(report.Finding{
		Source:   report.SourceOllama,
		Target:   "http://10.0.0.2:11434",
		Title:    "Another Finding",
		Severity: report.SeverityMedium,
		Metadata: map[string]interface{}{
			"workflow": map[string]interface{}{
				"recommendations": []interface{}{
					map[string]interface{}{"command": "aipostex scan", "gated": false},
				},
			},
		},
	})

	_ = mw.WriteFooter(map[string]int{report.SeverityHigh: 1, report.SeverityMedium: 1})

	rendered := out.String()
	if !strings.Contains(rendered, "## Next Actions") {
		t.Fatalf("expected Next Actions section, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "aipostex ollama show --model llama3") {
		t.Fatalf("expected ungated command, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "aipostex ollama generate") {
		t.Fatalf("gated command should be excluded, got:\n%s", rendered)
	}
}

func TestMarkdownNextActionsSummaryNoWorkflow(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	_ = mw.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://10.0.0.1:8080",
		Title:    "No workflow",
		Severity: report.SeverityLow,
	})
	_ = mw.WriteFooter(map[string]int{report.SeverityLow: 1})

	rendered := out.String()
	if strings.Contains(rendered, "## Next Actions") {
		t.Fatalf("should not have Next Actions without workflow metadata, got:\n%s", rendered)
	}
}

func TestMarkdownRenderFullFinding(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	_ = mw.WriteFinding(report.Finding{
		ID:          "finding-123",
		Source:      report.SourceVulnCheck,
		Target:      "http://10.0.0.1:8080",
		Title:       "Full Finding",
		Severity:    report.SeverityCritical,
		CVSS:        9.5,
		Description: "Critical vulnerability found",
		Evidence:    "proof output here",
		Remediation: "Apply patch",
		Tags:        []string{"auth", "rce"},
		References:  []string{"https://example.com/ref"},
	})
	_ = mw.WriteFooter(map[string]int{report.SeverityCritical: 1})

	rendered := out.String()
	for _, expected := range []string{
		"`finding-123`",
		"**Description:** Critical vulnerability found",
		"**Evidence:**",
		"proof output here",
		"**References:**",
		"https://example.com/ref",
		"9.5",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected %q in markdown output, got:\n%s", expected, rendered)
		}
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	result := mdEscape("title | with pipe")
	if strings.Contains(result, "| with") && !strings.Contains(result, "\\|") {
		t.Fatalf("expected pipe to be escaped, got %s", result)
	}
}

func TestMarkdownCloseStdoutIsNoop(t *testing.T) {
	mw := &MarkdownWriter{w: nopWriteCloser{&strings.Builder{}}}
	if err := mw.Close(); err != nil {
		t.Fatalf("expected Close to succeed, got %v", err)
	}
}

func TestMarkdownNextActionsDedupesCommands(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	for i := 0; i < 3; i++ {
		_ = mw.WriteFinding(report.Finding{
			Source:   report.SourceOllama,
			Target:   "http://10.0.0.1:11434",
			Title:    "Same Finding",
			Severity: report.SeverityHigh,
			Metadata: map[string]interface{}{
				"workflow": map[string]interface{}{
					"recommendations": []interface{}{
						map[string]interface{}{"command": "aipostex same-cmd", "gated": false},
					},
				},
			},
		})
	}
	_ = mw.WriteFooter(map[string]int{report.SeverityHigh: 3})

	rendered := out.String()
	count := strings.Count(rendered, "aipostex same-cmd")
	if count != 1 {
		t.Fatalf("expected deduplicated command (1 occurrence), got %d", count)
	}
}

func TestMarkdownNextActionsSkipsBadRecTypes(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	_ = mw.WriteFinding(report.Finding{
		Source:   report.SourceOllama,
		Target:   "http://10.0.0.1:11434",
		Title:    "Bad rec type",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{
			"workflow": map[string]interface{}{
				"recommendations": []interface{}{
					"not-a-map",
					42,
				},
			},
		},
	})
	_ = mw.WriteFooter(map[string]int{report.SeverityHigh: 1})

	rendered := out.String()
	if strings.Contains(rendered, "## Next Actions") {
		t.Fatalf("expected no Next Actions for invalid rec types, got:\n%s", rendered)
	}
}

func TestMarkdownNextActionsEmptyCommand(t *testing.T) {
	var out strings.Builder
	mw := &MarkdownWriter{w: nopWriteCloser{&out}}

	_ = mw.WriteFinding(report.Finding{
		Source:   report.SourceOllama,
		Target:   "http://10.0.0.1:11434",
		Title:    "Empty command",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{
			"workflow": map[string]interface{}{
				"recommendations": []interface{}{
					map[string]interface{}{"command": "", "gated": false},
				},
			},
		},
	})
	_ = mw.WriteFooter(map[string]int{report.SeverityHigh: 1})

	rendered := out.String()
	if strings.Contains(rendered, "## Next Actions") {
		t.Fatalf("expected no Next Actions for empty command, got:\n%s", rendered)
	}
}
