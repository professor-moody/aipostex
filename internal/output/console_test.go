package output

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

// TestMain pins a deterministic, wide framing width so the console tests assert
// against stable output regardless of the runner's terminal size ($COLUMNS). Tests
// that exercise wrapping override the width locally.
func TestMain(m *testing.M) {
	SetConsoleWidth(200)
	os.Exit(m.Run())
}

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestResolveWidthCapsAutoDetection(t *testing.T) {
	// Auto-detected widths are ceilinged so a very wide terminal doesn't stretch the
	// dividers/content edge-to-edge; narrow terminals are left as-is.
	if got := capAutoWidth(220); got != maxAutoWidth {
		t.Fatalf("capAutoWidth(220) = %d, want %d", got, maxAutoWidth)
	}
	if got := capAutoWidth(80); got != 80 {
		t.Fatalf("capAutoWidth(80) = %d, want 80 (narrow uncapped)", got)
	}

	defer SetConsoleWidth(200) // restore the TestMain pin
	var nonFile strings.Builder

	// An explicit --width overrides the cap (even above it).
	SetConsoleWidth(160)
	if got := resolveWidth(&nonFile); got != 160 {
		t.Fatalf("resolveWidth with --width 160 = %d, want 160 (override, uncapped)", got)
	}

	// The $COLUMNS auto path is capped.
	SetConsoleWidth(0)
	t.Setenv("COLUMNS", "220")
	if got := resolveWidth(&nonFile); got != maxAutoWidth {
		t.Fatalf("resolveWidth via COLUMNS=220 = %d, want %d (auto capped)", got, maxAutoWidth)
	}
}

func TestResolveWidthUncappedForTables(t *testing.T) {
	defer SetConsoleWidth(200) // restore the TestMain pin
	var nonFile strings.Builder

	// Auto ($COLUMNS) is NOT ceilinged for tables (unlike prose/dividers), so wide
	// columns like VERSION stay intact on a wide terminal.
	SetConsoleWidth(0)
	t.Setenv("COLUMNS", "220")
	if got := resolveWidthUncapped(&nonFile); got != 220 {
		t.Fatalf("resolveWidthUncapped via COLUMNS=220 = %d, want 220 (tables uncapped)", got)
	}
	if got := resolveWidth(&nonFile); got != maxAutoWidth {
		t.Fatalf("resolveWidth via COLUMNS=220 = %d, want %d (prose capped)", got, maxAutoWidth)
	}

	// An explicit --width still wins for tables.
	SetConsoleWidth(160)
	if got := resolveWidthUncapped(&nonFile); got != 160 {
		t.Fatalf("resolveWidthUncapped with --width 160 = %d, want 160", got)
	}
}

func TestNewConsoleWriterCreatesWriter(t *testing.T) {
	cw := NewConsoleWriter(false)
	if cw == nil {
		t.Fatal("expected non-nil ConsoleWriter")
	}
	if cw.verbose {
		t.Error("expected verbose=false")
	}
}

func TestNewGroupedConsoleWriterCreatesGroupedWriter(t *testing.T) {
	cw := NewGroupedConsoleWriter(false)
	if cw == nil {
		t.Fatal("expected non-nil ConsoleWriter")
	}
	if !cw.grouped {
		t.Error("expected grouped=true")
	}
	if !cw.suppressNextActions {
		t.Error("expected suppressNextActions=true")
	}
}

func TestConsoleWriterCloseReturnsNil(t *testing.T) {
	cw := newConsoleWriter(&strings.Builder{}, false, false)
	if err := cw.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
}

func TestIsInteractiveStream(t *testing.T) {
	// os.Stdin is not a terminal in test context
	if isInteractiveStream(os.Stdin) {
		t.Skip("stdin is a terminal in this environment")
	}
}

func TestConsoleWriterFormatsFingerprintAndExploitContext(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)

	_ = writer.WriteHeader()
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceFingerprint,
		Target:   "http://127.0.0.1:11434",
		Title:    "AI Service Discovered: ollama",
		Severity: report.SeverityInfo,
		Metadata: map[string]interface{}{
			"service":     "ollama",
			"host":        "127.0.0.1",
			"port":        11434,
			"match_kind":  "confirmed",
			"confidence":  "high",
			"specificity": 100,
		},
	})
	_ = writer.WriteFinding(report.Finding{
		Source:      report.SourceOllama,
		Target:      "http://127.0.0.1:11434",
		Title:       "Inference succeeded on llama3",
		Severity:    report.SeverityHigh,
		TemplateID:  "",
		Description: "Executed inference",
		Evidence:    "Hello there from the target model",
		Metadata: map[string]interface{}{
			"module":   "ollama",
			"action":   "generate",
			"provider": "ollama",
			"model":    "llama3",
			"mutating": false,
			"workflow": map[string]interface{}{
				"stage": "model",
				"recommendations": []map[string]interface{}{
					{
						"command": "aipostex ollama --target http://127.0.0.1:11434 show --model llama3",
						"gated":   false,
					},
				},
			},
		},
	})
	rendered := out.String()

	for _, expected := range []string{
		"context: service=ollama  host=127.0.0.1  port=11434  match_kind=confirmed  confidence=high  specificity=100",
		"context: module=ollama  action=generate  provider=ollama  model=llama3",
		"next: [read] aipostex ollama --target http://127.0.0.1:11434 show --model llama3",
		"evidence: Hello there from the target model",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected rendered output to contain %q, got %q", expected, rendered)
		}
	}
}

func TestConsoleWriterWrapsContextWithinFrame(t *testing.T) {
	SetConsoleWidth(60)
	defer SetConsoleWidth(200)
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceK8s,
		Target:   "https://localhost:6443",
		Title:    "Kubernetes privilege escalation",
		Severity: report.SeverityCritical,
		Metadata: map[string]interface{}{
			"module": "k8s", "action": "sa-loot", "namespace": "ml-prod",
			"escalation": true, "sa_can_write": true, "landed": "execution-confirmed",
		},
	})
	rendered := out.String()
	// Invariant 1: no rendered line exceeds the frame width.
	for _, line := range strings.Split(rendered, "\n") {
		if stringutil.VisibleWidth(line) > 60 {
			t.Fatalf("line exceeds width 60 (%d): %q", stringutil.VisibleWidth(line), line)
		}
	}
	// Invariant 2: a key=value pair is never split across lines.
	if !strings.Contains(rendered, "landed=execution-confirmed") {
		t.Fatalf("a key=value pair was split across lines:\n%s", rendered)
	}
	// Invariant 3: the context spans multiple lines at this width.
	if strings.Count(rendered, "\n") < 3 {
		t.Fatalf("expected the context to wrap onto multiple lines:\n%s", rendered)
	}
}

func TestConsoleWriterVerboseShowsExpandedDescriptionAndDedupe(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, true, false)

	_ = writer.WriteFinding(report.Finding{
		Source:      report.SourceVulnCheck,
		Target:      "http://127.0.0.1:3000",
		Title:       "MCP access",
		Severity:    report.SeverityCritical,
		TemplateID:  "mcp-auth-001",
		Description: "Longer operator-facing description of the detection",
		Evidence:    "line one\nline two",
		Metadata: map[string]interface{}{
			"dedupe_count": 2,
			"evidence": map[string]interface{}{
				"preview": "line one line two",
			},
		},
	})
	rendered := out.String()
	for _, expected := range []string{
		"template: mcp-auth-001",
		"desc: Longer operator-facing description of the detection",
		"dedupe: 2 duplicate finding(s) collapsed",
		// Verbose now prints full, multi-line evidence (the raw value), not the
		// collapsed bounded preview.
		"evidence: line one",
		"\n            line two",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected verbose output to contain %q, got %q", expected, rendered)
		}
	}
}

func TestConsoleWriterFormatsNewServiceFamilyContext(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)

	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceRay,
		Target:   "http://127.0.0.1:8265",
		Title:    "Ray job discovered: job-1",
		Severity: report.SeverityInfo,
		Metadata: map[string]interface{}{
			"module":   "ray",
			"action":   "jobs",
			"provider": "ray",
			"job_id":   "job-1",
			"endpoint": "/api/jobs/",
			"mutating": false,
		},
	})

	rendered := out.String()
	if !strings.Contains(rendered, "context: module=ray  action=jobs  provider=ray  endpoint=/api/jobs/  job_id=job-1") {
		t.Fatalf("expected ray context to render, got %q", rendered)
	}
	if strings.Contains(rendered, "mutating=false") {
		t.Fatalf("expected false mutating metadata to be suppressed in console context, got %q", rendered)
	}
}

func TestConsoleWriterShowsMCPCountsAndResourceURI(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)

	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceMCP,
		Target:   "http://127.0.0.1:3000/sse",
		Title:    "MCP endpoint enumerated",
		Severity: report.SeverityInfo,
		Metadata: map[string]interface{}{
			"module":         "mcp",
			"action":         "enum",
			"provider":       "mcp",
			"transport":      "sse",
			"tool_count":     4,
			"prompt_count":   3,
			"resource_count": 3,
		},
	})
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceMCP,
		Target:   "http://127.0.0.1:3000/sse",
		Title:    "MCP resource exposed: config",
		Severity: report.SeverityInfo,
		Metadata: map[string]interface{}{
			"module":    "mcp",
			"action":    "enum",
			"provider":  "mcp",
			"transport": "sse",
			"resource":  "file:///etc/app/config.yaml",
		},
	})

	rendered := out.String()
	for _, expected := range []string{"tool_count=4", "prompt_count=3", "resource_count=3", "resource=file:///etc/app/config.yaml"} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected rendered output to contain %q, got %q", expected, rendered)
		}
	}
}

func TestConsoleWriterPrefersConsoleEvidenceForSensitiveFindings(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)

	_ = writer.WriteFinding(report.Finding{
		Source:      report.SourceMCP,
		Target:      "/tmp/mcp.json",
		Title:       "MCP config embeds plaintext credential: OPENAI_API_KEY",
		Severity:    report.SeverityHigh,
		Description: "Sensitive value detected in config",
		Evidence:    "sk-super-secret-value",
		Metadata: map[string]interface{}{
			"module":           "mcp",
			"action":           "analyze",
			"server":           "alpha",
			"env_key":          "OPENAI_API_KEY",
			"console_evidence": "sk**************ue",
		},
	})

	rendered := out.String()
	if !strings.Contains(rendered, "evidence: sk**************ue") {
		t.Fatalf("expected redacted console evidence, got %q", rendered)
	}
	if strings.Contains(rendered, "sk-super-secret-value") {
		t.Fatalf("did not expect raw secret evidence in console output, got %q", rendered)
	}
}

func TestConsoleWriterSuppressesBannerWhenDisabled(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)
	if err := writer.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader returned error: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no banner output, got %q", out.String())
	}
}

func TestConsoleWriterReturnsWriteErrors(t *testing.T) {
	writer := newConsoleWriter(failingWriter{}, false, true)
	err := writer.WriteFinding(report.Finding{
		Source:      report.SourceVulnCheck,
		Target:      "http://127.0.0.1:3000",
		Title:       "test",
		Severity:    report.SeverityInfo,
		Description: "desc",
	})
	if err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("expected write error, got %v", err)
	}
}

func TestBoundedPreviewPreservesUTF8(t *testing.T) {
	value := stringutil.BoundedPreview("éééé", 3)
	if value != "éé…" {
		t.Fatalf("expected rune-safe truncation, got %q", value)
	}
}

func TestVulnCheckFindingExcludesWorkflowFromContext(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)

	_ = writer.WriteFinding(report.Finding{
		Source:     report.SourceVulnCheck,
		Target:     "http://127.0.0.1:11434",
		Title:      "LLMjacking Risk: No Auth",
		Severity:   report.SeverityCritical,
		TemplateID: "llmjacking-001",
		Metadata: map[string]interface{}{
			"workflow": map[string]interface{}{
				"rationale": "Long workflow description",
				"recommendations": []map[string]interface{}{
					{"command": "aipostex ollama enum", "gated": false},
				},
			},
		},
	})

	rendered := out.String()
	if strings.Contains(rendered, "context:") {
		t.Fatalf("expected no context line for vulncheck finding with only workflow metadata, got %q", rendered)
	}
	if strings.Contains(rendered, "rationale") || strings.Contains(rendered, "recommendations") {
		t.Fatalf("expected workflow map to not appear in output, got %q", rendered)
	}
}

func TestGroupedWriterSuppressesNextActions(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)
	writer.grouped = true
	writer.suppressNextActions = true

	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceOllama,
		Target:   "http://127.0.0.1:11434",
		Title:    "Ollama enum",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{
			"module": "ollama",
			"action": "enum",
			"workflow": map[string]interface{}{
				"recommendations": []map[string]interface{}{
					{"command": "aipostex ollama show --model llama3", "gated": false},
				},
			},
		},
	})

	_ = writer.WriteFooter(map[string]int{
		report.SeverityCritical: 0,
		report.SeverityHigh:     1,
		report.SeverityMedium:   0,
		report.SeverityLow:      0,
		report.SeverityInfo:     0,
	})

	rendered := out.String()
	if strings.Contains(rendered, "next:") {
		t.Fatalf("expected grouped writer to suppress next: lines, got %q", rendered)
	}
}

func TestFlatWriterShowsNextActions(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)

	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceOllama,
		Target:   "http://127.0.0.1:11434",
		Title:    "Ollama enum",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{
			"module": "ollama",
			"action": "enum",
			"workflow": map[string]interface{}{
				"recommendations": []map[string]interface{}{
					{"command": "aipostex ollama show --model llama3", "gated": false},
				},
			},
		},
	})

	rendered := out.String()
	if !strings.Contains(rendered, "next:") {
		t.Fatalf("expected flat writer to show next: lines, got %q", rendered)
	}
	if !strings.Contains(rendered, "aipostex ollama show --model llama3") {
		t.Fatalf("expected command in next: line, got %q", rendered)
	}
}

func TestConsoleWriterWriteHeaderWithBanner(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, true)
	if err := writer.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader returned error: %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "AI Infrastructure Offensive Security") {
		t.Fatalf("expected banner text, got %q", rendered)
	}
}

func TestConsoleWriterWriteHeaderBannerWriteError(t *testing.T) {
	writer := newConsoleWriter(failingWriter{}, false, true)
	err := writer.WriteHeader()
	if err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("expected write error from banner, got %v", err)
	}
}

func TestFormatSeverityAllLevels(t *testing.T) {
	tests := []struct {
		severity string
		contains string
	}{
		{report.SeverityCritical, "CRIT"},
		{report.SeverityHigh, "HIGH"},
		{report.SeverityMedium, "MED"},
		{report.SeverityLow, "LOW"},
		{report.SeverityInfo, "INFO"},
		{"unknown", "[unknown]"},
		{"", "[]"},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			result := FormatSeverity(tc.severity)
			if !strings.Contains(result, tc.contains) {
				t.Errorf("FormatSeverity(%q) = %q, expected to contain %q", tc.severity, result, tc.contains)
			}
		})
	}
}

func TestConsoleWriterWriteFindingWithTags(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://127.0.0.1:8080",
		Title:    "Tagged Finding",
		Severity: report.SeverityLow,
		Tags:     []string{"auth", "injection"},
	})
	rendered := out.String()
	if !strings.Contains(rendered, "tags: auth, injection") {
		t.Fatalf("expected tags line, got %q", rendered)
	}
}

func TestConsoleWriterFlatFooterIsNoOp(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)
	if err := writer.WriteFooter(map[string]int{report.SeverityCritical: 2, report.SeverityHigh: 3}); err != nil {
		t.Fatalf("WriteFooter returned error: %v", err)
	}
	// The severity tally + total moved into the framed Summary block (printSummaryHeader);
	// the console writer's flat footer no longer emits a rule or a Findings: line.
	if out.String() != "" {
		t.Fatalf("expected the flat footer to emit nothing, got %q", out.String())
	}
}

func TestConsoleWriterGroupedWriterRendersExploitFindings(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)
	writer.grouped = true
	writer.suppressNextActions = true

	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceFingerprint,
		Target:   "http://10.0.0.1:11434",
		Title:    "AI Service: ollama",
		Severity: report.SeverityInfo,
		Metadata: map[string]interface{}{"service": "ollama", "match_kind": "confirmed"},
	})
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceOllama,
		Target:   "http://10.0.0.1:11434",
		Title:    "Ollama unauth",
		Severity: report.SeverityCritical,
	})
	_ = writer.WriteFooter(map[string]int{
		report.SeverityCritical: 1,
		report.SeverityInfo:     1,
	})

	rendered := out.String()
	if !strings.Contains(rendered, "ollama") {
		t.Fatalf("expected service name in grouped output, got %q", rendered)
	}
	if !strings.Contains(rendered, "Ollama unauth") {
		t.Fatalf("expected finding title in grouped output, got %q", rendered)
	}
}

func TestExtractConfirmedServiceNamesEdgeCases(t *testing.T) {
	findings := []report.Finding{
		{Source: report.SourceOllama, Target: "http://host:1", Title: "not fp", Severity: report.SeverityInfo},
		{Source: report.SourceFingerprint, Target: "http://host:2", Title: "no service", Severity: report.SeverityInfo,
			Metadata: map[string]interface{}{"match_kind": "confirmed"}},
		{Source: report.SourceFingerprint, Target: "http://host:3", Title: "suspected", Severity: report.SeverityInfo,
			Metadata: map[string]interface{}{"match_kind": "suspected", "service": "ray"}},
		{Source: report.SourceFingerprint, Target: "http://host:4", Title: "confirmed", Severity: report.SeverityInfo,
			Metadata: map[string]interface{}{"match_kind": "confirmed", "service": "ollama"}},
		{Source: report.SourceFingerprint, Target: "http://host:5", Title: "confirmed dup", Severity: report.SeverityInfo,
			Metadata: map[string]interface{}{"match_kind": "confirmed", "service": "ollama"}},
		{Source: report.SourceFingerprint, Target: "http://host:6", Title: "empty kind", Severity: report.SeverityInfo,
			Metadata: map[string]interface{}{"service": "jupyter"}},
	}
	services := extractConfirmedServiceNames(findings)
	if len(services) != 2 {
		t.Fatalf("expected 2 confirmed services (jupyter, ollama), got %v", services)
	}
	if services[0] != "jupyter" || services[1] != "ollama" {
		t.Fatalf("expected [jupyter ollama], got %v", services)
	}
}

func TestWorkflowDisplayEdgeCases(t *testing.T) {
	t.Run("nil metadata", func(t *testing.T) {
		result := workflowDisplay(report.Finding{})
		if result != nil {
			t.Fatalf("expected nil for empty metadata, got %v", result)
		}
	})
	t.Run("no workflow key", func(t *testing.T) {
		result := workflowDisplay(report.Finding{Metadata: map[string]interface{}{"key": "val"}})
		if result != nil {
			t.Fatalf("expected nil for missing workflow, got %v", result)
		}
	})
	t.Run("gated recommendation is skipped", func(t *testing.T) {
		result := workflowDisplay(report.Finding{
			Metadata: map[string]interface{}{
				"workflow": map[string]interface{}{
					"recommendations": []interface{}{
						map[string]interface{}{"command": "aipostex do-thing", "gated": true},
					},
				},
			},
		})
		if len(result) != 1 || !strings.Contains(result[0], "[gated]") {
			t.Fatalf("expected gated label, got %v", result)
		}
	})
	t.Run("empty command is skipped", func(t *testing.T) {
		result := workflowDisplay(report.Finding{
			Metadata: map[string]interface{}{
				"workflow": map[string]interface{}{
					"recommendations": []interface{}{
						map[string]interface{}{"command": "", "gated": false},
						map[string]interface{}{"command": "aipostex scan", "gated": false},
					},
				},
			},
		})
		if len(result) != 1 || !strings.Contains(result[0], "aipostex scan") {
			t.Fatalf("expected 1 result (non-empty), got %v", result)
		}
	})
	t.Run("empty recommendations list", func(t *testing.T) {
		result := workflowDisplay(report.Finding{
			Metadata: map[string]interface{}{
				"workflow": map[string]interface{}{
					"recommendations": []interface{}{},
				},
			},
		})
		if result != nil {
			t.Fatalf("expected nil for empty recommendations, got %v", result)
		}
	})
}

func TestEvidenceForDisplayPreference(t *testing.T) {
	t.Run("uses evidence preview from metadata", func(t *testing.T) {
		f := report.Finding{
			Evidence: "raw evidence",
			Metadata: map[string]interface{}{
				"evidence": map[string]interface{}{
					"preview": "trimmed preview",
				},
			},
		}
		got := evidenceForDisplay(f)
		if got != "trimmed preview" {
			t.Fatalf("expected 'trimmed preview', got %q", got)
		}
	})
	t.Run("empty preview falls through to console_evidence", func(t *testing.T) {
		f := report.Finding{
			Evidence: "raw",
			Metadata: map[string]interface{}{
				"evidence": map[string]interface{}{
					"preview": "   ",
				},
				"console_evidence": "redacted",
			},
		}
		got := evidenceForDisplay(f)
		if got != "redacted" {
			t.Fatalf("expected 'redacted', got %q", got)
		}
	})
	t.Run("no metadata falls through to Evidence field", func(t *testing.T) {
		f := report.Finding{Evidence: "raw"}
		got := evidenceForDisplay(f)
		if got != "raw" {
			t.Fatalf("expected 'raw', got %q", got)
		}
	})
}

func TestDedupeSummary(t *testing.T) {
	t.Run("no metadata", func(t *testing.T) {
		got := dedupeSummary(report.Finding{})
		if got != "" {
			t.Fatalf("expected empty, got %q", got)
		}
	})
	t.Run("no dedupe_count key", func(t *testing.T) {
		got := dedupeSummary(report.Finding{Metadata: map[string]interface{}{"key": "val"}})
		if got != "" {
			t.Fatalf("expected empty, got %q", got)
		}
	})
	t.Run("with dedupe_count", func(t *testing.T) {
		got := dedupeSummary(report.Finding{Metadata: map[string]interface{}{"dedupe_count": 3}})
		if got != "3 duplicate finding(s) collapsed" {
			t.Fatalf("expected '3 duplicate finding(s) collapsed', got %q", got)
		}
	})
}

func TestMetadataSummaryFallback(t *testing.T) {
	f := report.Finding{
		Source: "unknown-source",
		Metadata: map[string]interface{}{
			"alpha": "a",
			"beta":  "b",
			"empty": "",
			"false": false,
			"gamma": "g",
			"delta": "d",
			"extra": "e",
		},
	}
	result := metadataSummary(f)
	if !strings.Contains(result, "alpha=a") {
		t.Fatalf("expected fallback metadata summary with sorted keys, got %q", result)
	}
	if strings.Count(result, "=") > 4 {
		t.Fatalf("expected at most 4 metadata pairs, got %q", result)
	}
	if strings.Contains(result, "empty=") || strings.Contains(result, "false=false") {
		t.Fatalf("expected empty/false fallback metadata to be suppressed, got %q", result)
	}
}

func TestWriteFindingFlatWriteErrorOnTarget(t *testing.T) {
	callCount := 0
	limitedWriter := writerFunc(func(p []byte) (int, error) {
		callCount++
		if callCount > 1 {
			return 0, errors.New("write failed")
		}
		return len(p), nil
	})
	writer := newConsoleWriter(limitedWriter, false, false)
	err := writer.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://127.0.0.1:3000",
		Title:    "test",
		Severity: report.SeverityInfo,
	})
	if err == nil {
		t.Fatal("expected write error on second write call (target line)")
	}
}

func TestWriteFindingFlatWriteErrorOnTemplate(t *testing.T) {
	callCount := 0
	limitedWriter := writerFunc(func(p []byte) (int, error) {
		callCount++
		if callCount > 2 {
			return 0, errors.New("write failed")
		}
		return len(p), nil
	})
	writer := newConsoleWriter(limitedWriter, false, false)
	err := writer.WriteFinding(report.Finding{
		Source:     report.SourceVulnCheck,
		Target:     "http://127.0.0.1:3000",
		Title:      "test",
		Severity:   report.SeverityInfo,
		TemplateID: "tmpl-001",
	})
	if err == nil {
		t.Fatal("expected write error on template line")
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestGroupedWriterShowsSuspectedFingerprintsAndWarnings(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)
	writer.grouped = true
	writer.suppressNextActions = true

	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceFingerprint,
		Target:   "http://127.0.0.1:8000",
		Title:    "AI service suspected: langserve",
		Severity: report.SeverityInfo,
		Metadata: map[string]interface{}{
			"service":          "langserve",
			"match_kind":       "suspected",
			"confidence":       "low",
			"ambiguity_reason": "generic_match_only",
		},
	})
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceFingerprint,
		Target:   "http://127.0.0.1:8000",
		Title:    "AI service suspected: hf-tgi",
		Severity: report.SeverityInfo,
		Metadata: map[string]interface{}{
			"service":      "hf-tgi",
			"match_kind":   "ambiguous",
			"confidence":   "medium",
			"proxy_likely": true,
		},
	})

	_ = writer.WriteFooter(map[string]int{
		report.SeverityInfo: 2,
	})

	rendered := out.String()
	for _, expected := range []string{"suspected: hf-tgi, langserve", "warning: port 8000: reverse proxy likely"} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected grouped output to contain %q, got %q", expected, rendered)
		}
	}
}

func TestConsoleWriterEvidenceFullPrintsMultilineUntruncated(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)

	long := "Code executed on the cluster via the Ray Job Submission API (no auth). Output returned by the job:\n{\n  \"hostname\": \"ailab-ml\",\n  \"user\": \"mluser\"\n}"
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceRay,
		Target:   "http://127.0.0.1:8265",
		Title:    "Ray cluster takeover",
		Severity: report.SeverityCritical,
		Evidence: long,
		Metadata: map[string]interface{}{
			"evidence_full": true,
			// Simulate annotateEvidenceMetadata injecting a bounded preview; the
			// full branch must bypass it and render the raw multi-line evidence.
			"evidence": map[string]interface{}{"preview": stringutil.BoundedPreview(long, 160)},
		},
	})
	rendered := out.String()
	for _, expected := range []string{"Output returned by the job:", "\"hostname\": \"ailab-ml\"", "\"user\": \"mluser\""} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected full evidence to contain %q, got %q", expected, rendered)
		}
	}
	if strings.Contains(rendered, "...") {
		t.Fatalf("expected no truncation ellipsis with evidence_full, got %q", rendered)
	}
}

// The default (non-verbose) view preserves evidence line structure but caps the number
// of lines, pointing at -v for the rest — it no longer collapses a long value into one
// mangled, mid-word-truncated run-on.
func TestConsoleWriterEvidenceLineCappedWithoutFlag(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)
	var lines []string
	for i := 0; i < previewEvidenceLineCap; i++ {
		lines = append(lines, fmt.Sprintf("shown-%d", i))
	}
	lines = append(lines, "HIDDEN-A", "HIDDEN-B", "HIDDEN-C")
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceRay,
		Target:   "http://127.0.0.1:8265",
		Title:    "x",
		Severity: report.SeverityInfo,
		Evidence: strings.Join(lines, "\n"),
	})
	rendered := out.String()
	if !strings.Contains(rendered, "…") {
		t.Fatalf("expected a line-cap ellipsis without -v, got %q", rendered)
	}
	if !strings.Contains(rendered, "3 more line") {
		t.Fatalf("expected a '3 more line(s)' footer, got %q", rendered)
	}
	if !strings.Contains(rendered, "evidence: shown-0") {
		t.Fatalf("expected the first evidence line shown, got %q", rendered)
	}
	if strings.Contains(rendered, "HIDDEN-C") {
		t.Fatalf("expected lines past the cap to be hidden, got %q", rendered)
	}
}

func TestConsoleWriterVerbosePrintsFullEvidenceForAllFindings(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, true, false) // verbose

	// No evidence_full flag; an annotate-style bounded preview is present in
	// metadata. Verbose must render the raw multi-line evidence, not the preview.
	raw := "first line of evidence\nsecond line of evidence\nthird line of evidence"
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://127.0.0.1:3000",
		Title:    "some finding",
		Severity: report.SeverityHigh,
		Evidence: raw,
		Metadata: map[string]interface{}{
			"evidence": map[string]interface{}{"preview": stringutil.BoundedPreview(raw, 160)},
		},
	})
	rendered := out.String()
	for _, expected := range []string{
		"evidence: first line of evidence",
		"\n            second line of evidence",
		"\n            third line of evidence",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected verbose full evidence to contain %q, got %q", expected, rendered)
		}
	}
}

func TestPackUnderNeverSplitsAPartAndHangs(t *testing.T) {
	SetConsoleWidth(40)
	defer SetConsoleWidth(200)
	parts := []string{"ollama=3", "litellm=1", "chromadb=2", "mlflow=1", "weaviate=4", "qdrant=2"}
	lines := PackUnder(2, "services:", parts, ", ")
	if len(lines) < 2 {
		t.Fatalf("expected the parts to wrap at width 40, got %d line(s): %v", len(lines), lines)
	}
	joined := strings.Join(lines, "\n")
	for _, p := range parts {
		if !strings.Contains(joined, p) {
			t.Fatalf("part %q was split or dropped:\n%s", p, joined)
		}
	}
	for _, ln := range lines {
		if stringutil.VisibleWidth(ln) > 40 {
			t.Fatalf("line exceeds width 40 (%d): %q", stringutil.VisibleWidth(ln), ln)
		}
	}
	if !strings.HasPrefix(lines[0], "  services: ") {
		t.Fatalf("expected labeled first line, got %q", lines[0])
	}
	gutter := len("  services: ")
	for _, ln := range lines[1:] {
		if !strings.HasPrefix(ln, strings.Repeat(" ", gutter)) {
			t.Fatalf("continuation not hang-indented to %d cols: %q", gutter, ln)
		}
	}
}

func TestWrapUnderHangIndentsLongValue(t *testing.T) {
	SetConsoleWidth(50)
	defer SetConsoleWidth(200)
	cmd := "aipostex ray --target http://127.0.0.1:8265 jobs submit --entrypoint train.py --force-exploit"
	lines := WrapUnder(4, "", cmd)
	if len(lines) < 2 {
		t.Fatalf("expected the long command to wrap at width 50, got %d line(s)", len(lines))
	}
	for _, ln := range lines {
		if stringutil.VisibleWidth(ln) > 50 {
			t.Fatalf("line exceeds width 50 (%d): %q", stringutil.VisibleWidth(ln), ln)
		}
		if !strings.HasPrefix(ln, "    ") {
			t.Fatalf("expected 4-space indent on every line, got %q", ln)
		}
	}
}

// secretFinding builds a k8s-secret-read-style finding whose credentials live in the
// structured extracted_credentials channel (the []interface{} form findings take after
// a JSON round-trip) with the same values echoed in raw Evidence.
func secretFinding() report.Finding {
	return report.Finding{
		Source:   report.SourceK8s,
		Target:   "https://localhost:6443",
		Title:    "Kubernetes secret exfiltrated: ml-prod/model-registry",
		Severity: report.SeverityCritical,
		Evidence: "Secret: ml-prod/model-registry (type=Opaque)\n" +
			"  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
			"  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n" +
			"  HF_TOKEN=hf_ABCdefGHIjklMNOpqrSTUvwxYZ0123456789",
		Metadata: map[string]interface{}{
			"module": "k8s", "action": "secret-read", "namespace": "ml-prod",
			"secret_name": "model-registry",
			"extracted_credentials": []interface{}{
				map[string]interface{}{"type": "k8s-secret", "name": "AWS_ACCESS_KEY_ID", "value": "AKIAIOSFODNN7EXAMPLE"},
				map[string]interface{}{"type": "k8s-secret", "name": "AWS_SECRET_ACCESS_KEY", "value": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"},
				map[string]interface{}{"type": "k8s-secret", "name": "HF_TOKEN", "value": "hf_ABCdefGHIjklMNOpqrSTUvwxYZ0123456789"},
			},
		},
	}
}

func TestConsoleWriterCredentialsBlockAlignedAndComplete(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, false, false)
	_ = writer.WriteFinding(secretFinding())
	rendered := out.String()

	if !strings.Contains(rendered, "creds:") {
		t.Fatalf("expected a creds: block, got %q", rendered)
	}
	// Every value is shown in full — no truncation of the payload the demo is about.
	for _, full := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
		"hf_ABCdefGHIjklMNOpqrSTUvwxYZ0123456789",
	} {
		if !strings.Contains(rendered, full) {
			t.Fatalf("expected full credential value %q in creds block, got %q", full, rendered)
		}
	}
	// The '=' separators align in a column across all rows.
	var eqCols []int
	for _, ln := range strings.Split(rendered, "\n") {
		if (strings.Contains(ln, "AWS_") || strings.Contains(ln, "HF_TOKEN")) && strings.Contains(ln, " = ") {
			eqCols = append(eqCols, strings.Index(ln, " = "))
		}
	}
	if len(eqCols) != 3 {
		t.Fatalf("expected 3 aligned credential rows, found %d in %q", len(eqCols), rendered)
	}
	for _, c := range eqCols {
		if c != eqCols[0] {
			t.Fatalf("credential '=' columns not aligned (%v):\n%s", eqCols, rendered)
		}
	}
	// The default view does not also dump the same secrets as raw evidence.
	if strings.Contains(rendered, "evidence:") {
		t.Fatalf("expected raw evidence suppressed when a creds block is shown, got %q", rendered)
	}
}

func TestConsoleWriterCredentialsAdditiveUnderVerbose(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, true, false) // verbose
	_ = writer.WriteFinding(secretFinding())
	rendered := out.String()
	// -v is additive: the creds block still shows, and the raw evidence is added on
	// top (with its provenance header), not swapped in for the block.
	if !strings.Contains(rendered, "creds:") {
		t.Fatalf("expected creds block under -v, got %q", rendered)
	}
	if !strings.Contains(rendered, "evidence:") || !strings.Contains(rendered, "Secret: ml-prod/model-registry") {
		t.Fatalf("expected full raw evidence added under -v, got %q", rendered)
	}
}

func TestFindingCredentialsAcceptsInProcessMapForm(t *testing.T) {
	f := report.Finding{
		Metadata: map[string]interface{}{
			"extracted_credentials": []map[string]interface{}{
				{"type": "wandb-run-secret", "name": "OPENAI_API_KEY", "value": "sk-live-xyz"},
				{"type": "wandb-run-secret", "value": ""}, // no value → skipped
			},
		},
	}
	creds := findingCredentials(f)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential (empty-value skipped), got %d: %+v", len(creds), creds)
	}
	if creds[0].name != "OPENAI_API_KEY" || creds[0].value != "sk-live-xyz" {
		t.Fatalf("unexpected credential parsed: %+v", creds[0])
	}
}

func TestConsoleWriterPrettyPrintsSingleLineJSONEvidence(t *testing.T) {
	raw := `{"cells":[{"cell_type":"code","source":"import os"}],"nbformat":4}`
	var out strings.Builder
	writer := newConsoleWriter(&out, true, false) // verbose → full evidence
	_ = writer.WriteFinding(report.Finding{
		Source:   report.SourceRay,
		Target:   "http://127.0.0.1:8888",
		Title:    "Notebook read",
		Severity: report.SeverityHigh,
		Evidence: raw,
	})
	rendered := out.String()
	// The single-line JSON is reflowed to structured, indented lines.
	if !strings.Contains(rendered, "nbformat") {
		t.Fatalf("expected JSON keys in the rendered evidence, got %q", rendered)
	}
	if strings.Contains(rendered, `{"cells":[{"cell_type":"code"`) {
		t.Fatalf("expected the single-line JSON run-on to be reflowed, got %q", rendered)
	}

	// maybeIndentJSON is display-only and leaves non-JSON / already-multiline untouched.
	if got := maybeIndentJSON("plain text evidence"); got != "plain text evidence" {
		t.Fatalf("expected plain text unchanged, got %q", got)
	}
	multiline := "Output:\n{\n  \"ok\": true\n}"
	if got := maybeIndentJSON(multiline); got != multiline {
		t.Fatalf("expected already-multiline evidence unchanged, got %q", got)
	}
}

func TestConsoleWriterSuppressesEvidenceThatDuplicatesCred(t *testing.T) {
	f := report.Finding{
		Source:   report.SourceJupyter,
		Target:   "http://127.0.0.1:8888",
		Title:    "Credential in notebook x: OpenAI API Key",
		Severity: report.SeverityHigh,
		Evidence: "sk-proj-FAKE-key-123",
		Metadata: map[string]interface{}{
			"extracted_credentials": []interface{}{
				map[string]interface{}{"type": "jupyter-notebook-secret", "name": "OpenAI API Key", "value": "sk-proj-FAKE-key-123"},
			},
		},
	}
	// The secret shows once (in creds:), never a second time under evidence: — in either view.
	for _, verbose := range []bool{false, true} {
		var out strings.Builder
		cw := newConsoleWriter(&out, verbose, false)
		_ = cw.WriteFinding(f)
		rendered := out.String()
		if !strings.Contains(rendered, "creds: OpenAI API Key = sk-proj-FAKE-key-123") {
			t.Fatalf("verbose=%v: expected the creds line, got %q", verbose, rendered)
		}
		if strings.Contains(rendered, "evidence:") {
			t.Fatalf("verbose=%v: evidence duplicating a cred must be suppressed, got %q", verbose, rendered)
		}
	}
}

func TestConsoleWriterDoesNotWrapCredentialValues(t *testing.T) {
	SetConsoleWidth(60)
	defer SetConsoleWidth(200)
	long := "postgresql://chatbot:Ch4tb0tPwd!@db-dev-01.acme.internal:5432/chatbot_dev"
	f := report.Finding{
		Source:   report.SourceJupyter,
		Target:   "http://127.0.0.1:8888",
		Title:    "Credential",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{
			"extracted_credentials": []interface{}{
				map[string]interface{}{"type": "pg", "name": "PostgreSQL Connection", "value": long},
			},
		},
	}
	var out strings.Builder
	cw := newConsoleWriter(&out, false, false)
	_ = cw.WriteFinding(f)
	if !strings.Contains(out.String(), "= "+long) {
		t.Fatalf("expected the full connection string intact on one line (never wrapped), got %q", out.String())
	}
}

func TestConsoleWriterSeparatesSectionsWithBlankLines(t *testing.T) {
	f := report.Finding{
		Source:   report.SourceRay,
		Target:   "http://127.0.0.1:8265",
		Title:    "x",
		Severity: report.SeverityHigh,
		Evidence: "some log line",
		Metadata: map[string]interface{}{"module": "ray", "action": "job-artifacts"},
	}
	var out strings.Builder
	cw := newConsoleWriter(&out, false, false)
	_ = cw.WriteFinding(f)
	if !strings.Contains(out.String(), "\n\n  evidence:") {
		t.Fatalf("expected a blank line separating the header from the evidence section, got %q", out.String())
	}
}

func TestConsoleWriterFullEvidenceCapped(t *testing.T) {
	var out strings.Builder
	writer := newConsoleWriter(&out, true, false) // verbose

	_ = writer.WriteFinding(report.Finding{
		ID:       "fnd-123",
		Source:   report.SourceRay,
		Target:   "http://127.0.0.1:8265",
		Title:    "huge evidence",
		Severity: report.SeverityHigh,
		Evidence: strings.Repeat("Z", fullEvidenceRuneCap+500),
	})
	rendered := out.String()
	if !strings.Contains(rendered, "evidence truncated at") {
		t.Fatalf("expected truncation hint for oversized evidence, got %q", rendered)
	}
	if !strings.Contains(rendered, "fnd-123") {
		t.Fatalf("expected truncation hint to reference the finding ID, got %q", rendered)
	}
	// The evidence content itself must be capped (wrapping adds indent/newlines,
	// so assert on the payload runes rather than total rendered length).
	if z := strings.Count(rendered, "Z"); z > fullEvidenceRuneCap {
		t.Fatalf("expected evidence payload capped at %d, got %d Z runes", fullEvidenceRuneCap, z)
	}
}

func TestGroupedWriterFoldsHostNextSteps(t *testing.T) {
	var out strings.Builder
	cw := newConsoleWriter(&out, false, false)
	cw.grouped = true
	cw.SetHostNextSteps(map[string]HostNextSteps{
		"172.16.50.20": {
			Commands: []string{
				"aipostex ray --target http://172.16.50.20:8265 jobs",
				"aipostex mlflow --target http://172.16.50.20:5000 enum",
			},
			MoreCount: 7,
		},
	})
	_ = cw.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://172.16.50.20:8265",
		Title:    "Ray Jobs API Exposed Without Authentication",
		Severity: report.SeverityCritical,
	})
	_ = cw.WriteFooter(map[string]int{report.SeverityCritical: 1})

	s := out.String()
	for _, want := range []string{
		"→ next:",
		"aipostex ray --target http://172.16.50.20:8265 jobs",
		"aipostex mlflow --target http://172.16.50.20:5000 enum",
		"+7 more (-v)",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected %q in grouped output:\n%s", want, s)
		}
	}
}

func TestGroupedWriterVerboseSkipsHostNextSteps(t *testing.T) {
	var out strings.Builder
	cw := newConsoleWriter(&out, true, false) // verbose
	cw.grouped = true
	cw.SetHostNextSteps(map[string]HostNextSteps{
		"172.16.50.20": {Commands: []string{"aipostex ray --target http://172.16.50.20:8265 jobs"}, MoreCount: 3},
	})
	_ = cw.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://172.16.50.20:8265",
		Title:    "Ray Jobs API Exposed Without Authentication",
		Severity: report.SeverityCritical,
	})
	_ = cw.WriteFooter(map[string]int{report.SeverityCritical: 1})

	if strings.Contains(out.String(), "→ next:") {
		t.Fatalf("verbose grouped output should not fold next-steps, got:\n%s", out.String())
	}
}
