package output

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestCSVWriterWritesHeaderAndRows(t *testing.T) {
	path := t.TempDir() + "/test.csv"
	w, err := NewCSVWriter(path)
	if err != nil {
		t.Fatalf("NewCSVWriter: %v", err)
	}
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if err := w.WriteFinding(report.Finding{
		Timestamp:   time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Source:      report.SourceVulnCheck,
		TemplateID:  "tmpl-001",
		Target:      "http://10.0.0.1:8000",
		Title:       "Test Finding",
		Severity:    report.SeverityHigh,
		Description: "A test description",
		Tags:        []string{"tag1", "tag2"},
	}); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if err := w.WriteFooter(nil); err != nil {
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
	if !strings.Contains(content, "timestamp,source,template_id") {
		t.Fatalf("expected CSV header, got %q", content)
	}
	if !strings.Contains(content, "tmpl-001") {
		t.Fatalf("expected template ID in CSV, got %q", content)
	}
	if !strings.Contains(content, "tag1; tag2") {
		t.Fatalf("expected tags in CSV, got %q", content)
	}
}

func TestCSVMetaString(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]interface{}
		key  string
		want string
	}{
		{"nil map", nil, "key", ""},
		{"missing key", map[string]interface{}{"a": "b"}, "key", ""},
		{"string value", map[string]interface{}{"key": "val"}, "key", "val"},
		{"int value", map[string]interface{}{"key": 42}, "key", "42"},
		{"bool value", map[string]interface{}{"key": true}, "key", "true"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := csvMetaString(tc.m, tc.key)
			if got != tc.want {
				t.Errorf("csvMetaString(%v, %q) = %q, want %q", tc.m, tc.key, got, tc.want)
			}
		})
	}
}

func TestCSVWriterHeaderIdempotent(t *testing.T) {
	path := t.TempDir() + "/idem.csv"
	w, err := NewCSVWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("first WriteHeader: %v", err)
	}
	if err := w.WriteHeader(); err != nil {
		t.Fatalf("second WriteHeader should be no-op: %v", err)
	}
	if err := w.WriteFooter(nil); err != nil {
		t.Fatalf("WriteFooter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line (header only, not duplicated), got %d", len(lines))
	}
}

func TestCSVWriterFullPipeline(t *testing.T) {
	path := t.TempDir() + "/pipeline.csv"
	w, err := NewCSVWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteHeader(); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFinding(report.Finding{
		Source:      report.SourceVulnCheck,
		Target:      "http://10.0.0.1:8080",
		Title:       "Test",
		Severity:    report.SeverityHigh,
		Description: "desc",
		Evidence:    "ev",
		Remediation: "fix it",
		Tags:        []string{"t1"},
		References:  []string{"ref1"},
		Metadata: map[string]interface{}{
			"landed": "confirmed",
			"stage":  "impact",
			"action": "exploit",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFooter(nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	for _, expected := range []string{"confirmed", "impact", "exploit", "fix it"} {
		if !strings.Contains(content, expected) {
			t.Fatalf("expected %q in CSV output, got %q", expected, content)
		}
	}
}

func TestCSVWriterAutoWritesHeader(t *testing.T) {
	path := t.TempDir() + "/auto.csv"
	w, err := NewCSVWriter(path)
	if err != nil {
		t.Fatalf("NewCSVWriter: %v", err)
	}
	if err := w.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Title:    "Auto header",
		Severity: report.SeverityInfo,
	}); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + data), got %d", len(lines))
	}
}
