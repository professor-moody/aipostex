package output

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestPDFWriterRequiresOutputPath(t *testing.T) {
	pw, err := NewPDFWriter("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = pw.WriteFinding(report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://10.0.0.5:11434",
		Title:    "Test",
		Severity: report.SeverityHigh,
	})
	err = pw.WriteFooter(nil)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestPDFWriterRendersHTMLIntermediate(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("Chrome not available, skipping PDF render test")
	}
	if out, err := exec.Command(chrome, "--headless=new", "--disable-gpu", "--dump-dom", "about:blank").CombinedOutput(); err != nil {
		t.Skipf("Chrome present but headless mode non-functional (environment limitation): %v\n%s", err, out)
	}

	tmpFile, err := os.CreateTemp("", "test-report-*.pdf")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	pw, err := NewPDFWriter(tmpFile.Name())
	if err != nil {
		t.Fatalf("creating pdf writer: %v", err)
	}

	_ = pw.WriteFinding(report.Finding{
		Source:     report.SourceVulnCheck,
		TemplateID: "test-001",
		Target:     "http://10.0.0.5:11434",
		Title:      "Ollama No Auth",
		Severity:   report.SeverityCritical,
		Evidence:   "No authentication required",
		Tags:       []string{"ollama", "auth"},
	})
	_ = pw.WriteFinding(report.Finding{
		Source:   report.SourceFingerprint,
		Target:   "http://10.0.0.5:8888",
		Title:    "Jupyter Detected",
		Severity: report.SeverityInfo,
	})

	stats := map[string]int{
		report.SeverityCritical: 1,
		report.SeverityInfo:     1,
	}
	if err := pw.WriteFooter(stats); err != nil {
		t.Fatalf("WriteFooter: %v", err)
	}

	info, err := os.Stat(tmpFile.Name())
	if err != nil {
		t.Fatalf("stat pdf: %v", err)
	}
	if info.Size() < 1000 {
		t.Fatalf("PDF too small (%d bytes), likely not a real PDF", info.Size())
	}

	header := make([]byte, 5)
	f, _ := os.Open(tmpFile.Name())
	defer f.Close()
	if _, err := f.Read(header); err != nil {
		t.Fatalf("reading header: %v", err)
	}
	if string(header) != "%PDF-" {
		t.Fatalf("expected PDF header, got %q", string(header))
	}
}

func TestPDFWriterNoOpMethods(t *testing.T) {
	pw, _ := NewPDFWriter("/tmp/test.pdf")
	if err := pw.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader should be no-op, got %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("Close should be no-op, got %v", err)
	}
}

func TestNopWC(t *testing.T) {
	n := &nopWC{}
	written, err := n.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if written != 5 {
		t.Fatalf("expected 5 bytes written, got %d", written)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	var buf strings.Builder
	n2 := &nopWC{w: &buf}
	_, _ = n2.Write([]byte("world"))
	if buf.String() != "world" {
		t.Fatalf("expected 'world', got %q", buf.String())
	}
}

func TestFindChrome(t *testing.T) {
	result := findChrome()
	t.Logf("findChrome() = %q", result)
}
