package output

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/professor-moody/aipostex/pkg/report"
)

// PDFWriter renders findings as a PDF by generating an HTML report
// and converting it to PDF via headless Chrome.
type PDFWriter struct {
	path     string
	findings []report.Finding
}

func NewPDFWriter(path string) (*PDFWriter, error) {
	return &PDFWriter{path: path}, nil
}

func (pw *PDFWriter) WriteHeader() error { return nil }

func (pw *PDFWriter) WriteFinding(f report.Finding) error {
	pw.findings = append(pw.findings, f)
	return nil
}

func (pw *PDFWriter) WriteFooter(stats map[string]int) error {
	return pw.render(stats)
}

func (pw *PDFWriter) Close() error { return nil }

func (pw *PDFWriter) render(stats map[string]int) error {
	if pw.path == "" {
		return fmt.Errorf("PDF output requires --output <file.pdf>")
	}

	chromePath := findChrome()
	if chromePath == "" {
		return fmt.Errorf("PDF output requires Chrome or Chromium installed; use --format html as an alternative")
	}

	hw := &HTMLWriter{w: &nopWC{}}
	hw.findings = append(hw.findings, pw.findings...)

	var htmlBuf strings.Builder
	hw.w = &nopWC{w: &htmlBuf}
	if err := hw.render(stats); err != nil {
		return fmt.Errorf("rendering HTML for PDF: %w", err)
	}

	tmpHTML, err := os.CreateTemp("", "aipostex-report-*.html")
	if err != nil {
		return fmt.Errorf("creating temp HTML file: %w", err)
	}
	defer os.Remove(tmpHTML.Name())

	if _, err := tmpHTML.WriteString(htmlBuf.String()); err != nil {
		tmpHTML.Close()
		return fmt.Errorf("writing temp HTML: %w", err)
	}
	tmpHTML.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, chromePath,
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-software-rasterizer",
		"--disable-dev-shm-usage",
		"--print-to-pdf="+pw.path,
		"--print-to-pdf-no-header",
		tmpHTML.Name(),
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Chrome PDF generation failed: %w\n%s", err, string(output))
	}

	return nil
}

func findChrome() string {
	for _, name := range []string{
		"google-chrome", "google-chrome-stable", "chromium-browser",
		"chromium", "chrome",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
	} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

type nopWC struct {
	w *strings.Builder
}

func (n *nopWC) Write(p []byte) (int, error) {
	if n.w != nil {
		return n.w.Write(p)
	}
	return len(p), nil
}

func (n *nopWC) Close() error { return nil }
