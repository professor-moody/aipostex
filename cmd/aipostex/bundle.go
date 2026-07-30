package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/reportgen"
	"github.com/professor-moody/aipostex/pkg/report"
)

var bundleInput string

var engagementBundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Package an engagement into a self-contained zip archive",
	Long: `Read an engagement JSON file and produce a zip containing:
  report.json      -- the full engagement JSON
  report.html      -- rendered HTML report
  evidence/        -- raw evidence for findings with substantial evidence
  README.md        -- auto-generated index`,
	Example: strings.Join([]string{
		formatCommandExample("engagement bundle --input scan-results.json"),
		formatCommandExample("engagement bundle --input scan.json --output report-bundle.zip"),
	}, "\n"),
	RunE: runBundle,
}

func init() {
	engagementBundleCmd.Flags().StringVar(&bundleInput, "input", "", "Engagement JSON file (required)")
	_ = engagementBundleCmd.MarkFlagRequired("input")
}

func runBundle(_ *cobra.Command, _ []string) error {
	collection, err := loadFindingCollection(bundleInput)
	if err != nil {
		return err
	}
	data, err := collection.ToJSON()
	if err != nil {
		return fmt.Errorf("serializing input: %w", err)
	}

	safeEngagementID := sanitizeBundleName(collection.EngagementID)
	outputPath := cfg.OutputFile
	if outputPath == "" || outputPath == "-" {
		outputPath = fmt.Sprintf("bundle-%s.zip", safeEngagementID)
	}

	prefix := fmt.Sprintf("bundle-%s/", safeEngagementID)

	zipFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating zip: %w", err)
	}
	zw := zip.NewWriter(zipFile)
	// On an error path, best-effort cleanup. The success path closes both explicitly and
	// CHECKS the errors below — a failed finalize/flush is a corrupt ZIP, not a success.
	finalized := false
	defer func() {
		if !finalized {
			_ = zw.Close()
			_ = zipFile.Close()
		}
	}()

	if err := addZipFile(zw, prefix+"report.json", data); err != nil {
		return err
	}

	htmlContent, err := renderHTMLForBundle(collection)
	if err != nil {
		return fmt.Errorf("rendering HTML: %w", err)
	}
	if err := addZipFile(zw, prefix+"report.html", htmlContent); err != nil {
		return err
	}

	evidenceCount := 0
	for _, f := range collection.Findings {
		if len(f.Evidence) > 200 {
			name := f.ID
			if name == "" {
				name = fmt.Sprintf("finding-%d", evidenceCount)
			}
			safeName := strings.Map(func(r rune) rune {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
					return r
				}
				return '_'
			}, name)
			if err := addZipFile(zw, prefix+"evidence/"+safeName+".txt", []byte(f.Evidence)); err != nil {
				return err
			}
			evidenceCount++
		}
	}

	readme := generateBundleReadme(collection, evidenceCount)
	if err := addZipFile(zw, prefix+"README.md", []byte(readme)); err != nil {
		return err
	}

	// Finalize and CHECK: zw.Close() writes the central directory, zipFile.Close() flushes
	// to disk. A failure here means a truncated/corrupt archive — never report success.
	if err := zw.Close(); err != nil {
		return fmt.Errorf("finalizing zip (central directory): %w", err)
	}
	if err := zipFile.Close(); err != nil {
		return fmt.Errorf("flushing zip to disk: %w", err)
	}
	finalized = true

	infof("Bundle written to %s (%d findings, %d evidence files)",
		outputPath, len(collection.Findings), evidenceCount)
	return nil
}

func addZipFile(zw *zip.Writer, name string, data []byte) error {
	name, err := sanitizeZipEntryName(name)
	if err != nil {
		return err
	}
	header := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: time.Now().UTC(),
	}
	w, err := zw.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("creating zip entry %s: %w", filepath.Base(name), err)
	}
	_, err = w.Write(data)
	return err
}

func sanitizeBundleName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "engagement"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range raw {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	safe := strings.Trim(b.String(), "-_.")
	if safe == "" {
		return "engagement"
	}
	return safe
}

func sanitizeZipEntryName(name string) (string, error) {
	clean := path.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "." || clean == "" || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("invalid zip entry path %q", name)
	}
	for _, segment := range strings.Split(clean, "/") {
		if segment == ".." {
			return "", fmt.Errorf("invalid zip entry path %q", name)
		}
	}
	return clean, nil
}

func renderHTMLForBundle(collection report.FindingCollection) ([]byte, error) {
	return []byte(reportgen.RenderHTML(reportgen.Generate(collection))), nil
}

func generateBundleReadme(collection report.FindingCollection, evidenceCount int) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Engagement Bundle: %s\n\n", collection.EngagementID))
	b.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))

	stats := collection.Stats()
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Total Findings:** %d\n", len(collection.Findings)))
	b.WriteString(fmt.Sprintf("- **Critical:** %d\n", stats[report.SeverityCritical]))
	b.WriteString(fmt.Sprintf("- **High:** %d\n", stats[report.SeverityHigh]))
	b.WriteString(fmt.Sprintf("- **Medium:** %d\n", stats[report.SeverityMedium]))
	b.WriteString(fmt.Sprintf("- **Low:** %d\n", stats[report.SeverityLow]))
	b.WriteString(fmt.Sprintf("- **Info:** %d\n", stats[report.SeverityInfo]))
	b.WriteString(fmt.Sprintf("- **Evidence Files:** %d\n\n", evidenceCount))

	b.WriteString("## Contents\n\n")
	b.WriteString("| File | Description |\n")
	b.WriteString("|------|-------------|\n")
	b.WriteString("| `report.json` | Full engagement data (machine-readable) |\n")
	b.WriteString("| `report.html` | Rendered HTML report (human-readable) |\n")
	b.WriteString(fmt.Sprintf("| `evidence/` | %d raw evidence files for findings with >200 chars of evidence |\n", evidenceCount))
	b.WriteString("| `artifacts/` | Reserved for future artifact collection |\n\n")

	return b.String()
}
