package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/pkg/report"
)

var engagementMergeCmd = &cobra.Command{
	Use:   "merge [file1.json] [file2.json] ...",
	Short: "Merge multiple engagement JSON files into a single output",
	Long: `Combine findings from multiple aipostex engagement JSON files into one
unified engagement document. Duplicate findings are removed based on
stable finding identity across scans.

Useful for combining results from separate module runs into a single
scorable output.`,
	Example: strings.Join([]string{
		formatCommandExample("engagement merge ollama-results.json vectordb-results.json ray-results.json -o combined.json"),
		formatCommandExample("engagement merge results/*.json -o assessment.json"),
	}, "\n"),
	Args: cobra.MinimumNArgs(1),
	RunE: runMerge,
}

func runMerge(_ *cobra.Command, args []string) error {
	var allFindings []report.Finding
	var earliest time.Time
	for _, path := range args {
		collection, err := loadFindingCollection(path)
		if err != nil {
			return err
		}
		if !collection.StartTime.IsZero() && (earliest.IsZero() || collection.StartTime.Before(earliest)) {
			earliest = collection.StartTime
		}
		allFindings = append(allFindings, collection.Findings...)
	}

	deduped := deduplicateFindings(allFindings)

	merged := report.NewCollection()
	if !earliest.IsZero() {
		merged.StartTime = earliest
	}
	merged.Findings = deduped

	output, err := merged.ToJSON()
	if err != nil {
		return fmt.Errorf("serializing merged output: %w", err)
	}

	if cfg.OutputFile != "" && cfg.OutputFile != "-" {
		if err := os.WriteFile(cfg.OutputFile, output, 0o600); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		infof("Merged %d findings from %d file(s) into %s (deduplicated from %d)", len(deduped), len(args), cfg.OutputFile, len(allFindings))
	} else {
		fmt.Println(string(output))
	}

	return nil
}

func deduplicateFindings(findings []report.Finding) []report.Finding {
	seen := make(map[string]bool)
	var result []report.Finding

	// Newest first so the first kept row for each identity key carries the
	// latest evidence, metadata, and workflow context when runs are merged.
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Timestamp.After(findings[j].Timestamp)
	})

	for _, f := range findings {
		key := findingHash(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}
	return result
}

func findingHash(f report.Finding) string {
	tags := append([]string(nil), f.Tags...)
	sort.Strings(tags)
	references := append([]string(nil), f.References...)
	sort.Strings(references)
	// Hash only identity fields — Evidence and Metadata are excluded because
	// they contain response snippets and runtime values that vary across scans
	// for the same underlying vulnerability.
	payload := struct {
		Source      string   `json:"source"`
		TemplateID  string   `json:"template_id,omitempty"`
		Target      string   `json:"target"`
		Title       string   `json:"title"`
		Severity    string   `json:"severity"`
		CVSS        float64  `json:"cvss,omitempty"`
		Description string   `json:"description"`
		Remediation string   `json:"remediation,omitempty"`
		Tags        []string `json:"tags,omitempty"`
		References  []string `json:"references,omitempty"`
	}{
		Source:      f.Source,
		TemplateID:  f.TemplateID,
		Target:      f.Target,
		Title:       f.Title,
		Severity:    report.NormalizeSeverity(f.Severity),
		CVSS:        f.CVSS,
		Description: f.Description,
		Remediation: f.Remediation,
		Tags:        tags,
		References:  references,
	}
	serialized, _ := json.Marshal(payload)
	h := sha256.New()
	h.Write(serialized)
	return fmt.Sprintf("%x", h.Sum(nil))
}
