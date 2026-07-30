package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type fileScanSummary struct {
	PathsScanned    int
	RulesLoaded     int
	FilesConsidered int64
	FilesSkipped    int
	WalkErrors      int64
	FindingsEmitted int
	ExcludedDirHits int64
}

type templatesSummary struct {
	TemplatesLoaded   int
	TemplatesFiltered int
	CategoryCounts    map[string]int
}

type exploitSummary struct {
	Module              string
	Action              string
	ResourcesEnumerated int
	FindingsEmitted     int
	PartialFailures     int
	Mutating            bool
	WorkflowTargets     int
	GatedSuggestions    int
	WorkflowFailures    int
	WorkflowPlans       []workflowPlan
}

var englishTitleCaser = cases.Title(language.English)
var stderrWriter io.Writer = os.Stderr
var stderrWriterMu sync.Mutex

func infof(format string, args ...interface{}) {
	stderrWriterMu.Lock()
	defer stderrWriterMu.Unlock()
	fmt.Fprintf(stderrWriter, "[*] "+format+"\n", args...)
}

func warnf(format string, args ...interface{}) {
	stderrWriterMu.Lock()
	defer stderrWriterMu.Unlock()
	fmt.Fprintf(stderrWriter, "[!] "+format+"\n", args...)
}

func blockedf(format string, args ...interface{}) {
	stderrWriterMu.Lock()
	defer stderrWriterMu.Unlock()
	fmt.Fprintf(stderrWriter, "[x] "+format+"\n", args...)
}

func missingFlagError(flag, example string) error {
	return fmt.Errorf("missing --%s\nexample: %s", flag, example)
}

func invalidChoiceError(flag, value string, choices []string) error {
	sorted := append([]string(nil), choices...)
	sort.Strings(sorted)
	return fmt.Errorf("invalid --%s value %q (valid: %s)", flag, value, strings.Join(sorted, ", "))
}

// yesNo renders a boolean as a human word for framed summary lines.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func printFileScanSummary(w io.Writer, summary fileScanSummary, stats map[string]int) {
	printSummaryHeader(w, stats)
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d path(s) scanned", summary.PathsScanned),
		fmt.Sprintf("%d rule(s) loaded", summary.RulesLoaded),
		fmt.Sprintf("%d file(s) considered", summary.FilesConsidered),
		fmt.Sprintf("%d finding(s)", summary.FindingsEmitted),
	}, "  |  ")
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d skipped by exclusions", summary.ExcludedDirHits),
		fmt.Sprintf("%d skipped by errors", summary.WalkErrors),
	}, "  |  ")
}

func printTemplatesSummary(w io.Writer, summary templatesSummary) {
	fmt.Fprintf(w, "\n%s\n", consoleSectionHeader("Summary"))
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d template(s) loaded", summary.TemplatesLoaded),
		fmt.Sprintf("%d after filtering", summary.TemplatesFiltered),
	}, "  |  ")
	if len(summary.CategoryCounts) == 0 {
		return
	}

	categories := make([]string, 0, len(summary.CategoryCounts))
	for category := range summary.CategoryCounts {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	parts := make([]string, 0, len(categories))
	for _, category := range categories {
		parts = append(parts, category+"="+fmt.Sprint(summary.CategoryCounts[category]))
	}
	printPacked(w, 2, "categories:", parts, ", ")
}

func printExploitSummary(w io.Writer, summary exploitSummary, stats map[string]int) {
	printSummaryHeader(w, stats)
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d resource(s)", summary.ResourcesEnumerated),
		fmt.Sprintf("%d finding(s)", summary.FindingsEmitted),
		fmt.Sprintf("%d partial failure(s)", summary.PartialFailures),
		fmt.Sprintf("mutating: %s", yesNo(summary.Mutating)),
	}, "  |  ")
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d target(s) with follow-on guidance", summary.WorkflowTargets),
		fmt.Sprintf("%d gated action(s) suggested", summary.GatedSuggestions),
		fmt.Sprintf("%d workflow planning failure(s)", summary.WorkflowFailures),
	}, "  |  ")
}

func formatCommandExample(cmd string) string {
	return fmt.Sprintf("aipostex %s", cmd)
}

func maybeWarnJSONLForLongRunning(command string) {
	if cfg.OutputFile == "" || cfg.OutputFile == "-" || cfg.Format != "json" {
		return
	}
	infof("%s is writing to a file with --format json; jsonl is safer for long-running jobs because it streams incrementally", command)
}
