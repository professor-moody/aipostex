package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/pkg/discover"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

var (
	scanFilePaths []string
	scanRulesDir  string
)

var discoverFilesCmd = &cobra.Command{
	Use:   "files",
	Short: "Scan file system for AI artifacts and credentials",
	Long: `Discover AI-related artifacts on compromised hosts or exfiltrated data:
  - API keys (OpenAI, Anthropic, HuggingFace, Cohere, Google, AWS, etc.)
  - MCP server configurations with embedded credentials
  - Local LLM deployments (Ollama, LM Studio, GGUF models)
  - Vector database files (ChromaDB, FAISS indexes)
  - RAG pipeline configurations with data source connections
  - Training/fine-tuning data files
  - LLMjacking indicators

Examples:
  aipostex discover files --path /home/
  aipostex discover files --path /home/ --path /opt/ -o findings.json -f json
  aipostex discover files --path /tmp/exfil/ --rules-dir ./custom-rules/`,
	Example: strings.Join([]string{
		formatCommandExample("discover files --path /tmp/exfil"),
		formatCommandExample("discover files --path /home/user --rules-dir ./custom-rules"),
	}, "\n"),
	RunE: runScanFiles,
}

func init() {
	discoverFilesCmd.Flags().StringSliceVarP(&scanFilePaths, "path", "p", nil, "Path(s) to scan (required)")
	discoverFilesCmd.Flags().StringVar(&scanRulesDir, "rules-dir", "", "Additional rules directory")
}

func runScanFiles(cmd *cobra.Command, args []string) error {
	paths := uniqueSortedStrings(append([]string{}, scanFilePaths...))
	if len(paths) == 0 {
		return missingFlagError("path", formatCommandExample("discover files --path /tmp/exfil"))
	}

	writer, err := getWriter()
	if err != nil {
		return err
	}
	defer writer.Close()

	if err := writer.WriteHeader(); err != nil {
		return err
	}
	maybeWarnJSONLForLongRunning("discover files")

	// Create scanner
	workers := cfg.Concurrency
	if cfg.Stealth {
		workers = 1
	}
	scanner := discover.NewFileScanner(workers)
	scanner.ExcludePaths = stringutil.DedupeStrings(append(scanner.ExcludePaths, cfg.ExcludePaths...))
	scanner.Context = currentContext()

	rules, err := discover.LoadEmbeddedRules()
	if err != nil {
		warnf("loading embedded rules: %v", err)
	} else {
		scanner.Rules = append(scanner.Rules, rules...)
	}

	// Load additional rules
	if scanRulesDir != "" {
		rules, err := discover.LoadRulesFromDir(scanRulesDir)
		if err != nil {
			return fmt.Errorf("loading rules from %s: %w", scanRulesDir, err)
		}
		scanner.Rules = append(scanner.Rules, rules...)
	}

	if len(scanner.Rules) == 0 {
		return fmt.Errorf("no discovery rules loaded — check rules directory")
	}

	if cfg.Verbose {
		infof("Loaded %d file discovery rules", len(scanner.Rules))
		infof("Scanning %d path(s) with %d workers", len(paths), workers)
	}

	// Run scan
	findings, scanStats, err := scanner.ScanDetailed(paths)
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	stats := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}

	// File-discovery findings are written directly here rather than through a workflow,
	// so annotate them the same way every other output path does — guaranteeing each
	// carries stage/landed (honest floor: discovery/reachable).
	findings = annotateFindingsForOutput(findings)
	for _, f := range findings {
		if err := writer.WriteFinding(f); err != nil {
			warnf("writing finding: %v", err)
		}
		stats[f.Severity]++
	}

	if err := writer.WriteFooter(stats); err != nil {
		return err
	}

	printFileScanSummary(stderrWriter, fileScanSummary{
		PathsScanned:    len(paths),
		RulesLoaded:     len(scanner.Rules),
		FilesConsidered: scanStats.FilesConsidered,
		WalkErrors:      scanStats.WalkErrors,
		ExcludedDirHits: scanStats.ExcludedDirHits,
		FindingsEmitted: len(findings),
	}, stats)
	if currentContext().Err() != nil {
		infof("Discover files interrupted")
	}

	return nil
}
