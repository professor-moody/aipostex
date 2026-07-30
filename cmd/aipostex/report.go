package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/reportgen"
)

var (
	reportRenderFormat string
)

var reportRenderCmd = &cobra.Command{
	Use:   "render [engagement.json]",
	Short: "Generate an engagement report from findings",
	Long: `Generate a styled engagement report from an aipostex findings JSON file.
Supports HTML, Markdown, and JSON output formats.

Input is a standard aipostex engagement JSON file (output of scan targets, engagement merge, or assess network).`,
	Example: strings.Join([]string{
		formatCommandExample("report render findings.json -o report.html"),
		formatCommandExample("report render findings.json --format markdown -o report.md"),
		formatCommandExample("report render findings.json --format json"),
	}, "\n"),
	Args: cobra.ExactArgs(1),
	RunE: runReport,
}

func init() {
	reportRenderCmd.Flags().StringVar(&reportRenderFormat, "format", "html", "Report format: html, markdown, json")
}

func runReport(_ *cobra.Command, args []string) error {
	collection, err := loadFindingCollection(args[0])
	if err != nil {
		return err
	}

	r := reportgen.Generate(collection)

	var output string
	switch strings.ToLower(reportRenderFormat) {
	case "html":
		output = reportgen.RenderHTML(r)
	case "markdown", "md":
		output = reportgen.RenderMarkdown(r)
	case "json":
		jsonData, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return fmt.Errorf("serializing report: %w", err)
		}
		output = string(jsonData)
	default:
		return fmt.Errorf("unknown report format: %s (valid: html, markdown, json)", reportRenderFormat)
	}

	if cfg.OutputFile != "" && cfg.OutputFile != "-" {
		if err := os.WriteFile(cfg.OutputFile, []byte(output), 0o600); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		infof("Report written to %s (%d findings, %d targets)", cfg.OutputFile, r.TotalFindings, len(r.TargetCounts))
	} else {
		fmt.Print(output)
	}

	return nil
}
