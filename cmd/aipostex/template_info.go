package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/pkg/vulncheck"
)

var templatesInfoCmd = &cobra.Command{
	Use:   "info <template-id>",
	Short: "Show detailed information for a vulnerability template",
	Long: `Show detailed metadata, source path, detection steps, and checks for one template ID.

Examples:
  aipostex templates info mcp-auth-001-unauthenticated-sse
  aipostex templates info ollama-auth-001-unauthenticated-api --templates-dir ./custom-templates`,
	Example: strings.Join([]string{
		formatCommandExample("templates info mcp-auth-001-unauthenticated-sse"),
		formatCommandExample("templates info ollama-auth-001-unauthenticated-api --templates-dir ./custom-templates"),
	}, "\n"),
	Args: cobra.ExactArgs(1),
	RunE: runTemplateInfo,
}

func runTemplateInfo(cmd *cobra.Command, args []string) error {
	engine, err := loadTemplateEngine()
	if err != nil {
		return err
	}

	tmpl, ok := findTemplateByID(engine.Templates, args[0])
	if !ok {
		return fmt.Errorf("template %q not found\nexample: %s", args[0], formatCommandExample("templates list --tags mcp"))
	}

	writeTemplateInfo(os.Stdout, tmpl)
	infof("Template info loaded from %s with %d detect step(s) and %d check(s)", tmpl.SourcePath, len(tmpl.Detect), len(tmpl.Checks))
	return nil
}

func loadTemplateEngine() (*vulncheck.Engine, error) {
	engine := vulncheck.NewEngine(cfg.Timeout, 1)
	if err := engine.LoadEmbeddedTemplates(); err != nil {
		return nil, fmt.Errorf("loading templates: %w", err)
	}

	if scanTemplDir != "" {
		if err := engine.LoadTemplates(scanTemplDir); err != nil {
			return nil, fmt.Errorf("loading templates from %s: %w", scanTemplDir, err)
		}
	}

	return engine, nil
}

func findTemplateByID(templates []*vulncheck.Template, id string) (*vulncheck.Template, bool) {
	for _, tmpl := range templates {
		if tmpl.ID == id {
			return tmpl, true
		}
	}
	return nil, false
}

func writeTemplateInfo(w io.Writer, tmpl *vulncheck.Template) {
	fmt.Fprintf(w, "ID: %s\n", tmpl.ID)
	fmt.Fprintf(w, "Name: %s\n", tmpl.Info.Name)
	fmt.Fprintf(w, "Severity: %s\n", tmpl.Info.Severity)
	if tmpl.Info.CVSS > 0 {
		fmt.Fprintf(w, "CVSS: %.1f\n", tmpl.Info.CVSS)
	}
	fmt.Fprintf(w, "Author: %s\n", tmpl.Info.Author)
	if tmpl.SourcePath != "" {
		fmt.Fprintf(w, "Source: %s\n", tmpl.SourcePath)
	}
	if len(tmpl.Info.Tags) > 0 {
		fmt.Fprintf(w, "Tags: %s\n", strings.Join(tmpl.Info.Tags, ", "))
	}
	if len(tmpl.Info.References) > 0 {
		fmt.Fprintln(w, "References:")
		for _, ref := range tmpl.Info.References {
			fmt.Fprintf(w, "  - %s\n", ref)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Description:")
	for _, line := range strings.Split(strings.TrimSpace(tmpl.Info.Description), "\n") {
		fmt.Fprintf(w, "  %s\n", strings.TrimSpace(line))
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Detect Steps: %d\n", len(tmpl.Detect))
	fmt.Fprintln(w, "Checks:")
	for _, check := range tmpl.Checks {
		severity := check.Severity
		if severity == "" {
			severity = tmpl.Info.Severity
		}
		fmt.Fprintf(w, "  - [%s] %s\n", severity, check.Name)
		fmt.Fprintf(w, "    %s %s\n", strings.ToUpper(check.Method), check.Path)
	}
}
