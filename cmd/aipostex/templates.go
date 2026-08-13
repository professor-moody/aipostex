package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/pkg/vulncheck"
)

var templatesFilterTags []string

var templatesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available vulnerability templates",
	Long: `Display all loaded vulnerability templates with metadata.

Examples:
  aipostex templates list
  aipostex templates list --tags mcp
  aipostex templates list --tags bizarre-bazaar`,
	Example: strings.Join([]string{
		formatCommandExample("templates list"),
		formatCommandExample("templates list --tags mcp"),
	}, "\n"),
	RunE: runTemplates,
}

var templatesLintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Lint vulnerability templates for safety and advisory metadata",
	Long: `Lint the vulnerability templates for safety and advisory metadata.

Checks the corpus for the properties the scanner depends on: that each template
declares the metadata used for grading and reporting, and that none carries an
unsafe or mutating request in a detection-only path. Run this after adding or
editing templates.`,
	Example: formatCommandExample("templates lint"),
	RunE:    runTemplatesLint,
}

func init() {
	templatesListCmd.Flags().StringSliceVar(&templatesFilterTags, "tags", nil, "Filter by tags")
}

func runTemplates(cmd *cobra.Command, args []string) error {
	engine, err := loadTemplateEngine()
	if err != nil {
		return err
	}

	templates := engine.FilteredTemplates(templatesFilterTags, nil)

	fmt.Printf("%s %d detection template(s) loaded", color.CyanString("[*]"), len(templates))
	if len(templatesFilterTags) > 0 {
		fmt.Printf(" (filtered by tags: %s)", strings.Join(templatesFilterTags, ", "))
	}
	fmt.Println()
	fmt.Println()

	// Group by directory/category
	categories := make(map[string][]*vulncheck.Template)
	for _, t := range templates {
		cat := templateCategoryForTags(t.Info.Tags)
		categories[cat] = append(categories[cat], t)
	}

	order := []string{"mcp", "ollama", "vectordb", "jupyter", "openai-compat", "campaign", "other"}
	for _, cat := range order {
		tmpls, ok := categories[cat]
		if !ok || len(tmpls) == 0 {
			continue
		}
		sort.Slice(tmpls, func(i, j int) bool {
			return tmpls[i].ID < tmpls[j].ID
		})

		fmt.Printf("%s\n", consoleSectionHeader(fmt.Sprintf("%s (%d)", strings.ToUpper(cat), len(tmpls))))
		for _, t := range tmpls {
			sevStr := formatTemplateSeverity(t.Info.Severity)
			fmt.Printf("  %s  %s\n", sevStr, t.ID)
			fmt.Printf("       %s\n", t.Info.Name)
			if len(t.Info.Tags) > 0 {
				fmt.Printf("       %s\n", color.HiBlackString("tags: %s", strings.Join(t.Info.Tags, ", ")))
			}
			if cfg.Verbose && t.SourcePath != "" {
				fmt.Printf("       %s\n", color.HiBlackString("source: %s", t.SourcePath))
			}
			fmt.Println()
		}
	}

	categoryCounts := make(map[string]int, len(categories))
	for category, tmpls := range categories {
		categoryCounts[category] = len(tmpls)
	}
	printTemplatesSummary(stderrWriter, templatesSummary{
		TemplatesLoaded:   len(engine.Templates),
		TemplatesFiltered: len(templates),
		CategoryCounts:    categoryCounts,
	})

	return nil
}

func runTemplatesLint(cmd *cobra.Command, args []string) error {
	engine, err := loadTemplateEngine()
	if err != nil {
		return err
	}
	issues := vulncheck.LintTemplates(engine.Templates)
	errorCount := 0
	for _, issue := range issues {
		if issue.Severity == vulncheck.LintError {
			errorCount++
		}
		source := issue.SourcePath
		if source == "" {
			source = issue.TemplateID
		}
		fmt.Printf("%s [%s] %s: %s (%s)\n", strings.ToUpper(string(issue.Severity)), issue.Rule, issue.TemplateID, issue.Message, source)
	}
	if len(issues) == 0 {
		fmt.Printf("%s template lint passed (%d template(s) across all profiles; `templates list` shows the default detection subset)\n", color.CyanString("[*]"), len(engine.Templates))
		return nil
	}
	fmt.Printf("%s template lint found %d issue(s), %d error(s)\n", color.CyanString("[*]"), len(issues), errorCount)
	if errorCount > 0 {
		return fmt.Errorf("template lint failed with %d error(s)", errorCount)
	}
	return nil
}

func templateCategoryForTags(tags []string) string {
	lookup := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		lookup[strings.ToLower(strings.TrimSpace(tag))] = struct{}{}
	}
	if _, ok := lookup["mcp"]; ok {
		return "mcp"
	}
	if _, ok := lookup["ollama"]; ok {
		return "ollama"
	}
	for _, tag := range []string{"vectordb", "chromadb", "weaviate", "qdrant"} {
		if _, ok := lookup[tag]; ok {
			return "vectordb"
		}
	}
	if _, ok := lookup["jupyter"]; ok {
		return "jupyter"
	}
	for _, tag := range []string{"openai-compatible", "vllm", "litellm", "lmstudio", "localai"} {
		if _, ok := lookup[tag]; ok {
			return "openai-compat"
		}
	}
	if _, ok := lookup["adversary-emulation"]; ok {
		return "campaign"
	}
	for tag := range lookup {
		if strings.Contains(tag, "bizarre-bazaar") {
			return "campaign"
		}
	}
	return "other"
}

func formatTemplateSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return color.New(color.FgRed, color.Bold).Sprint("[crit]")
	case "high":
		return color.New(color.FgHiRed).Sprint("[high]")
	case "medium":
		return color.New(color.FgYellow).Sprint("[med] ")
	case "low":
		return color.New(color.FgBlue).Sprint("[low] ")
	case "info":
		return color.New(color.FgHiBlack).Sprint("[info]")
	default:
		return fmt.Sprintf("[%s]", sev)
	}
}
