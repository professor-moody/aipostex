package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/assessment"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	graphInput  string
	graphFormat string
)

var reportGraphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Generate a finding correlation graph from engagement data",
	Long: `Read an engagement JSON file and produce a visual attack graph
showing the recon-to-own chain per host. Outputs Mermaid
(default) or Graphviz DOT format.

The graph is most useful after merging results from multiple module
runs. With a single discover network run, most findings sit at the
discovery stage.`,
	Example: strings.Join([]string{
		formatCommandExample("report graph --input scan-results.json"),
		formatCommandExample("report graph --input merged.json --format dot -o graph.dot"),
	}, "\n"),
	RunE: runGraph,
}

func init() {
	reportGraphCmd.Flags().StringVar(&graphInput, "input", "", "Engagement JSON file (required)")
	_ = reportGraphCmd.MarkFlagRequired("input")
	reportGraphCmd.Flags().StringVar(&graphFormat, "format", "mermaid", "Output format: mermaid, dot")
}

func runGraph(_ *cobra.Command, _ []string) error {
	collection, err := loadFindingCollection(graphInput)
	if err != nil {
		return err
	}

	graph := buildGraph(collection.Findings)

	var output string
	switch graphFormat {
	case "mermaid":
		output = renderMermaid(graph)
	case "dot":
		output = renderDOT(graph)
	default:
		return fmt.Errorf("unknown --format %q (valid: mermaid, dot)", graphFormat)
	}

	if cfg.OutputFile != "" && cfg.OutputFile != "-" {
		if err := os.WriteFile(cfg.OutputFile, []byte(output), 0o600); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		infof("Graph written to %s", cfg.OutputFile)
	} else {
		fmt.Print(output)
	}

	if len(graph.hosts) > 0 {
		hasDepth := false
		for _, h := range graph.hosts {
			if len(h.stages) > 1 {
				hasDepth = true
				break
			}
		}
		if !hasDepth {
			warnf("All findings at recon stage. Run follow-on commands and merge results for a richer graph.")
		}
	}

	return nil
}

type attackGraph struct {
	hosts []*hostNode
}

type hostNode struct {
	host   string
	stages map[string]*stageNode
}

type stageNode struct {
	stage       string
	findCount   int
	maxSev      string
	topTitle    string
	targets     []string
	services    []string
	sevCounts   map[string]int
	templateIDs []string
}

func inferStage(f report.Finding) string {
	if s := report.MetadataStage(f.Metadata); s != "" {
		return report.NormalizeStage(s)
	}

	sev := report.NormalizeSeverity(f.Severity)
	switch f.Source {
	case report.SourceFingerprint, report.SourceFileDiscovery:
		return report.StageRecon
	case report.SourceVulnCheck:
		switch sev {
		case report.SeverityCritical, report.SeverityHigh:
			return report.StageImpact
		case report.SeverityMedium:
			return report.StageAccess
		default:
			return report.StageRecon
		}
	default:
		return report.StageAccess
	}
}

func stageLabel(sn *stageNode) string {
	switch sn.stage {
	case report.StageRecon:
		svcCount := len(sn.services)
		portCount := len(sn.targets)
		if svcCount > 0 {
			return fmt.Sprintf("recon: %d services on %d ports", svcCount, portCount)
		}
		return fmt.Sprintf("recon: %d findings", sn.findCount)
	case report.StageAccess:
		tmplCount := len(sn.templateIDs)
		if tmplCount > 0 {
			return fmt.Sprintf("access: %d vulns across %d templates", sn.findCount, tmplCount)
		}
		return fmt.Sprintf("access: %d findings", sn.findCount)
	case report.StageImpact:
		critHigh := sn.sevCounts[report.SeverityCritical] + sn.sevCounts[report.SeverityHigh]
		label := fmt.Sprintf("impact: %d critical/high findings", critHigh)
		if sn.topTitle != "" {
			title := sn.topTitle
			if len(title) > 45 {
				title = title[:42] + "..."
			}
			label += ", " + title
		}
		return label
	case report.StageOwn:
		label := fmt.Sprintf("own: %d findings", sn.findCount)
		if sn.topTitle != "" {
			title := sn.topTitle
			if len(title) > 45 {
				title = title[:42] + "..."
			}
			label += ", " + title
		}
		return label
	default:
		return fmt.Sprintf("%s: %d findings", sn.stage, sn.findCount)
	}
}

func buildGraph(findings []report.Finding) attackGraph {
	hostMap := map[string]*hostNode{}

	for _, f := range findings {
		host := graphExtractHost(f)
		sev := report.NormalizeSeverity(f.Severity)

		hn, ok := hostMap[host]
		if !ok {
			hn = &hostNode{host: host, stages: map[string]*stageNode{}}
			hostMap[host] = hn
		}

		stage := inferStage(f)

		sn, ok := hn.stages[stage]
		if !ok {
			sn = &stageNode{stage: stage, sevCounts: map[string]int{}}
			hn.stages[stage] = sn
		}
		sn.findCount++
		sn.sevCounts[sev]++

		if severityRankForGraph(sev) < severityRankForGraph(sn.maxSev) || sn.maxSev == "" {
			sn.maxSev = sev
			sn.topTitle = f.Title
		}

		if svc, ok := f.Metadata["service"].(string); ok && svc != "" {
			if !stringInSlice(svc, sn.services) {
				sn.services = append(sn.services, svc)
			}
		}

		if f.TemplateID != "" && !stringInSlice(f.TemplateID, sn.templateIDs) {
			sn.templateIDs = append(sn.templateIDs, f.TemplateID)
		}

		if !stringInSlice(f.Target, sn.targets) {
			sn.targets = append(sn.targets, f.Target)
		}
	}

	hosts := make([]*hostNode, 0, len(hostMap))
	for _, hn := range hostMap {
		hosts = append(hosts, hn)
	}
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].host < hosts[j].host
	})

	return attackGraph{hosts: hosts}
}

func stringInSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func renderMermaid(g attackGraph) string {
	var b strings.Builder
	b.WriteString("flowchart TD\n")

	stages := []string{"recon", "access", "impact", "own"}

	for _, hn := range g.hosts {
		safeHost := mermaidSafe(hn.host)
		b.WriteString(fmt.Sprintf("  subgraph %s [\"%s\"]\n", safeHost, hn.host))

		prevID := ""
		for _, stage := range stages {
			sn, ok := hn.stages[stage]
			if !ok {
				continue
			}
			nodeID := fmt.Sprintf("%s_%s", safeHost, stage)
			label := stageLabel(sn)

			shape := "[\"%s\"]"
			if sn.maxSev == report.SeverityCritical || sn.maxSev == report.SeverityHigh {
				shape = "[[\"%s\"]]"
			}
			b.WriteString(fmt.Sprintf("    %s", nodeID))
			b.WriteString(fmt.Sprintf(shape, label))
			b.WriteString("\n")

			if prevID != "" {
				b.WriteString(fmt.Sprintf("    %s --> %s\n", prevID, nodeID))
			}
			prevID = nodeID
		}

		b.WriteString("  end\n")
	}

	return b.String()
}

func renderDOT(g attackGraph) string {
	var b strings.Builder
	b.WriteString("digraph attack_graph {\n")
	b.WriteString("  rankdir=TB;\n")
	b.WriteString("  node [shape=box, style=filled, fontname=\"Helvetica\"];\n")
	b.WriteString("  edge [color=\"#666666\"];\n\n")

	stages := []string{"recon", "access", "impact", "own"}
	sevColors := map[string]string{
		report.SeverityCritical: "#ff7b72",
		report.SeverityHigh:     "#ffa657",
		report.SeverityMedium:   "#e3b341",
		report.SeverityLow:      "#79c0ff",
		report.SeverityInfo:     "#8b949e",
		"":                      "#c9d1d9",
	}

	for _, hn := range g.hosts {
		safeHost := dotSafe(hn.host)
		b.WriteString(fmt.Sprintf("  subgraph cluster_%s {\n", safeHost))
		b.WriteString(fmt.Sprintf("    label=\"%s\";\n", hn.host))
		b.WriteString("    style=dashed;\n")
		b.WriteString("    color=\"#58a6ff\";\n")

		prevID := ""
		for _, stage := range stages {
			sn, ok := hn.stages[stage]
			if !ok {
				continue
			}
			nodeID := fmt.Sprintf("%s_%s", safeHost, stage)
			label := dotEscape(stageLabel(sn))

			fillColor := sevColors[sn.maxSev]
			b.WriteString(fmt.Sprintf("    %s [label=\"%s\", fillcolor=\"%s\"];\n",
				nodeID, label, fillColor))

			if prevID != "" {
				b.WriteString(fmt.Sprintf("    %s -> %s;\n", prevID, nodeID))
			}
			prevID = nodeID
		}

		b.WriteString("  }\n\n")
	}

	b.WriteString("}\n")
	return b.String()
}

func graphExtractHost(f report.Finding) string {
	return assessment.TargetGroupKey(f.Source, f.Target)
}

func mermaidSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func dotSafe(s string) string {
	return mermaidSafe(s)
}

func dotEscape(s string) string {
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

func severityRankForGraph(sev string) int {
	switch report.NormalizeSeverity(sev) {
	case report.SeverityCritical:
		return 0
	case report.SeverityHigh:
		return 1
	case report.SeverityMedium:
		return 2
	case report.SeverityLow:
		return 3
	case report.SeverityInfo:
		return 4
	default:
		return 5
	}
}
