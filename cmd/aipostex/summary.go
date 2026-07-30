package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/assessment"
	"github.com/professor-moody/aipostex/pkg/report"
)

var reportSummaryCmd = &cobra.Command{
	Use:   "summary [file1.json] [file2.json] ...",
	Short: "Generate an executive summary from engagement JSON files",
	Long: `Read one or more aipostex engagement JSON files and produce
a structured executive summary with risk scoring, attack surface
overview, top critical chains, and remediation priorities.`,
	Example: strings.Join([]string{
		formatCommandExample("report summary scan-results.json"),
		formatCommandExample("report summary scan.json ollama.json -o summary.json"),
	}, "\n"),
	Args: cobra.MinimumNArgs(1),
	RunE: runSummary,
}

func runSummary(_ *cobra.Command, args []string) error {
	var allFindings []report.Finding

	for _, path := range args {
		collection, err := loadFindingCollection(path)
		if err != nil {
			return err
		}
		allFindings = append(allFindings, collection.Findings...)
	}

	s := buildSummary(allFindings)
	printConsoleSummary(stderrWriter, s)

	if cfg.OutputFile != "" && cfg.OutputFile != "-" {
		data, err := json.MarshalIndent(s.toJSON(), "", "  ")
		if err != nil {
			return fmt.Errorf("serializing summary: %w", err)
		}
		if err := os.WriteFile(cfg.OutputFile, data, 0o600); err != nil {
			return fmt.Errorf("writing summary: %w", err)
		}
		infof("Summary written to %s", cfg.OutputFile)
	}

	return nil
}

type executiveSummary struct {
	TotalFindings int
	Stats         map[string]int
	RiskScore     float64
	RiskGrade     string
	Hosts         int
	Services      int
	ServiceTypes  []string
	TopChains     []chainSummary
	Remediations  []remediationPriority
	CoverageGaps  []string
}

type chainSummary struct {
	Target      string
	MaxStage    string
	MaxStrength string
	CritCount   int
	HighCount   int
	TopFinding  string
}

type remediationPriority struct {
	Text            string
	AffectedCount   int
	HighestSeverity string
	Targets         []string
}

type summaryTargetInfo struct {
	stages    map[string]bool
	strengths map[string]bool
	crits     int
	highs     int
	topTitle  string
	topSev    int
}

func buildSummary(findings []report.Finding) executiveSummary {
	stats := map[string]int{
		report.SeverityCritical: 0,
		report.SeverityHigh:     0,
		report.SeverityMedium:   0,
		report.SeverityLow:      0,
		report.SeverityInfo:     0,
	}
	for _, f := range findings {
		stats[report.NormalizeSeverity(f.Severity)]++
	}

	hosts := map[string]bool{}
	services := map[string]bool{}
	serviceTypes := map[string]bool{}
	discoveredTargets := map[string]bool{}
	vulnTargets := map[string]bool{}
	targetData := map[string]*summaryTargetInfo{}

	remMap := map[string]*remediationPriority{}

	for _, f := range findings {
		sev := report.NormalizeSeverity(f.Severity)
		host := summaryExtractHost(f)
		hosts[host] = true

		if f.Source == report.SourceFingerprint {
			if svc, ok := f.Metadata["service"].(string); ok {
				services[f.Target] = true
				serviceTypes[svc] = true
			}
			discoveredTargets[f.Target] = true
		} else if f.Source != report.SourceFileDiscovery {
			vulnTargets[f.Target] = true
		}

		td, ok := targetData[f.Target]
		if !ok {
			td = &summaryTargetInfo{stages: map[string]bool{}, strengths: map[string]bool{}}
			targetData[f.Target] = td
		}

		if stage, ok := f.Metadata["stage"].(string); ok {
			td.stages[stage] = true
		}
		if strength, ok := f.Metadata["landed"].(string); ok {
			td.strengths[strength] = true
		}
		sRank := severityRankForSummary(sev)
		if sRank < td.topSev || td.topTitle == "" {
			td.topSev = sRank
			td.topTitle = f.Title
		}
		if sev == report.SeverityCritical {
			td.crits++
		}
		if sev == report.SeverityHigh {
			td.highs++
		}

		if f.Remediation != "" {
			rp, ok := remMap[f.Remediation]
			if !ok {
				rp = &remediationPriority{Text: f.Remediation, HighestSeverity: sev}
				remMap[f.Remediation] = rp
			}
			rp.AffectedCount++
			if severityRankForSummary(sev) < severityRankForSummary(rp.HighestSeverity) {
				rp.HighestSeverity = sev
			}
			targetKey := summaryExtractHost(f)
			found := false
			for _, t := range rp.Targets {
				if t == targetKey {
					found = true
					break
				}
			}
			if !found {
				rp.Targets = append(rp.Targets, targetKey)
			}
		}
	}

	rawScore := float64(stats[report.SeverityCritical])*10 +
		float64(stats[report.SeverityHigh])*5 +
		float64(stats[report.SeverityMedium])*2 +
		float64(stats[report.SeverityLow])*0.5
	riskScore := math.Min(100, rawScore)
	riskGrade := gradeFromScore(riskScore)

	stSlice := make([]string, 0, len(serviceTypes))
	for st := range serviceTypes {
		stSlice = append(stSlice, st)
	}
	sort.Strings(stSlice)

	chains := buildTopChains(targetData, 5)

	remSlice := make([]remediationPriority, 0, len(remMap))
	for _, rp := range remMap {
		remSlice = append(remSlice, *rp)
	}
	sort.Slice(remSlice, func(i, j int) bool {
		ri := severityRankForSummary(remSlice[i].HighestSeverity)
		rj := severityRankForSummary(remSlice[j].HighestSeverity)
		if ri != rj {
			return ri < rj
		}
		return remSlice[i].AffectedCount > remSlice[j].AffectedCount
	})

	var gaps []string
	for target := range discoveredTargets {
		if !vulnTargets[target] {
			gaps = append(gaps, target)
		}
	}
	sort.Strings(gaps)

	return executiveSummary{
		TotalFindings: len(findings),
		Stats:         stats,
		RiskScore:     riskScore,
		RiskGrade:     riskGrade,
		Hosts:         len(hosts),
		Services:      len(services),
		ServiceTypes:  stSlice,
		TopChains:     chains,
		Remediations:  remSlice,
		CoverageGaps:  gaps,
	}
}

func buildTopChains(targetData map[string]*summaryTargetInfo, limit int) []chainSummary {
	stageOrder := map[string]int{"recon": 0, "access": 1, "impact": 2, "own": 3}
	strengthOrder := map[string]int{"reachable": 0, "influenced": 1, "read-confirmed": 2, "execution-confirmed": 3, "takeover-capable": 4}

	type scored struct {
		target string
		info   *summaryTargetInfo
		depth  int
		maxStr int
	}

	var items []scored
	for target, info := range targetData {
		maxStage := 0
		for s := range info.stages {
			if v, ok := stageOrder[s]; ok && v > maxStage {
				maxStage = v
			}
		}
		maxStrength := 0
		for s := range info.strengths {
			if v, ok := strengthOrder[s]; ok && v > maxStrength {
				maxStrength = v
			}
		}
		items = append(items, scored{target: target, info: info, depth: maxStage, maxStr: maxStrength})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].info.crits != items[j].info.crits {
			return items[i].info.crits > items[j].info.crits
		}
		if items[i].depth != items[j].depth {
			return items[i].depth > items[j].depth
		}
		return items[i].maxStr > items[j].maxStr
	})

	stageNames := []string{"recon", "access", "impact", "own"}
	strengthNames := []string{"reachable", "influenced", "read-confirmed", "execution-confirmed", "takeover-capable"}

	if limit > len(items) {
		limit = len(items)
	}
	chains := make([]chainSummary, 0, limit)
	for _, item := range items[:limit] {
		maxStageName := "recon"
		for _, s := range stageNames {
			if item.info.stages[s] {
				maxStageName = s
			}
		}
		maxStrName := "reachable"
		for _, s := range strengthNames {
			if item.info.strengths[s] {
				maxStrName = s
			}
		}
		chains = append(chains, chainSummary{
			Target:      item.target,
			MaxStage:    maxStageName,
			MaxStrength: maxStrName,
			CritCount:   item.info.crits,
			HighCount:   item.info.highs,
			TopFinding:  item.info.topTitle,
		})
	}
	return chains
}

func printConsoleSummary(w io.Writer, s executiveSummary) {
	fmt.Fprintf(w, "\n%s\n", consoleSectionHeader("Executive Summary"))

	gradeColor := color.New(color.FgWhite, color.BgRed, color.Bold)
	if s.RiskScore < 30 {
		gradeColor = color.New(color.FgBlack, color.BgGreen, color.Bold)
	} else if s.RiskScore < 60 {
		gradeColor = color.New(color.FgBlack, color.BgYellow, color.Bold)
	}

	fmt.Fprintf(w, "\n  Risk Score: %s  %.0f/100\n",
		gradeColor.Sprintf(" %s ", s.RiskGrade), s.RiskScore)

	fmt.Fprintf(w, "\n  %s\n", color.HiWhiteString("Attack Surface"))
	fmt.Fprintf(w, "    Hosts: %d  |  Services: %d  |  Service Types: %s\n",
		s.Hosts, s.Services, strings.Join(s.ServiceTypes, ", "))

	fmt.Fprintf(w, "\n  %s\n", color.HiWhiteString("Severity Distribution"))
	printBar(w, "CRIT", s.Stats[report.SeverityCritical], color.New(color.FgRed))
	printBar(w, "HIGH", s.Stats[report.SeverityHigh], color.New(color.FgHiRed))
	printBar(w, "MED ", s.Stats[report.SeverityMedium], color.New(color.FgYellow))
	printBar(w, "LOW ", s.Stats[report.SeverityLow], color.New(color.FgBlue))
	printBar(w, "INFO", s.Stats[report.SeverityInfo], color.New(color.FgHiBlack))

	if len(s.TopChains) > 0 {
		fmt.Fprintf(w, "\n  %s\n", color.HiWhiteString("Top Critical Chains"))
		for i, c := range s.TopChains {
			host := assessment.TargetGroupKey("", c.Target)
			fmt.Fprintf(w, "    %d. %s  (%d crit, %d high)  stage=%s  landed=%s\n",
				i+1, host, c.CritCount, c.HighCount, c.MaxStage, c.MaxStrength)
			fmt.Fprintf(w, "       %s\n", c.TopFinding)
		}
	}

	if len(s.Remediations) > 0 {
		fmt.Fprintf(w, "\n  %s\n", color.HiWhiteString("Remediation Priorities"))
		limit := len(s.Remediations)
		if limit > 10 {
			limit = 10
		}
		for i, r := range s.Remediations[:limit] {
			rem := r.Text
			if len(rem) > 80 {
				rem = rem[:77] + "..."
			}
			fmt.Fprintf(w, "    %d. [%s] %s  (%d findings, %d hosts)\n",
				i+1, strings.ToUpper(r.HighestSeverity), rem, r.AffectedCount, len(r.Targets))
		}
	}

	if len(s.CoverageGaps) > 0 {
		fmt.Fprintf(w, "\n  %s\n", color.HiWhiteString("Coverage Gaps (discovered but no vuln findings)"))
		for _, g := range s.CoverageGaps {
			fmt.Fprintf(w, "    - %s\n", g)
		}
	}

	fmt.Fprintln(w)
}

func printBar(w io.Writer, label string, count int, c *color.Color) {
	bar := strings.Repeat("█", count)
	if count > 40 {
		bar = strings.Repeat("█", 40) + "…"
	}
	fmt.Fprintf(w, "    %s %s %d\n", label, c.Sprint(bar), count)
}

func gradeFromScore(score float64) string {
	switch {
	case score >= 90:
		return "F"
	case score >= 70:
		return "D"
	case score >= 50:
		return "C"
	case score >= 30:
		return "B"
	case score >= 10:
		return "A-"
	default:
		return "A"
	}
}

func severityRankForSummary(sev string) int {
	switch sev {
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

func summaryExtractHost(f report.Finding) string {
	return assessment.TargetGroupKey(f.Source, f.Target)
}

func (s executiveSummary) toJSON() map[string]interface{} {
	chains := make([]map[string]interface{}, len(s.TopChains))
	for i, c := range s.TopChains {
		chains[i] = map[string]interface{}{
			"target":       c.Target,
			"max_stage":    c.MaxStage,
			"max_strength": c.MaxStrength,
			"critical":     c.CritCount,
			"high":         c.HighCount,
			"top_finding":  c.TopFinding,
		}
	}
	rems := make([]map[string]interface{}, len(s.Remediations))
	for i, r := range s.Remediations {
		rems[i] = map[string]interface{}{
			"text":             r.Text,
			"affected_count":   r.AffectedCount,
			"highest_severity": r.HighestSeverity,
			"targets":          r.Targets,
		}
	}
	return map[string]interface{}{
		"total_findings": s.TotalFindings,
		"stats":          s.Stats,
		"risk_score":     s.RiskScore,
		"risk_grade":     s.RiskGrade,
		"hosts":          s.Hosts,
		"services":       s.Services,
		"service_types":  s.ServiceTypes,
		"top_chains":     chains,
		"remediations":   rems,
		"coverage_gaps":  s.CoverageGaps,
	}
}
