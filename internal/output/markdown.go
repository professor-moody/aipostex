package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/professor-moody/aipostex/internal/assessment"
	"github.com/professor-moody/aipostex/pkg/report"
)

// MarkdownWriter writes findings as a Markdown report.
type MarkdownWriter struct {
	w        io.WriteCloser
	findings []report.Finding
}

func NewMarkdownWriter(path string) (*MarkdownWriter, error) {
	var w io.WriteCloser
	if path == "" || path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("creating markdown output file: %w", err)
		}
		w = f
	}
	return &MarkdownWriter{w: w}, nil
}

func (mw *MarkdownWriter) WriteHeader() error { return nil }

func (mw *MarkdownWriter) WriteFinding(f report.Finding) error {
	mw.findings = append(mw.findings, f)
	return nil
}

func (mw *MarkdownWriter) WriteFooter(stats map[string]int) error {
	return mw.render(stats)
}

func (mw *MarkdownWriter) Close() error {
	if mw.w != os.Stdout {
		return mw.w.Close()
	}
	return nil
}

func (mw *MarkdownWriter) render(stats map[string]int) error {
	var b strings.Builder

	b.WriteString("# aipostex Scan Report\n\n")
	b.WriteString(fmt.Sprintf("Generated %s\n\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|-------|\n")
	for _, pair := range []struct {
		label string
		key   string
	}{
		{"Critical", report.SeverityCritical},
		{"High", report.SeverityHigh},
		{"Medium", report.SeverityMedium},
		{"Low", report.SeverityLow},
		{"Info", report.SeverityInfo},
	} {
		b.WriteString(fmt.Sprintf("| %s | %d |\n", pair.label, stats[pair.key]))
	}
	total := 0
	for _, c := range stats {
		total += c
	}
	b.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", total))

	groups := mw.groupByHost()
	hosts := make([]string, 0, len(groups))
	for h := range groups {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	b.WriteString("## Findings\n\n")

	for _, host := range hosts {
		findings := groups[host]
		b.WriteString(fmt.Sprintf("### %s\n\n", host))
		b.WriteString("| # | Severity | Source | CVSS | Title | Target | Template | Tags |\n")
		b.WriteString("|---|----------|--------|------|-------|--------|----------|------|\n")

		sorted := sortBySeverity(findings)
		for i, f := range sorted {
			tags := strings.Join(f.Tags, ", ")
			cvss := ""
			if f.CVSS > 0 {
				cvss = fmt.Sprintf("%.1f", f.CVSS)
			}
			b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %s | %s | %s |\n",
				i+1,
				strings.ToUpper(report.NormalizeSeverity(f.Severity)),
				mdEscape(f.Source),
				cvss,
				mdEscape(f.Title),
				mdEscape(f.Target),
				mdEscape(f.TemplateID),
				mdEscape(tags)))
		}
		b.WriteString("\n")

		for i, f := range sorted {
			b.WriteString(fmt.Sprintf("#### %d. %s\n\n", i+1, mdEscape(f.Title)))
			if f.ID != "" {
				b.WriteString(fmt.Sprintf("**ID:** `%s`\n\n", f.ID))
			}
			if f.Description != "" {
				b.WriteString(fmt.Sprintf("**Description:** %s\n\n", mdEscape(f.Description)))
			}
			if f.Evidence != "" {
				b.WriteString("**Evidence:**\n\n```\n" + f.Evidence + "\n```\n\n")
			}
			if len(f.References) > 0 {
				b.WriteString("**References:**\n\n")
				for _, ref := range f.References {
					b.WriteString(fmt.Sprintf("- %s\n", mdEscape(ref)))
				}
				b.WriteString("\n")
			}
		}
	}

	remediations := mw.remediationSummary()
	if len(remediations) > 0 {
		b.WriteString("## Remediation Summary\n\n")
		b.WriteString("| Remediation | Affected Findings |\n")
		b.WriteString("|-------------|-------------------|\n")
		for _, r := range remediations {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", mdEscape(r.text), r.count))
		}
		b.WriteString("\n")
	}

	nextActions := mw.nextActionsSummary()
	if len(nextActions) > 0 {
		b.WriteString("## Next Actions\n\n")
		for _, na := range nextActions {
			b.WriteString(fmt.Sprintf("**%s**\n\n", na.target))
			for _, cmd := range na.commands {
				b.WriteString(fmt.Sprintf("```\n%s\n```\n\n", cmd))
			}
		}
	}

	_, err := io.WriteString(mw.w, b.String())
	return err
}

func (mw *MarkdownWriter) groupByHost() map[string][]report.Finding {
	groups := map[string][]report.Finding{}
	for _, f := range mw.findings {
		host := assessment.TargetGroupKey(f.Source, f.Target)
		groups[host] = append(groups[host], f)
	}
	return groups
}

type remediationEntry struct {
	text  string
	count int
}

func (mw *MarkdownWriter) remediationSummary() []remediationEntry {
	counts := map[string]int{}
	for _, f := range mw.findings {
		if f.Remediation != "" {
			counts[f.Remediation]++
		}
	}
	entries := make([]remediationEntry, 0, len(counts))
	for text, count := range counts {
		entries = append(entries, remediationEntry{text: text, count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].text < entries[j].text
	})
	return entries
}

type nextActionGroup struct {
	target   string
	commands []string
}

func (mw *MarkdownWriter) nextActionsSummary() []nextActionGroup {
	targetCmds := map[string][]string{}
	seen := map[string]bool{}

	for _, f := range mw.findings {
		wf, ok := f.Metadata["workflow"].(map[string]interface{})
		if !ok {
			continue
		}
		recs, ok := wf["recommendations"].([]interface{})
		if !ok {
			continue
		}
		for _, r := range recs {
			rec, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			cmd, _ := rec["command"].(string)
			gated, _ := rec["gated"].(bool)
			if cmd == "" || gated {
				continue
			}
			key := f.Target + "|" + cmd
			if seen[key] {
				continue
			}
			seen[key] = true
			targetCmds[f.Target] = append(targetCmds[f.Target], cmd)
		}
	}

	targets := make([]string, 0, len(targetCmds))
	for t := range targetCmds {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	groups := make([]nextActionGroup, 0, len(targets))
	for _, t := range targets {
		groups = append(groups, nextActionGroup{target: t, commands: targetCmds[t]})
	}
	return groups
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "*", "\\*")
	s = strings.ReplaceAll(s, "_", "\\_")
	s = strings.ReplaceAll(s, "`", "\\`")
	s = strings.ReplaceAll(s, "[", "\\[")
	s = strings.ReplaceAll(s, "]", "\\]")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
