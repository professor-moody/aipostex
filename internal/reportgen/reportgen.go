package reportgen

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

// mdBodyWidth bounds report-body prose so the generated Markdown has no runaway lines
// when read raw. Indented soft-wrapped continuation lines still render as one paragraph.
const mdBodyWidth = 100

// writeWrappedReportLine emits a finding's body block (description or remediation) under
// its bullet, word-wrapped to mdBodyWidth and indented two spaces. Only the final line
// carries the Markdown hard break ("  ") so the next block starts on its own line while
// the wrapped lines above it stay a single paragraph.
func writeWrappedReportLine(sb *strings.Builder, text, prefix string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	lines := stringutil.WrapWords(prefix+text, mdBodyWidth)
	for i, line := range lines {
		if i == len(lines)-1 {
			sb.WriteString(fmt.Sprintf("  %s  \n", line))
		} else {
			sb.WriteString(fmt.Sprintf("  %s\n", line))
		}
	}
}

// Report holds the processed engagement data for rendering.
type Report struct {
	EngagementID     string
	GeneratedAt      time.Time
	StartTime        time.Time
	EndTime          time.Time
	TotalFindings    int
	Stats            map[string]int
	SourceCounts     map[string]int
	TargetCounts     map[string]int
	ATLASCoverage    map[string]int
	FindingsByTarget map[string][]report.Finding
}

// Generate builds a Report from a FindingCollection.
func Generate(fc report.FindingCollection) Report {
	r := Report{
		EngagementID:     fc.EngagementID,
		GeneratedAt:      time.Now().UTC(),
		StartTime:        fc.StartTime,
		EndTime:          fc.EndTime,
		TotalFindings:    len(fc.Findings),
		Stats:            fc.Stats(),
		SourceCounts:     make(map[string]int),
		TargetCounts:     make(map[string]int),
		ATLASCoverage:    make(map[string]int),
		FindingsByTarget: make(map[string][]report.Finding),
	}

	for _, f := range fc.Findings {
		r.SourceCounts[f.Source]++
		r.TargetCounts[f.Target]++
		r.FindingsByTarget[f.Target] = append(r.FindingsByTarget[f.Target], f)

		// Collect unique ATLAS techniques per finding to avoid double-counting
		// when the same technique appears in both tags and references.
		techniques := make(map[string]struct{})
		for _, tag := range f.Tags {
			if strings.HasPrefix(tag, "AML.") || strings.HasPrefix(tag, "aml.") {
				techniques[strings.ToUpper(tag)] = struct{}{}
			}
		}
		for _, ref := range f.References {
			if strings.Contains(ref, "atlas.mitre.org") {
				parts := strings.Split(ref, "/")
				for _, p := range parts {
					if strings.HasPrefix(strings.ToUpper(p), "AML.") {
						techniques[strings.ToUpper(p)] = struct{}{}
					}
				}
			}
		}
		for t := range techniques {
			r.ATLASCoverage[t]++
		}
	}

	return r
}

// RenderMarkdown generates a Markdown engagement report.
func RenderMarkdown(r Report) string {
	var sb strings.Builder

	sb.WriteString("# aipostex Engagement Report\n\n")
	sb.WriteString(fmt.Sprintf("**Engagement ID:** %s  \n", r.EngagementID))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", r.GeneratedAt.Format(time.RFC3339)))
	if !r.StartTime.IsZero() {
		sb.WriteString(fmt.Sprintf("**Scan Start:** %s  \n", r.StartTime.Format(time.RFC3339)))
	}
	if !r.EndTime.IsZero() {
		sb.WriteString(fmt.Sprintf("**Scan End:** %s  \n", r.EndTime.Format(time.RFC3339)))
	}
	sb.WriteString("\n---\n\n")

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d  \n", r.TotalFindings))
	sb.WriteString(fmt.Sprintf("**Targets Assessed:** %d  \n", len(r.TargetCounts)))
	sb.WriteString(fmt.Sprintf("**Modules Used:** %d  \n\n", len(r.SourceCounts)))

	sb.WriteString("### Severity Breakdown\n\n")
	sb.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range []string{report.SeverityCritical, report.SeverityHigh, report.SeverityMedium, report.SeverityLow, report.SeverityInfo} {
		sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(sev[:1])+sev[1:], r.Stats[sev]))
	}
	sb.WriteString("\n")

	if len(r.ATLASCoverage) > 0 {
		sb.WriteString("### MITRE ATLAS Coverage\n\n")
		sb.WriteString("| Technique | Findings |\n|---|---|\n")
		techniques := sortedKeys(r.ATLASCoverage)
		for _, t := range techniques {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", t, r.ATLASCoverage[t]))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n\n## Findings by Target\n\n")
	targets := sortedKeys(r.TargetCounts)
	for _, target := range targets {
		sb.WriteString(fmt.Sprintf("### %s\n\n", target))
		for _, f := range r.FindingsByTarget[target] {
			sb.WriteString(fmt.Sprintf("- **[%s]** %s  \n", strings.ToUpper(f.Severity), f.Title))
			writeWrappedReportLine(&sb, f.Description, "")
			writeWrappedReportLine(&sb, f.Remediation, "*Remediation:* ")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// RenderHTML generates an executive-grade HTML engagement report by
// delegating to the output.HTMLWriter for a consistent, polished layout.
func RenderHTML(r Report) string {
	var buf strings.Builder
	hw := &output.HTMLWriter{}
	hw.InitForBuffer(&buf)

	hw.EngagementID = r.EngagementID
	hw.EngagementStart = r.StartTime
	hw.EngagementEnd = r.EndTime
	hw.ATLASCoverage = r.ATLASCoverage
	hw.ScanMode = extractScanMode(r)

	for _, target := range sortedKeys(r.TargetCounts) {
		for _, f := range r.FindingsByTarget[target] {
			_ = hw.WriteFinding(f)
		}
	}
	_ = hw.WriteFooter(r.Stats)
	return buf.String()
}

func extractScanMode(r Report) string {
	for _, target := range sortedKeys(r.TargetCounts) {
		for _, f := range r.FindingsByTarget[target] {
			if v, ok := f.Metadata["scan_mode"]; ok {
				if s, ok := v.(string); ok && s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
