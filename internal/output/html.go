package output

import (
	"fmt"
	"hash/fnv"
	"html"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/professor-moody/aipostex/internal/assessment"
	"github.com/professor-moody/aipostex/pkg/report"
)

// HTMLWriter writes findings as a self-contained HTML report.
type HTMLWriter struct {
	mu       sync.Mutex
	w        io.WriteCloser
	findings []report.Finding

	// Optional engagement context (set by callers that have collection metadata).
	EngagementID    string
	EngagementStart time.Time
	EngagementEnd   time.Time

	// ScanMode indicates the scan mode used ("detect" or "full").
	ScanMode string

	// ATLASCoverage maps MITRE ATLAS technique IDs to finding counts.
	ATLASCoverage map[string]int
}

func NewHTMLWriter(path string) (*HTMLWriter, error) {
	if path == "" || path == "-" {
		return &HTMLWriter{w: os.Stdout}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("creating html output file: %w", err)
	}
	return &HTMLWriter{w: f}, nil
}

// InitForBuffer configures the writer to render into a strings.Builder
// instead of a file, useful for in-memory HTML generation (e.g. PDF, bundle).
func (hw *HTMLWriter) InitForBuffer(buf *strings.Builder) {
	hw.w = &nopStringWriteCloser{buf}
}

type nopStringWriteCloser struct{ *strings.Builder }

func (nopStringWriteCloser) Close() error { return nil }

func (hw *HTMLWriter) WriteHeader() error { return nil }

func (hw *HTMLWriter) WriteFinding(f report.Finding) error {
	hw.mu.Lock()
	hw.findings = append(hw.findings, f)
	hw.mu.Unlock()
	return nil
}

func (hw *HTMLWriter) WriteFooter(stats map[string]int) error {
	return hw.render(stats)
}

func (hw *HTMLWriter) Close() error {
	if hw.w != os.Stdout {
		return hw.w.Close()
	}
	return nil
}

func htmlHostKey(target string) string {
	slug := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, target)
	// Distinct targets can slug identically (e.g. "10.0.0.1" and "10:0:0:1"),
	// which would collide their DOM anchors and merge unrelated findings under
	// one host section. Append a short stable hash of the raw target so ids stay
	// unique while remaining deterministic for a given target.
	fh := fnv.New32a()
	_, _ = fh.Write([]byte(target))
	return fmt.Sprintf("%s-%08x", slug, fh.Sum32())
}

func htmlWorstSeverityRank(findings []report.Finding) int {
	best := 5
	for _, f := range findings {
		r := severityRank(report.NormalizeSeverity(f.Severity))
		if r < best {
			best = r
		}
	}
	return best
}

func severityLabelFromRank(r int) string {
	switch r {
	case 0:
		return "critical"
	case 1:
		return "high"
	case 2:
		return "medium"
	case 3:
		return "low"
	default:
		return "info"
	}
}

func sevCSSClass(sev string) string {
	switch report.NormalizeSeverity(sev) {
	case report.SeverityCritical:
		return "critical"
	case report.SeverityHigh:
		return "high"
	case report.SeverityMedium:
		return "medium"
	case report.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func htmlCellReferences(refs []string, e func(string) string) string {
	if len(refs) == 0 {
		return `<span class="muted">—</span>`
	}
	var b strings.Builder
	wrote := false
	b.WriteString(`<ul class="refs">`)
	for _, r := range refs {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		wrote = true
		if u, err := url.Parse(r); err == nil &&
			(strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")) &&
			u.Host != "" {
			b.WriteString(fmt.Sprintf(`<li><a href="%s" rel="noopener noreferrer" target="_blank">%s</a></li>`,
				e(r), e(r)))
		} else {
			b.WriteString(fmt.Sprintf(`<li>%s</li>`, e(r)))
		}
	}
	if !wrote {
		return `<span class="muted">—</span>`
	}
	b.WriteString(`</ul>`)
	return b.String()
}

func htmlTopFindings(findings []report.Finding, limit int) []report.Finding {
	var critHigh []report.Finding
	seen := make(map[string]bool)
	for _, f := range findings {
		severity := report.NormalizeSeverity(f.Severity)
		if severity != report.SeverityCritical && severity != report.SeverityHigh {
			continue
		}
		if seen[f.Title] {
			continue
		}
		seen[f.Title] = true
		critHigh = append(critHigh, f)
		if len(critHigh) >= limit {
			break
		}
	}
	return critHigh
}

type svcCategory struct {
	name      string
	hostCount int
}

type hostRisk struct {
	host          string
	count         int
	worstSeverity string
	topFinding    string
	exploited     int
	verified      int
}

func htmlServiceCategories(findings []report.Finding) []svcCategory {
	svcHosts := make(map[string]map[string]bool)
	for _, f := range findings {
		svc := ""
		if v, ok := f.Metadata["service"]; ok {
			if s, ok := v.(string); ok {
				svc = s
			}
		}
		if svc == "" {
			continue
		}
		cat := categorizeService(svc)
		host := assessment.TargetGroupKey(f.Source, f.Target)
		if svcHosts[cat] == nil {
			svcHosts[cat] = make(map[string]bool)
		}
		svcHosts[cat][host] = true
	}
	var cats []svcCategory
	for name, hosts := range svcHosts {
		cats = append(cats, svcCategory{name: name, hostCount: len(hosts)})
	}
	sort.Slice(cats, func(i, j int) bool {
		if cats[i].hostCount != cats[j].hostCount {
			return cats[i].hostCount > cats[j].hostCount
		}
		return cats[i].name < cats[j].name
	})
	return cats
}

func categorizeService(svc string) string {
	s := strings.ToLower(svc)
	switch {
	case s == "ollama" || s == "vllm" || s == "litellm" || s == "lmstudio" || s == "localai" || s == "openai-compatible":
		return "LLM Inference"
	case s == "chromadb" || s == "weaviate" || s == "qdrant":
		return "Vector Database"
	case s == "mlflow":
		return "Experiment Tracking"
	case s == "jupyter":
		return "Notebooks"
	case s == "mcp-sse" || s == "mcp-inspector" || s == "mcpjam-inspector" || strings.HasPrefix(s, "mcp"):
		return "MCP Server"
	case s == "gradio" || s == "streamlit":
		return "ML App Framework"
	case s == "ray":
		return "Distributed Compute"
	case s == "open-webui":
		return "AI UI"
	default:
		return cases.Title(language.English).String(s)
	}
}

func htmlRiskByHost(byHost map[string][]report.Finding, hostOrder []string) []hostRisk {
	var risks []hostRisk
	for _, h := range hostOrder {
		group := byHost[h]
		if len(group) == 0 {
			continue
		}
		sorted := sortBySeverity(append([]report.Finding(nil), group...))
		worst := report.NormalizeSeverity(sorted[0].Severity)
		topTitle := sorted[0].Title

		var ex, ver int
		for _, f := range group {
			switch proofBadgeClass(f) {
			case badgeExploited:
				ex++
			case badgeVerified:
				ver++
			}
		}
		risks = append(risks, hostRisk{host: h, count: len(group), worstSeverity: worst, topFinding: topTitle, exploited: ex, verified: ver})
	}
	return risks
}

func htmlRiskVerdict(cats []svcCategory, hostCount, critCount, highCount int, scanMode string) string {
	if critCount+highCount == 0 {
		return "This assessment did not identify critical or high severity vulnerabilities. Review medium and informational findings for hardening opportunities."
	}
	var surfaces []string
	for _, c := range cats {
		surfaces = append(surfaces, strings.ToLower(c.name))
	}
	surfaceStr := "AI infrastructure"
	if len(surfaces) > 0 {
		if len(surfaces) > 3 {
			surfaces = surfaces[:3]
		}
		surfaceStr = strings.Join(surfaces, ", ")
	}
	prefix := "This assessment identified"
	if strings.EqualFold(scanMode, "detect") {
		prefix = "This detection-only assessment identified"
	} else if strings.EqualFold(scanMode, "full") {
		prefix = "This full assessment identified and actively validated"
	}
	return fmt.Sprintf("%s %d critical and %d high severity findings across %d host(s), exposing unauthenticated access to %s endpoints that could enable model theft, data exfiltration, or remote code execution.",
		prefix, critCount, highCount, hostCount, surfaceStr)
}

func hostServices(findings []report.Finding) string {
	seen := make(map[string]bool)
	var svcs []string
	for _, f := range findings {
		if v, ok := f.Metadata["service"]; ok {
			if s, ok := v.(string); ok && s != "" && !seen[s] {
				seen[s] = true
				svcs = append(svcs, s)
			}
		}
	}
	sort.Strings(svcs)
	return strings.Join(svcs, ", ")
}

func metaStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", val)
	}
}

const (
	badgeExploited = "exploited"
	badgeVerified  = "verified"
)

func proofBadgeClass(f report.Finding) string {
	// Badge strictly by what actually LANDED — never by intent (mutating=true is an
	// attempted state change, not a successful one), source (a vulncheck detection or an
	// errored check is not "verified"), or kill-chain stage. Those describe the attempt,
	// not the outcome, and badging on them over-claims (a failed mutating request must not
	// read as EXPLOITED; an inconclusive check must not read as VERIFIED).
	switch metaStr(f.Metadata, "landed") {
	case "takeover-capable", "execution-confirmed":
		return badgeExploited
	case "read-confirmed", "influenced":
		return badgeVerified
	default:
		return ""
	}
}

func (hw *HTMLWriter) render(stats map[string]int) error {
	hw.mu.Lock()
	findings := make([]report.Finding, len(hw.findings))
	copy(findings, hw.findings)
	hw.mu.Unlock()

	e := html.EscapeString
	var b strings.Builder

	totalFindings := len(findings)
	criticalCount := stats[report.SeverityCritical]
	highCount := stats[report.SeverityHigh]
	mediumCount := stats[report.SeverityMedium]
	lowCount := stats[report.SeverityLow]
	infoCount := stats[report.SeverityInfo]
	critHigh := criticalCount + highCount

	byHost := make(map[string][]report.Finding)
	var hostOrder []string
	seenHost := make(map[string]bool)
	for _, f := range findings {
		h := assessment.TargetGroupKey(f.Source, f.Target)
		if !seenHost[h] {
			seenHost[h] = true
			hostOrder = append(hostOrder, h)
		}
		byHost[h] = append(byHost[h], f)
	}
	sort.Strings(hostOrder)
	hostCount := len(hostOrder)

	topFindings := htmlTopFindings(sortBySeverity(append([]report.Finding(nil), findings...)), 5)

	svcCategories := htmlServiceCategories(findings)
	riskByHost := htmlRiskByHost(byHost, hostOrder)

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Infrastructure Security Assessment</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.5;font-size:15px}
.page{max-width:1320px;margin:0 auto;padding:2rem 2.5rem 2rem calc(230px + 2.5rem)}

/* --- Sidebar --- */
.sidebar{position:fixed;top:0;left:0;bottom:0;width:230px;background:#161b22;border-right:1px solid #30363d;z-index:100;overflow-y:auto;padding:1.25rem 0;display:flex;flex-direction:column}
.sb-brand{color:#58a6ff;font-weight:700;font-size:1rem;padding:0 1.25rem .85rem;border-bottom:1px solid #21262d;margin-bottom:.5rem}
.sb-nav{flex:1;display:flex;flex-direction:column;gap:1px}
.sb-link{display:flex;align-items:center;gap:.5rem;color:#8b949e;text-decoration:none;font-size:.82rem;padding:.45rem 1.25rem;transition:background .15s,color .15s;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sb-link:hover{color:#c9d1d9;background:#21262d}
.sb-link.sb-active{color:#e6edf3;background:#21262d;border-left:3px solid #58a6ff;padding-left:calc(1.25rem - 3px)}
.sb-section{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#484f58;padding:.85rem 1.25rem .35rem}
.sb-dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0}
.sb-dot-critical{background:#ff7b72}
.sb-dot-high{background:#ffa657}
.sb-dot-medium{background:#e3b341}
.sb-dot-low{background:#79c0ff}
.sb-dot-info{background:#8b949e}
.sb-count{color:#484f58;font-size:.72rem;margin-left:auto}

/* --- Header --- */
.report-header{margin-bottom:2rem}
.report-header h1{font-size:1.75rem;font-weight:700;color:#e6edf3;margin-bottom:.25rem}
.report-header .subtitle{color:#8b949e;font-size:.92rem}

/* --- Engagement strip --- */
.eng-strip{display:flex;gap:2rem;flex-wrap:wrap;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:.85rem 1.25rem;margin-bottom:1.75rem;font-size:.88rem}
.eng-strip .kv{display:flex;gap:.4rem;align-items:baseline}
.eng-strip .kv-label{color:#8b949e;font-weight:500}
.eng-strip .kv-value{color:#c9d1d9;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:.82rem}

/* --- Executive summary --- */
.exec-summary{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:1.5rem 1.75rem;margin-bottom:1.75rem}
.exec-summary h2{font-size:1.05rem;font-weight:600;color:#e6edf3;margin-bottom:.85rem}
.exec-summary .risk-verdict{font-size:1rem;font-weight:600;color:#e6edf3;margin-bottom:1.25rem;line-height:1.6;border-left:4px solid #ff7b72;padding-left:1rem}
.exec-summary .risk-verdict.no-crit{border-left-color:#e3b341}

/* --- Stat cards --- */
.stat-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem;margin-bottom:1.5rem}
.stat-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:1rem;text-align:center}
.stat-card .stat-val{font-size:1.75rem;font-weight:700;color:#e6edf3;line-height:1}
.stat-card .stat-label{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:#8b949e;margin-top:.35rem}
.stat-card.stat-critical .stat-val{color:#ff7b72}
.stat-card.stat-high .stat-val{color:#ffa657}
.stat-card.stat-proven .stat-val{color:#3fb950}

/* --- Attack surface --- */
.attack-surface{margin-bottom:1.25rem}
.attack-surface h3{font-size:.85rem;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;margin-bottom:.55rem}
.svc-tags{display:flex;gap:.5rem;flex-wrap:wrap}
.svc-tag{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:.35rem .75rem;font-size:.82rem;color:#c9d1d9;display:inline-flex;align-items:center;gap:.35rem}
.svc-tag .svc-count{color:#58a6ff;font-weight:600;font-size:.72rem}

/* --- Top findings mini-cards --- */
.top-findings{margin-bottom:1.25rem}
.top-findings h3{font-size:.85rem;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;margin-bottom:.55rem}
.tf-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:.65rem 1rem;margin-bottom:.45rem;display:flex;align-items:flex-start;gap:.75rem}
.tf-card .tf-body{flex:1;min-width:0}
.tf-card .tf-title{font-weight:600;color:#e6edf3;font-size:.88rem}
.tf-card .tf-desc{color:#8b949e;font-size:.8rem;margin-top:.2rem;line-height:1.45}
.tf-card .tf-target{color:#484f58;font-size:.75rem;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;margin-top:.15rem}

/* --- Risk-by-host table --- */
.risk-host-tbl{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:.5rem}
.risk-host-tbl th{text-align:left;padding:.5rem .75rem;color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #21262d}
.risk-host-tbl td{padding:.5rem .75rem;border-bottom:1px solid #161b22;color:#c9d1d9}
.risk-host-tbl .rh-host{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;color:#e6edf3;font-weight:500}

/* --- Severity bar chart --- */
.sev-bar{display:flex;height:32px;border-radius:6px;overflow:hidden;margin-bottom:.75rem;min-width:100%}
.sev-bar .seg{display:flex;align-items:center;justify-content:center;font-size:.72rem;font-weight:700;min-width:0;transition:flex .3s}
.sev-bar .seg-critical{background:#7d1a1a;color:#ff7b72}
.sev-bar .seg-high{background:#5a2d0c;color:#ffa657}
.sev-bar .seg-medium{background:#4d3800;color:#e3b341}
.sev-bar .seg-low{background:#0c2d6b;color:#79c0ff}
.sev-bar .seg-info{background:#21262d;color:#8b949e}
.sev-legend{display:flex;gap:1.25rem;flex-wrap:wrap;margin-bottom:1.5rem}
.sev-legend .leg-item{display:flex;align-items:center;gap:.35rem;font-size:.82rem;color:#8b949e}
.sev-legend .leg-dot{width:10px;height:10px;border-radius:2px;display:inline-block}
.leg-dot-critical{background:#ff7b72}
.leg-dot-high{background:#ffa657}
.leg-dot-medium{background:#e3b341}
.leg-dot-low{background:#79c0ff}
.leg-dot-info{background:#8b949e}

/* --- Filters --- */
.filter-wrap{margin-bottom:1.5rem}
.filter-wrap>summary{cursor:pointer;font-size:.88rem;color:#58a6ff;font-weight:600;padding:.45rem 0;list-style:none}
.filter-wrap>summary::-webkit-details-marker{display:none}
.filter-wrap>summary::before{content:"\25B6  ";font-size:.65rem}
.filter-wrap[open]>summary::before{content:"\25BC  "}
.filter-bar{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:.75rem 1rem;display:flex;flex-wrap:wrap;gap:.75rem;align-items:center;margin-top:.5rem}
.filter-bar label{font-size:.82rem;color:#c9d1d9;cursor:pointer;user-select:none;display:inline-flex;align-items:center;gap:.3rem}
.filter-bar input[type="search"]{min-width:200px;flex:1;max-width:340px;padding:.45rem .65rem;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;font-size:.85rem}

/* --- Host card --- */
.host-card{background:#0d1117;border:1px solid #21262d;border-radius:10px;margin-bottom:2rem;overflow:hidden;scroll-margin-top:56px}
.host-card-header{display:flex;flex-wrap:wrap;align-items:center;gap:.65rem;padding:1rem 1.25rem;background:#161b22;border-bottom:1px solid #21262d;cursor:pointer;user-select:none}
.host-card-header h2{font-size:1.125rem;color:#e6edf3;font-weight:600}
.host-card-header .hc-meta{color:#8b949e;font-size:.82rem}
.host-card-header .sev-badge{font-size:.7rem;text-transform:uppercase;font-weight:700;padding:3px 10px;border-radius:4px}
.host-card-header .hc-services{width:100%;font-size:.78rem;color:#6e7681;margin-top:.15rem}

/* --- Findings table (exec layer) --- */
table.ft{width:100%;border-collapse:collapse;font-size:.88rem}
table.ft thead th{text-align:left;padding:.65rem .85rem;color:#8b949e;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #21262d;background:#0d1117;position:sticky;top:0;z-index:2;cursor:pointer;user-select:none}
table.ft thead th:hover{color:#c9d1d9}
table.ft tbody tr.finding-row{border-left:3px solid transparent;cursor:pointer;transition:background .15s}
table.ft tbody tr.finding-row:hover{background:#161b22}
table.ft tbody tr.sev-row-critical{border-left-color:#ff7b72}
table.ft tbody tr.sev-row-high{border-left-color:#ffa657}
table.ft tbody tr.sev-row-medium{border-left-color:#e3b341}
table.ft tbody tr.sev-row-low{border-left-color:#79c0ff}
table.ft td{padding:.6rem .85rem;border-bottom:1px solid #161b22;vertical-align:middle}
table.ft .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:.8rem;color:#8b949e}
table.ft .title-cell{font-weight:500;color:#e6edf3}
table.ft .expand-btn{color:#58a6ff;font-size:.78rem;cursor:pointer;background:none;border:none;padding:.25rem .5rem;border-radius:4px}
table.ft .expand-btn:hover{background:#21262d}

/* --- Detail row --- */
tr.detail-row{display:none}
tr.detail-row.open{display:table-row}
tr.detail-row td{padding:0;border-bottom:2px solid #21262d}
.detail-panel{padding:1.25rem 1.5rem;background:#0f1419;display:grid;grid-template-columns:1fr 1fr;gap:1rem 2rem}
.detail-panel .dp-full{grid-column:1/-1}
.detail-panel h4{font-size:.78rem;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;margin-bottom:.35rem;font-weight:600}
.detail-panel .dp-val{font-size:.88rem;color:#c9d1d9;line-height:1.55}
.dp-val a{color:#58a6ff}
.detail-panel .tags{display:flex;gap:5px;flex-wrap:wrap;margin-top:.25rem}
.detail-panel .tag{background:#21262d;color:#8b949e;padding:3px 8px;border-radius:4px;font-size:.72rem}
.remediation-callout{border-left:3px solid #ffa657;background:#1a1a10;border-radius:0 6px 6px 0;padding:.75rem 1rem;font-size:.88rem;color:#e3b341;line-height:1.5}
pre.evidence{margin:0;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:.82rem;line-height:1.6;color:#c9d1d9;background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:1rem 1.25rem;max-height:32rem;overflow:auto}

/* --- Severity badges --- */
.sev{display:inline-block;padding:3px 10px;border-radius:4px;font-weight:700;font-size:.72rem;text-transform:uppercase;white-space:nowrap}
.sev-critical{background:#7d1a1a;color:#ff7b72}
.sev-high{background:#5a2d0c;color:#ffa657}
.sev-medium{background:#4d3800;color:#e3b341}
.sev-low{background:#0c2d6b;color:#79c0ff}
.sev-info{background:#21262d;color:#8b949e}


/* --- Landed badges in table --- */
.proof-badge{display:inline-block;padding:2px 7px;border-radius:3px;font-weight:700;font-size:.62rem;text-transform:uppercase;white-space:nowrap;letter-spacing:.03em}
.badge-exploited{background:#7d1a1a;color:#ff7b72}
.badge-verified{background:#0d3320;color:#3fb950}

/* --- Collapsible sections --- */
.collapsible-heading{cursor:pointer;user-select:none}
.collapsible-heading .chevron{font-size:.7rem;margin-left:.35rem;transition:transform .2s}
.collapsible-heading .chevron.collapsed{transform:rotate(-90deg)}
.hc-chevron{font-size:.75rem;color:#8b949e;transition:transform .2s;cursor:pointer;flex-shrink:0}
.hc-chevron.collapsed{transform:rotate(-90deg)}
.hc-body.collapsed{display:none}

/* --- Expand/Collapse controls --- */
.bulk-controls{display:flex;gap:.5rem;margin-left:auto}
.bulk-controls button{background:#21262d;border:1px solid #30363d;color:#c9d1d9;font-size:.78rem;padding:.3rem .75rem;border-radius:5px;cursor:pointer;transition:background .15s}
.bulk-controls button:hover{background:#30363d;color:#e6edf3}

.muted{color:#484f58}
footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid #21262d;color:#484f58;font-size:.78rem;text-align:center}
.confidential{color:#484f58;font-size:.72rem;text-align:center;margin-top:.35rem}

/* --- Print --- */
@media print{
.no-print,.sidebar{display:none!important}
body{background:#fff;color:#111;font-size:12px}
.page{max-width:none;padding:0;margin:0}
.hc-body.collapsed{display:block!important}
.report-header h1{color:#111}
.exec-summary,.eng-strip,.host-card{border-color:#ccc;background:#fafafa}
.exec-summary h2,.host-card-header h2{color:#111}
.exec-summary li{color:#222;border-color:#e0e0e0}
.host-card-header{background:#f0f0f0;border-color:#ccc}
table.ft thead th{background:#f5f5f5;color:#333;position:static}
table.ft tbody tr{background:#fff!important}
tr.detail-row{display:table-row!important}
.detail-panel{background:#fafafa}
pre.evidence{background:#f5f5f5;border-color:#ddd;color:#222}
.remediation-callout{background:#fffde7;border-color:#f9a825;color:#6d4c00}
.sev-bar .seg,.sev,.sev-badge{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
</style>
</head>
<body>
`)

	// --- Sidebar ---
	b.WriteString(`<aside class="sidebar no-print"><div class="sb-brand">aipostex</div><nav class="sb-nav">`)
	b.WriteString(`<a href="#exec-summary" class="sb-link" data-section="exec-summary">Executive Summary</a>`)
	b.WriteString(`<div class="sb-section">Hosts</div>`)
	for _, h := range hostOrder {
		id := "host-" + htmlHostKey(h)
		wr := htmlWorstSeverityRank(byHost[h])
		worstLabel := severityLabelFromRank(wr)
		b.WriteString(fmt.Sprintf(`<a href="#%s" class="sb-link" data-section="%s"><span class="sb-dot sb-dot-%s"></span>%s<span class="sb-count">%d</span></a>`,
			id, id, e(worstLabel), e(h), len(byHost[h])))
	}
	if len(hw.ATLASCoverage) > 0 {
		b.WriteString(`<div class="sb-section">Coverage</div>`)
		b.WriteString(`<a href="#atlas-section" class="sb-link" data-section="atlas-section">MITRE ATLAS</a>`)
	}
	b.WriteString(`</nav></aside>`)

	b.WriteString(`<div class="page">`)

	// --- Header ---
	b.WriteString(`<div class="report-header">`)
	b.WriteString(`<h1>AI Infrastructure Security Assessment</h1>`)
	b.WriteString(fmt.Sprintf(`<p class="subtitle">Generated by aipostex &mdash; %s</p>`, e(time.Now().UTC().Format("2 Jan 2006, 15:04 UTC"))))
	b.WriteString(`</div>`)

	// --- Engagement strip ---
	showEngStrip := hw.EngagementID != "" || !hw.EngagementStart.IsZero() || !hw.EngagementEnd.IsZero() || hw.ScanMode != ""
	if showEngStrip {
		b.WriteString(`<div class="eng-strip">`)
		if hw.ScanMode != "" {
			modeLabel := "Detection Only"
			if strings.EqualFold(hw.ScanMode, "full") {
				modeLabel = "Full Assessment"
			}
			b.WriteString(fmt.Sprintf(`<div class="kv"><span class="kv-label">Scan Mode</span><span class="kv-value">%s</span></div>`, e(modeLabel)))
		}
		if hw.EngagementID != "" {
			b.WriteString(fmt.Sprintf(`<div class="kv"><span class="kv-label">Engagement</span><span class="kv-value">%s</span></div>`, e(hw.EngagementID)))
		}
		if !hw.EngagementStart.IsZero() {
			b.WriteString(fmt.Sprintf(`<div class="kv"><span class="kv-label">Started</span><span class="kv-value">%s</span></div>`, e(hw.EngagementStart.UTC().Format("2 Jan 2006 15:04 UTC"))))
		}
		if !hw.EngagementEnd.IsZero() {
			b.WriteString(fmt.Sprintf(`<div class="kv"><span class="kv-label">Ended</span><span class="kv-value">%s</span></div>`, e(hw.EngagementEnd.UTC().Format("2 Jan 2006 15:04 UTC"))))
		}
		b.WriteString(`</div>`)
	}

	// --- Executive summary ---
	b.WriteString(`<section class="exec-summary" id="exec-summary"><h2>Executive Summary</h2>`)

	verdict := htmlRiskVerdict(svcCategories, hostCount, criticalCount, highCount, hw.ScanMode)
	verdictClass := "risk-verdict"
	if critHigh == 0 {
		verdictClass += " no-crit"
	}
	b.WriteString(fmt.Sprintf(`<p class="%s">%s</p>`, verdictClass, verdict))

	var provenCount int
	for _, rh := range riskByHost {
		provenCount += rh.exploited + rh.verified
	}

	b.WriteString(`<div class="stat-cards">`)
	for _, sc := range []struct {
		label string
		value int
		cls   string
	}{
		{"Hosts Assessed", hostCount, ""},
		{"Total Findings", totalFindings, ""},
		{"Critical", criticalCount, "stat-critical"},
		{"High", highCount, "stat-high"},
		{"Medium", mediumCount, ""},
		{"Low / Info", lowCount + infoCount, ""},
		{"Proven", provenCount, "stat-proven"},
	} {
		cls := "stat-card"
		if sc.cls != "" {
			cls += " " + sc.cls
		}
		b.WriteString(fmt.Sprintf(`<div class="%s"><div class="stat-val">%d</div><div class="stat-label">%s</div></div>`, cls, sc.value, e(sc.label)))
	}
	b.WriteString(`</div>`)

	if len(svcCategories) > 0 {
		b.WriteString(`<div class="attack-surface"><h3>Attack Surface</h3><div class="svc-tags">`)
		for _, sc := range svcCategories {
			b.WriteString(fmt.Sprintf(`<span class="svc-tag">%s <span class="svc-count">%d host(s)</span></span>`, e(sc.name), sc.hostCount))
		}
		b.WriteString(`</div></div>`)
	}

	if len(topFindings) > 0 {
		b.WriteString(`<div class="top-findings"><h3>Top Findings Requiring Attention</h3>`)
		for _, tf := range topFindings {
			sevClass := sevCSSClass(tf.Severity)
			desc := tf.Description
			if len(desc) > 120 {
				desc = desc[:117] + "..."
			}
			b.WriteString(`<div class="tf-card">`)
			b.WriteString(fmt.Sprintf(`<span class="sev sev-%s">%s</span>`, sevClass, e(report.NormalizeSeverity(tf.Severity))))

			if bc := proofBadgeClass(tf); bc == badgeExploited {
				b.WriteString(` <span class="proof-badge badge-exploited">EXPLOITED</span>`)
			} else if bc == badgeVerified {
				b.WriteString(` <span class="proof-badge badge-verified">VERIFIED</span>`)
			}

			b.WriteString(`<div class="tf-body">`)
			b.WriteString(fmt.Sprintf(`<div class="tf-title">%s</div>`, e(tf.Title)))
			if desc != "" {
				b.WriteString(fmt.Sprintf(`<div class="tf-desc">%s</div>`, e(desc)))
			}
			b.WriteString(fmt.Sprintf(`<div class="tf-target">%s</div>`, e(tf.Target)))
			b.WriteString(`</div></div>`)
		}
		b.WriteString(`</div>`)
	}

	if len(riskByHost) > 0 {
		b.WriteString(`<table class="risk-host-tbl"><thead><tr><th>Host</th><th>Findings</th><th>Worst Severity</th><th>Exploited</th><th>Verified</th><th>Top Finding</th></tr></thead><tbody>`)
		for _, rh := range riskByHost {
			sevClass := sevCSSClass(rh.worstSeverity)
			b.WriteString(fmt.Sprintf(`<tr><td class="rh-host">%s</td><td>%d</td><td><span class="sev sev-%s">%s</span></td><td>%d</td><td>%d</td><td>%s</td></tr>`,
				e(rh.host), rh.count, sevClass, e(rh.worstSeverity), rh.exploited, rh.verified, e(rh.topFinding)))
		}
		b.WriteString(`</tbody></table>`)
	}

	b.WriteString(`</section>`)

	// --- Severity bar chart ---
	if totalFindings > 0 {
		b.WriteString(`<div class="sev-bar">`)
		for _, seg := range []struct {
			cls   string
			count int
		}{
			{"critical", criticalCount},
			{"high", highCount},
			{"medium", mediumCount},
			{"low", lowCount},
			{"info", infoCount},
		} {
			if seg.count > 0 {
				pct := float64(seg.count) / float64(totalFindings) * 100
				label := ""
				if pct >= 8 {
					label = fmt.Sprintf("%d", seg.count)
				}
				b.WriteString(fmt.Sprintf(`<div class="seg seg-%s" style="flex:%d" title="%d %s">%s</div>`, seg.cls, seg.count, seg.count, seg.cls, label))
			}
		}
		b.WriteString(`</div><div class="sev-legend">`)
		for _, seg := range []struct {
			cls   string
			label string
			count int
		}{
			{"critical", "Critical", criticalCount},
			{"high", "High", highCount},
			{"medium", "Medium", mediumCount},
			{"low", "Low", lowCount},
			{"info", "Info", infoCount},
		} {
			b.WriteString(fmt.Sprintf(`<div class="leg-item"><span class="leg-dot leg-dot-%s"></span>%s: %d</div>`, seg.cls, seg.label, seg.count))
		}
		b.WriteString(`</div>`)
	}

	// --- MITRE ATLAS coverage ---
	if len(hw.ATLASCoverage) > 0 {
		atlasKeys := make([]string, 0, len(hw.ATLASCoverage))
		for k := range hw.ATLASCoverage {
			atlasKeys = append(atlasKeys, k)
		}
		sort.Strings(atlasKeys)

		b.WriteString(`<details class="atlas-section" id="atlas-section" style="margin-bottom:1.5rem"><summary style="cursor:pointer;font-size:.92rem;font-weight:600;color:#58a6ff;list-style:none">`)
		b.WriteString(fmt.Sprintf(`MITRE ATLAS Coverage (%d techniques)</summary>`, len(atlasKeys)))
		b.WriteString(`<table class="ft" style="margin-top:.5rem"><thead><tr><th>Technique</th><th>Findings</th></tr></thead><tbody>`)
		for _, t := range atlasKeys {
			b.WriteString(fmt.Sprintf(`<tr><td><a href="https://atlas.mitre.org/techniques/%s" target="_blank" rel="noopener noreferrer" style="color:#58a6ff">%s</a></td><td>%d</td></tr>`, e(t), e(t), hw.ATLASCoverage[t]))
		}
		b.WriteString(`</tbody></table></details>`)
	}

	// --- Filters (collapsed) ---
	b.WriteString(`<details class="filter-wrap no-print" id="filterToolbar"><summary>Filters &amp; Search</summary><div class="filter-bar">`)
	b.WriteString(`<label>Search <input type="search" id="findSearch" placeholder="Title, target, template, tags…" autocomplete="off"></label>`)
	b.WriteString(`<span class="muted" style="font-size:.82rem">Severity:</span>`)
	for _, sev := range []string{report.SeverityCritical, report.SeverityHigh, report.SeverityMedium, report.SeverityLow, report.SeverityInfo} {
		b.WriteString(fmt.Sprintf(`<label><input type="checkbox" data-sev="%s" checked> %s</label>`, sev, e(sev)))
	}
	b.WriteString(`<div class="bulk-controls"><button onclick="expandAll()">Expand All</button><button onclick="collapseAll()">Collapse All</button></div>`)
	b.WriteString(`</div></details>`)

	if len(hostOrder) == 0 {
		b.WriteString(`<p class="muted" style="text-align:center;margin:3rem 0">No findings in this report.</p>`)
	}

	// --- Host cards ---
	rowIdx := 0
	for _, h := range hostOrder {
		findings := sortBySeverity(append([]report.Finding(nil), byHost[h]...))
		id := "host-" + htmlHostKey(h)
		bodyID := "hcbody-" + htmlHostKey(h)
		wr := htmlWorstSeverityRank(findings)
		worstLabel := severityLabelFromRank(wr)
		worstClass := sevCSSClass(worstLabel)
		svcs := hostServices(findings)

		b.WriteString(fmt.Sprintf(`<div class="host-card" id="%s">`, id))
		b.WriteString(fmt.Sprintf(`<div class="host-card-header" onclick="toggleHostCard('%s')">`, bodyID))
		b.WriteString(fmt.Sprintf(`<span class="hc-chevron" id="chevron-%s">&#9660;</span>`, bodyID))
		b.WriteString(fmt.Sprintf(`<h2>%s</h2>`, e(h)))
		b.WriteString(fmt.Sprintf(`<span class="hc-meta">%d findings</span>`, len(findings)))
		b.WriteString(fmt.Sprintf(`<span class="sev-badge sev sev-%s">%s</span>`, worstClass, e(worstLabel)))
		if svcs != "" {
			b.WriteString(fmt.Sprintf(`<div class="hc-services">%s</div>`, e(svcs)))
		}
		b.WriteString(`</div>`)

		b.WriteString(fmt.Sprintf(`<div class="hc-body" id="%s">`, bodyID))
		tblID := "tbl-" + htmlHostKey(h)
		b.WriteString(fmt.Sprintf(`<table class="ft" id="%s">
<thead><tr>
<th onclick="sortFT('%s',0)" style="width:5rem">Severity</th>
<th onclick="sortFT('%s',1)">Finding</th>
<th onclick="sortFT('%s',2)">Target</th>
<th onclick="sortFT('%s',3)" style="width:4rem">CVSS</th>
<th style="width:4.5rem">Landed</th>
<th style="width:4rem"></th>
</tr></thead><tbody>
`, tblID, tblID, tblID, tblID, tblID))

		for _, f := range findings {
			detailID := fmt.Sprintf("detail-%d", rowIdx)
			sevClass := sevCSSClass(f.Severity)
			rowClass := "finding-row sev-row-" + sevClass
			b.WriteString(fmt.Sprintf(`<tr class="%s" data-row="1" data-severity="%s" data-detail="%s" onclick="toggleDetail('%s')">`, rowClass, e(report.NormalizeSeverity(f.Severity)), detailID, detailID))
			b.WriteString(fmt.Sprintf(`<td><span class="sev sev-%s">%s</span></td>`, sevClass, e(report.NormalizeSeverity(f.Severity))))
			b.WriteString(fmt.Sprintf(`<td class="title-cell">%s</td>`, e(f.Title)))
			b.WriteString(fmt.Sprintf(`<td class="mono">%s</td>`, e(f.Target)))
			cvss := `<span class="muted">—</span>`
			if f.CVSS > 0 {
				cvss = e(fmt.Sprintf("%.1f", f.CVSS))
			}
			b.WriteString(fmt.Sprintf(`<td>%s</td>`, cvss))

			proofBadge := ""
			if bc := proofBadgeClass(f); bc == badgeExploited {
				proofBadge = `<span class="proof-badge badge-exploited">EXPLOITED</span>`
			} else if bc == badgeVerified {
				proofBadge = `<span class="proof-badge badge-verified">VERIFIED</span>`
			}
			b.WriteString(fmt.Sprintf(`<td>%s</td>`, proofBadge))

			b.WriteString(fmt.Sprintf(`<td><button class="expand-btn" onclick="event.stopPropagation();toggleDetail('%s')">Details</button></td>`, detailID))
			b.WriteString("</tr>\n")

			// Detail row
			b.WriteString(fmt.Sprintf(`<tr class="detail-row" id="%s"><td colspan="6"><div class="detail-panel">`, detailID))

			b.WriteString(`<div><h4>Source</h4><div class="dp-val">`)
			b.WriteString(e(f.Source))
			if f.TemplateID != "" {
				b.WriteString(fmt.Sprintf(` <span class="muted">(%s)</span>`, e(f.TemplateID)))
			}
			b.WriteString(`</div></div>`)

			b.WriteString(`<div><h4>Tags</h4><div class="dp-val"><div class="tags">`)
			for _, tag := range f.Tags {
				b.WriteString(fmt.Sprintf(`<span class="tag">%s</span>`, e(tag)))
			}
			if len(f.Tags) == 0 {
				b.WriteString(`<span class="muted">—</span>`)
			}
			b.WriteString(`</div></div></div>`)

			if f.Description != "" {
				b.WriteString(`<div class="dp-full"><h4>Description</h4><div class="dp-val">`)
				b.WriteString(e(f.Description))
				b.WriteString(`</div></div>`)
			}

			if f.Remediation != "" {
				b.WriteString(`<div class="dp-full"><h4>Remediation</h4><div class="remediation-callout">`)
				b.WriteString(e(f.Remediation))
				b.WriteString(`</div></div>`)
			}

			if f.Evidence != "" {
				b.WriteString(`<div class="dp-full"><h4>Evidence</h4>`)
				b.WriteString(fmt.Sprintf(`<pre class="evidence">%s</pre>`, e(f.Evidence)))
				b.WriteString(`</div>`)
			}

			if len(f.References) > 0 {
				b.WriteString(`<div class="dp-full"><h4>References</h4><div class="dp-val">`)
				b.WriteString(htmlCellReferences(f.References, e))
				b.WriteString(`</div></div>`)
			}

			b.WriteString(`</div></td></tr>`)
			rowIdx++
		}
		b.WriteString(`</tbody></table></div></div>`)
	}

	b.WriteString(`
<script>
function toggleDetail(id){
  const r=document.getElementById(id);
  if(r) r.classList.toggle("open");
}
function toggleHostCard(id){
  const body=document.getElementById(id);
  const chev=document.getElementById("chevron-"+id);
  if(body){body.classList.toggle("collapsed");if(chev)chev.classList.toggle("collapsed");}
}
function toggleSection(id){
  const el=document.getElementById(id);
  const chev=document.getElementById("chevron-"+id);
  if(el){
    if(el.style.display==="none"){el.style.display="";if(chev)chev.classList.remove("collapsed");}
    else{el.style.display="none";if(chev)chev.classList.add("collapsed");}
  }
}
function expandAll(){
  document.querySelectorAll("tr.detail-row").forEach(r=>{if(r.style.display!=="none")r.classList.add("open")});
  document.querySelectorAll(".hc-body").forEach(b=>{b.classList.remove("collapsed");const c=document.getElementById("chevron-"+b.id);if(c)c.classList.remove("collapsed");});
}
function collapseAll(){
  document.querySelectorAll("tr.detail-row").forEach(r=>r.classList.remove("open"));
  document.querySelectorAll(".hc-body").forEach(b=>{b.classList.add("collapsed");const c=document.getElementById("chevron-"+b.id);if(c)c.classList.add("collapsed");});
}
function sortFT(tid,col){
  const t=document.getElementById(tid);
  if(!t)return;
  const tb=t.tBodies[0];
  const pairs=[];
  const rows=[...tb.rows];
  for(let i=0;i<rows.length;i++){
    if(rows[i].classList.contains("finding-row")){
      pairs.push({main:rows[i],detail:rows[i+1]&&rows[i+1].classList.contains("detail-row")?rows[i+1]:null});
      if(pairs[pairs.length-1].detail) i++;
    }
  }
  const dir=t.dataset.sortCol==String(col)&&t.dataset.sortDir=="asc"?"desc":"asc";
  t.dataset.sortCol=String(col);t.dataset.sortDir=dir;
  pairs.sort((a,c)=>{
    let x=a.main.cells[col].textContent.trim(),y=c.main.cells[col].textContent.trim();
    if(col===0){const o={critical:0,high:1,medium:2,low:3,info:4};x=o[x]??5;y=o[y]??5}
    if(col===3){x=parseFloat(x)||0;y=parseFloat(y)||0}
    return dir==="asc"?(x>y?1:x<y?-1:0):(x<y?1:x>y?-1:0);
  });
  pairs.forEach(p=>{tb.appendChild(p.main);if(p.detail)tb.appendChild(p.detail);});
}
(function(){
  const search=document.getElementById("findSearch");
  if(!search)return;
  function apply(){
    const q=(search.value||"").toLowerCase();
    const show={};
    document.querySelectorAll("#filterToolbar input[data-sev]").forEach(cb=>{show[cb.getAttribute("data-sev")]=cb.checked;});
    document.querySelectorAll("tr[data-row]").forEach(tr=>{
      const sev=tr.getAttribute("data-severity");
      const okSev=show[sev]!==false;
      const okText=!q||tr.innerText.toLowerCase().includes(q);
      const vis=okSev&&okText;
      tr.style.display=vis?"":"none";
      const did=tr.getAttribute("data-detail");
      if(did){const d=document.getElementById(did);if(d&&!vis){d.classList.remove("open");d.style.display="none";}else if(d){d.style.display="";}}
    });
  }
  search.addEventListener("input",apply);
  document.querySelectorAll("#filterToolbar input[data-sev]").forEach(cb=>cb.addEventListener("change",apply));
})();
(function(){
  const links=document.querySelectorAll(".sb-link[data-section]");
  if(!links.length)return;
  const obs=new IntersectionObserver(entries=>{
    entries.forEach(en=>{
      if(en.isIntersecting){
        links.forEach(l=>l.classList.remove("sb-active"));
        const match=document.querySelector('.sb-link[data-section="'+en.target.id+'"]');
        if(match)match.classList.add("sb-active");
      }
    });
  },{rootMargin:"-20% 0px -60% 0px"});
  document.querySelectorAll("[id]").forEach(el=>{
    if(document.querySelector('.sb-link[data-section="'+el.id+'"]'))obs.observe(el);
  });
})();
window.addEventListener("beforeprint",function(){
  document.querySelectorAll("tr.detail-row").forEach(r=>r.classList.add("open"));
  document.querySelectorAll(".hc-body").forEach(b=>b.classList.remove("collapsed"));
});
</script>
<footer>aipostex &mdash; AI Infrastructure Offensive Security</footer>
<p class="confidential">This report may contain sensitive security findings. Handle according to your organization's data classification policy.</p>
</div>
</body></html>
`)

	_, err := io.WriteString(hw.w, b.String())
	return err
}
