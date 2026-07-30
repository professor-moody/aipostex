package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/professor-moody/aipostex/internal/credchain"
	"github.com/professor-moody/aipostex/pkg/report"
)

// report view --chains reconstructs the operator's attack chains from a findings
// set: for each looted, chainable credential it shows the demo narrative
//
//	find  → loot  → run → reached   (or an un-run next hop)
//
// It is a VIEW over data that already exists (credchain + stage/landed metadata), not new
// execution tracking. The find→loot→command spine is exact (the credential records
// its source finding id and target). The "reached" link is only a CORRELATION: a
// finding that already exists on the unlocked target, matched by host + module. There
// is no explicit action→result edge — the tool does not record that this credential
// was replayed to produce that finding (it may even predate the loot) — so it is shown
// with its own honest stage/landed and labeled "reached", never "proven".

// chainStep is one rendered row of a reconstructed chain.
type chainStep struct {
	kind     string // find | loot | chain | reached | gap
	label    string // module or role (retained for structure/tests)
	text     string // the human-readable body (title / credential / raw command)
	ref      string // finding id or "from <id>"
	strength string // landed of the anchoring finding, when applicable
}

// attackChain is one looted credential and the steps around it.
type attackChain struct {
	title    string // "<from service> ─→ <to service>"
	credType string // the looted credential type (shown in the header)
	steps    []chainStep
	hasProof bool
}

func renderChainView(findings []report.Finding, full bool) error {
	chains := reconstructChains(findings)
	fmt.Println()
	fmt.Println(consoleSectionHeader("Attack chains"))
	if len(chains) == 0 {
		fmt.Println("  " + color.HiBlackString("(no chainable looted credentials — run exploit verbs that loot credentials first)"))
		return nil
	}
	reached := 0
	for i, ch := range chains {
		if ch.hasProof {
			reached++
		}
		renderChain(i+1, ch, full)
	}
	fmt.Printf("\n  %s\n", color.HiBlackString("%d chain(s) · %d reached a correlated finding · %d with an un-run next hop",
		len(chains), reached, len(chains)-reached))
	fmt.Println("  " + color.HiBlackString("(\"reached\" = a finding already on the unlocked target, correlated by host+module — not a verified replay)"))
	if !full {
		fmt.Println("  " + color.HiBlackString("tip: add --commands to print the exact runnable command for each hop"))
	}
	return nil
}

// renderChain prints one chain as a titled block: a hop header plus aligned
// find / loot / run / reached rows.
func renderChain(n int, ch attackChain, full bool) {
	status := color.HiBlackString("○ un-run")
	if ch.hasProof {
		status = color.GreenString("● reached")
	}
	header := color.New(color.Bold).Sprintf("▸ Chain %d", n)
	fmt.Printf("\n  %s   %s   %s   %s\n", header, ch.title, color.HiBlackString("· "+ch.credType), status)
	for _, st := range ch.steps {
		if line := formatChainStep(st, full); line != "" {
			fmt.Println("      " + line)
		}
	}
}

// reconstructChains builds one attackChain per chainable looted credential.
func reconstructChains(findings []report.Finding) []attackChain {
	records := credentialRecordsForReportView(findings)
	store := credchain.ExtractFromFindings(findings)
	actions := credchain.GenerateChainActions(store)
	byID := indexFindingsByID(findings)

	chains := make([]attackChain, 0, len(records))
	for _, rec := range records {
		if !rec.Chainable {
			continue
		}
		// mlflow-run-id is an intra-MLflow enumeration handle ("inspect THIS run's
		// artifacts"), not a credential that pivots to another service. Left in, it floods
		// the board with one near-identical `artifacts --run-id` chain per run and buries
		// the real cross-service flow (Ray→MLflow→HF). The chains view is for credential
		// FLOW between services; run-id artifact inspection still appears under Next Actions
		// / `report view --commands`.
		if rec.Type == "mlflow-run-id" {
			continue
		}
		var ch attackChain
		ch.credType = rec.Type
		src, haveSrc := byID[rec.Source]

		// 1) find — the finding that leaked this credential.
		if haveSrc {
			ch.steps = append(ch.steps, chainStep{
				kind:     "find",
				label:    src.Source,
				text:     src.Title,
				ref:      compactReportSourceID(src.ID),
				strength: landed(src),
			})
		} else {
			ch.steps = append(ch.steps, chainStep{
				kind:  "find",
				label: "-",
				text:  "credential discovered (source finding not in this view)",
				ref:   compactReportSourceID(rec.Source),
			})
		}

		// 2) loot — the credential itself (raw, never redacted).
		ch.steps = append(ch.steps, chainStep{
			kind:  "loot",
			label: "cred",
			text:  credentialChainLabel(rec),
			ref:   "from " + compactReportSourceID(rec.Source),
		})

		// 3) run — the single payoff command this credential unlocks (this credential's
		//    OWN command, not every same-type command in the run). The full runnable
		//    command set stays under `report view --commands`.
		credActions := actionsForCredentialRecord(actions, rec)
		if primary := primaryChainAction(credActions); primary != nil {
			ch.steps = append(ch.steps, chainStep{
				kind:  "chain",
				label: "next",
				text:  primary.Command, // raw; abbreviated at render time
			})
		}

		// 4) reached | (un-run) — a downstream finding already on the unlocked target
		//    (correlated by host+module, NOT a verified credential replay), or the
		//    honest "not yet run" state (rendered as the header status pill).
		if proof := downstreamFinding(findings, credActions, rec.Source); proof != nil {
			ch.hasProof = true
			ch.steps = append(ch.steps, chainStep{
				kind:     "reached",
				label:    proof.Source,
				text:     proof.Title,
				ref:      compactReportSourceID(proof.ID),
				strength: landed(*proof),
			})
		} else {
			ch.steps = append(ch.steps, chainStep{
				kind:  "gap",
				label: "run",
				text:  "not yet run — execute the command above to exercise this hop",
			})
		}

		ch.title = chainTitle(rec, src, haveSrc)
		chains = append(chains, ch)
	}
	return chains
}

// actionsForCredentialRecord returns the follow-on actions that belong to THIS
// credential. It scopes by the credential's own value first (so a chain shows only its
// own token's command, never every same-type token in the run), then by the unlocked
// host, then falls back to a type-only match so a chainable credential always shows a
// command.
func actionsForCredentialRecord(actions []credchain.ChainAction, rec credchain.CredentialRecord) []credchain.ChainAction {
	credHost := chainHostPort(rec.TargetURL)
	if credHost == "" {
		credHost = chainHostPort(rec.SourceTarget)
	}
	val := strings.TrimSpace(rec.Value)
	var valScoped, hostScoped, typeOnly []credchain.ChainAction
	seen := make(map[string]struct{})
	for _, a := range actions {
		if !strings.EqualFold(a.CredentialType, rec.Type) {
			continue
		}
		if _, ok := seen[a.Command]; ok {
			continue
		}
		seen[a.Command] = struct{}{}
		typeOnly = append(typeOnly, a)
		if credHost != "" && chainHostPort(a.TargetURL) == credHost {
			hostScoped = append(hostScoped, a)
		}
		if val != "" && strings.Contains(a.Command, val) {
			valScoped = append(valScoped, a)
		}
	}
	switch {
	case len(valScoped) > 0:
		return valScoped
	case len(hostScoped) > 0:
		return hostScoped
	default:
		return typeOnly
	}
}

// primaryChainAction picks the single most impactful follow-on to headline the chain —
// the payoff verb (generate / runs / secret-read / …) over a preliminary enum.
func primaryChainAction(actions []credchain.ChainAction) *credchain.ChainAction {
	if len(actions) == 0 {
		return nil
	}
	best := &actions[0]
	bestRank := chainVerbRank(actions[0].Command)
	for i := 1; i < len(actions); i++ {
		if r := chainVerbRank(actions[i].Command); r > bestRank {
			best, bestRank = &actions[i], r
		}
	}
	return best
}

func chainVerbRank(cmd string) int {
	c := " " + strings.ToLower(cmd) + " "
	switch {
	case strings.Contains(c, " generate "), strings.Contains(c, " proxy-chain "),
		strings.Contains(c, " sa-loot "), strings.Contains(c, " pod-exec "):
		return 6
	case strings.Contains(c, " secret-read "), strings.Contains(c, " runs "),
		strings.Contains(c, " model-download "), strings.Contains(c, " secrets "):
		return 5
	case strings.Contains(c, " jobs "), strings.Contains(c, " tamper-proof "):
		return 4
	case strings.Contains(c, " registry "), strings.Contains(c, " artifacts "):
		return 3
	case strings.Contains(c, " enum "), strings.Contains(c, " access-review "):
		return 2
	default:
		return 3
	}
}

// downstreamFinding correlates a credential's follow-on actions to a finding that
// running them would have produced: same unlocked host, module matching the
// command, and not the credential's own discovery finding. The strongest proof
// stage wins. Returns nil (a gap) when nothing matches.
func downstreamFinding(findings []report.Finding, credActions []credchain.ChainAction, sourceID string) *report.Finding {
	unlockHost := ""
	modules := make(map[string]struct{})
	for _, a := range credActions {
		if h := chainHostPort(a.TargetURL); h != "" {
			unlockHost = h
		}
		if m := commandModule(a.Command); m != "" {
			modules[m] = struct{}{}
		}
	}
	if unlockHost == "" {
		return nil
	}
	var best *report.Finding
	for i := range findings {
		f := &findings[i]
		if f.ID == sourceID {
			continue
		}
		if chainHostPort(f.Target) != unlockHost {
			continue
		}
		if len(modules) > 0 {
			if _, ok := modules[strings.ToLower(f.Source)]; !ok {
				continue
			}
		}
		if best == nil || chainStageRank(inferStage(*f)) > chainStageRank(inferStage(*best)) {
			best = f
		}
	}
	return best
}

// chainTitle renders the "<from service> ─→ <to service>" hop. Service names come from
// the ports so the board reads as a story ("Ray dashboard ─→ HuggingFace TGI") rather
// than a wall of host:port pairs; the raw host:port still appears in the run command.
func chainTitle(rec credchain.CredentialRecord, src report.Finding, haveSrc bool) string {
	to := chainHostPort(rec.TargetURL)
	if to == "" {
		to = chainHostPort(rec.SourceTarget)
	}
	from := ""
	if haveSrc {
		from = chainHostPort(src.Target)
	}
	toName := chainServiceName(to)
	fromName := chainServiceName(from)
	switch {
	case fromName == "" && toName == "":
		return rec.Type
	case fromName == "" || fromName == toName:
		return toName
	default:
		return fromName + " ─→ " + toName
	}
}

// chainServiceName maps a host:port to the friendly product name of the service that
// runs there, falling back to the host:port when the port is unrecognized.
func chainServiceName(hostPort string) string {
	hp := chainHostPort(hostPort)
	if hp == "" {
		return ""
	}
	port := hp
	if i := strings.LastIndex(hp, ":"); i >= 0 {
		port = hp[i+1:]
	}
	switch port {
	case "8265":
		return "Ray dashboard"
	case "5000":
		return "MLflow"
	case "4000", "4001":
		return "LiteLLM"
	case "8180":
		return "HuggingFace TGI"
	case "8181":
		return "HF TEI"
	case "8182":
		return "vLLM"
	case "3000":
		return "MCP server"
	case "8000":
		return "ChromaDB"
	case "8080":
		return "Weaviate"
	case "6333":
		return "Qdrant"
	case "6443", "6444":
		return "Kubernetes"
	case "11434":
		return "Ollama"
	case "8100", "8101", "8102", "8103":
		return "A2A agent"
	case "8444":
		return "W&B"
	case "8888", "8889":
		return "Jupyter"
	default:
		return hp
	}
}

// credentialChainLabel renders the looted credential for the loot row as "NAME = value"
// (the type lives in the chain header). The value is shown raw — aipostex never redacts.
func credentialChainLabel(rec credchain.CredentialRecord) string {
	name := strings.TrimSpace(rec.Name)
	val := strings.TrimSpace(rec.Value)
	switch {
	case name != "" && val != "":
		return name + " = " + val
	case val != "":
		return val
	case name != "":
		return name
	default:
		return rec.Type
	}
}

var chainTargetPortRe = regexp.MustCompile(`--target\s+\S*?:(\d+)`)

// formatChainStep renders a single row with an aligned, colored keyword column.
// The un-run "gap" step is folded into the chain header status pill, so it renders
// nothing here.
func formatChainStep(st chainStep, full bool) string {
	switch st.kind {
	case "find":
		return color.CyanString("%-8s", "find") + st.text + chainDimTail(st.ref, st.strength)
	case "loot":
		return color.CyanString("%-8s", "loot") + st.text
	case "chain":
		// --commands: show the exact runnable command so the operator can follow the
		// chain to the next hop without leaving the terminal. Default: the abbreviated
		// summary (service/verb) — the service/port already appears in the chain header,
		// so printing both the summary AND the full command would just be redundant.
		cmd := abbreviateChainCommand(st.text)
		if full {
			cmd = formatCommandExample(st.text)
		}
		return color.YellowString("%-8s", "run") + cmd + chainOutcomeHint(st.text)
	case "reached":
		return color.GreenString("%-8s", "reached") + st.text + chainDimTail(st.ref, st.strength)
	default: // gap — shown as the header status
		return ""
	}
}

// abbreviateChainCommand compresses a full follow-on command into a readable form:
// "<module> → :<port> · <verb> [--force-exploit]", eliding the long --header/--target
// boilerplate. The complete runnable command stays under `report view --commands`.
func abbreviateChainCommand(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return cmd
	}
	module := fields[0]
	if module == "aipostex" && len(fields) > 1 {
		module = fields[1]
	}
	out := module
	if m := chainTargetPortRe.FindStringSubmatch(cmd); len(m) == 2 {
		out += " → :" + m[1]
	}
	verbs := map[string]bool{
		"generate": true, "runs": true, "enum": true, "secret-read": true, "sa-loot": true,
		"pod-exec": true, "proxy-chain": true, "model-download": true, "registry": true,
		"jobs": true, "artifacts": true, "models": true, "secrets": true, "access-review": true,
	}
	for _, f := range fields {
		if verbs[f] {
			out += " · " + f
			break
		}
	}
	for _, fl := range []string{"--relay-test", "--all-namespaces", "--force-exploit"} {
		if strings.Contains(cmd, fl) {
			out += " " + fl
		}
	}
	return out
}

// chainOutcomeHint appends a short dim "⟶ <what it yields>" to the payoff command so
// the board reads as a story.
func chainOutcomeHint(cmd string) string {
	c := " " + strings.ToLower(cmd) + " "
	hint := ""
	switch {
	case strings.Contains(c, " generate "), strings.Contains(c, " proxy-chain "):
		hint = "real inference"
	case strings.Contains(c, " sa-loot "), strings.Contains(c, " pod-exec "):
		hint = "cluster takeover"
	case strings.Contains(c, " secret-read "), strings.Contains(c, " secrets "):
		hint = "cluster secrets"
	case strings.Contains(c, " runs "):
		hint = "gated gateway"
	case strings.Contains(c, " model-download "):
		hint = "model weights"
	}
	if hint == "" {
		return ""
	}
	return color.HiBlackString("   ⟶ " + hint)
}

func chainDimTail(ref, strength string) string {
	var tail []string
	if ref != "" {
		tail = append(tail, ref)
	}
	if strength != "" {
		tail = append(tail, strength)
	}
	if len(tail) == 0 {
		return ""
	}
	return color.HiBlackString("   (" + strings.Join(tail, " · ") + ")")
}

func indexFindingsByID(findings []report.Finding) map[string]report.Finding {
	byID := make(map[string]report.Finding, len(findings))
	for _, f := range findings {
		if f.ID != "" {
			byID[f.ID] = f
		}
	}
	return byID
}

func landed(f report.Finding) string {
	if s, ok := f.Metadata["landed"].(string); ok {
		return s
	}
	return ""
}

// commandModule returns the aipostex module a follow-on command drives (its first
// token), skipping non-module verbs like "scan"/"report" that don't map to a
// finding's Source.
func commandModule(cmd string) string {
	fields := strings.Fields(strings.TrimSpace(cmd))
	if len(fields) == 0 {
		return ""
	}
	mod := strings.ToLower(fields[0])
	switch mod {
	case "scan", "report", "aipostex":
		return ""
	}
	return mod
}

// chainHostPort normalizes a URL or bare host:port to its host:port for matching.
func chainHostPort(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.TrimSpace(strings.TrimSuffix(s, "http://"))
	}
	return u.Host
}

func chainStageRank(stage string) int {
	switch report.NormalizeStage(strings.ToLower(stage)) {
	case report.StageOwn:
		return 4
	case report.StageImpact:
		return 3
	case report.StageAccess:
		return 2
	case report.StageRecon:
		return 1
	default:
		return 0
	}
}
