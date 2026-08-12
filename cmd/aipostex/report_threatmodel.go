package main

import (
	"fmt"
	"sort"

	"github.com/professor-moody/aipostex/pkg/report"
)

// report view --threat-model turns a findings collection into a threat-model
// deliverable, entirely from the honest stage/landed kill-chain metadata each
// module already emits:
//
//   1. Kill-chain coverage — how far each target was actually pushed (recon →
//      access → impact → own, reachable → takeover-capable).
//   2. Crown jewels — the findings that reached the deepest landed levels (what the
//      operator actually got: execution / takeover / a confirmed read).
//   3. MITRE ATLAS-aligned tactic mapping — a curated grouping of the findings by
//      ATLAS tactic. The tactic + technique label is the authoritative anchor; a
//      specific AML.T#### id is attached ONLY where high-confidence, so nothing is
//      fabricated.

// stageOrder / landedOrder rank the honesty axes so we can find the furthest reach.
var stageOrder = map[string]int{"recon": 1, "access": 2, "impact": 3, "own": 4}
var landedOrder = map[string]int{
	"reachable": 1, "submission-accepted": 1, "influenced": 2, "read-confirmed": 3,
	"execution-confirmed": 4, "takeover-capable": 5,
}

// atlasMapping is aipostex's curated ATLAS-tactic mapping keyed by finding action
// (falling back to module). tactic is a well-established ATLAS tactic; technique is
// a descriptive label; id is a specific AML.T#### only where high-confidence.
type atlasMapping struct {
	tactic    string
	technique string
	id        string // optional; "" when not attaching a specific id
}

var atlasByAction = map[string]atlasMapping{
	"inject":             {"Defense Evasion", "LLM Prompt Injection", "AML.T0051"},
	"crescendo":          {"Defense Evasion", "LLM Prompt Injection (multi-turn)", "AML.T0051"},
	"fragment":           {"Defense Evasion", "LLM Prompt Injection (fragmented)", "AML.T0051"},
	"metadata-inject":    {"Defense Evasion", "LLM Prompt Injection (indirect/RAG)", "AML.T0051"},
	"poison":             {"ML Attack Staging", "Poison RAG / Training Data", ""},
	"obey":               {"Defense Evasion", "Indirect Prompt Injection (verified)", "AML.T0051"},
	"guardrail":          {"Defense Evasion", "LLM Jailbreak / Guardrail Probe", "AML.T0054"},
	"extract":            {"Collection", "System-Prompt / Sensitive-Info Disclosure", ""},
	"prompt-extract":     {"Collection", "System-Prompt / Sensitive-Info Disclosure", ""},
	"prompts":            {"Collection", "System-Prompt Disclosure", ""},
	"env-extract":        {"Credential Access", "Unsecured Credentials", ""},
	"config-extract":     {"Credential Access", "Unsecured Credentials", ""},
	"secret-read":        {"Credential Access", "Unsecured Credentials", ""},
	"key-gen":            {"Credential Access", "Unsecured Credentials", ""},
	"sa-loot":            {"Credential Access", "Steal Service-Account Token", ""},
	"session-probe":      {"Discovery", "Session-ID Enumeration", ""},
	"fingerprint":        {"Discovery", "Discover ML Model Family", ""},
	"enum":               {"Discovery", "Discover ML Artifacts", ""},
	"probe":              {"Discovery", "Discover ML Artifacts", ""},
	"map":                {"Discovery", "Discover RAG Knowledge Base", ""},
	"models":             {"Discovery", "Discover ML Artifacts", ""},
	"infer":              {"ML Model Access", "ML Model Inference API Access", ""},
	"generate":           {"ML Model Access", "ML Model Inference API Access", ""},
	"predict":            {"ML Model Access", "ML Model Inference API Access", ""},
	"embed":              {"ML Model Access", "ML Model Inference API Access", ""},
	"validate-inference": {"ML Model Access", "ML Model Inference API Access", ""},
	"exfiltrate":         {"Exfiltration", "Exfiltrate ML Artifacts", ""},
	"model-download":     {"Exfiltration", "Exfiltrate ML Model", ""},
	"bulk-download":      {"Exfiltration", "Exfiltrate ML Artifacts", ""},
	"download-artifact":  {"Exfiltration", "Exfiltrate ML Artifacts", ""},
	"model-artifacts":    {"Exfiltration", "Exfiltrate ML Artifacts", ""},
	"exec":               {"Execution", "Command & Scripting Interpreter", ""},
	"pod-exec":           {"Execution", "Command & Scripting Interpreter", ""},
	"shell":              {"Execution", "Command & Scripting Interpreter", ""},
	"reverse-shell":      {"Execution", "Command & Scripting Interpreter", ""},
	"pip-inject":         {"Execution", "ML Supply-Chain Code Execution", ""},
	"submit":             {"Execution", "Run Unsafe ML Job", ""},
	"run-pipeline":       {"Execution", "Run Unsafe ML Pipeline", ""},
	"model-load":         {"Execution", "Load Attacker Model", ""},
	"register":           {"Execution", "Register Attacker Model", ""},
	"persist":            {"Persistence", "ML Persistence", ""},
	"beacon":             {"Persistence", "ML Persistence (callback)", ""},
	"config-hijack":      {"Persistence", "MCP Config Hijack", ""},
	"hook":               {"Persistence", "Model-Registry Hook", ""},
	"tool-inject":        {"Persistence", "Agent Tool Poisoning", ""},
	"sandbox-escape":     {"Privilege Escalation", "MCP Tool Sandbox Escape", ""},
	"ssti":               {"Execution", "Server-Side Template Injection", ""},
}

var atlasByModule = map[string]atlasMapping{
	"credential":     {"Credential Access", "Unsecured Credentials", ""},
	"fingerprint":    {"Reconnaissance", "Active Scanning / Service Discovery", ""},
	"file-discovery": {"Collection", "ML Artifact & Secret Collection", ""},
}

func atlasFor(module, action string) atlasMapping {
	if m, ok := atlasByAction[action]; ok {
		return m
	}
	if m, ok := atlasByModule[module]; ok {
		return m
	}
	return atlasMapping{"Discovery", "AI-Surface Activity", ""}
}

func metaStr(f report.Finding, key string) string {
	if f.Metadata == nil {
		return ""
	}
	if v, ok := f.Metadata[key].(string); ok {
		return v
	}
	return ""
}

// renderThreatModel prints the threat-model deliverable for the given findings.
func renderThreatModel(findings []report.Finding) {
	fmt.Println()
	fmt.Println("═══ Threat Model (kill-chain coverage · crown jewels · ATLAS mapping) ═══")

	// 1. Kill-chain coverage per target.
	type reach struct {
		stage, landed       string
		stageRank, landedRk int
	}
	perTarget := map[string]*reach{}
	var targets []string
	for _, f := range findings {
		stage, landed := metaStr(f, "stage"), metaStr(f, "landed")
		if stage == "" && landed == "" {
			continue
		}
		r, ok := perTarget[f.Target]
		if !ok {
			r = &reach{}
			perTarget[f.Target] = r
			targets = append(targets, f.Target)
		}
		if stageOrder[stage] > r.stageRank {
			r.stageRank, r.stage = stageOrder[stage], stage
		}
		if landedOrder[landed] > r.landedRk {
			r.landedRk, r.landed = landedOrder[landed], landed
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		return perTarget[targets[i]].landedRk > perTarget[targets[j]].landedRk
	})
	fmt.Println("\nKill-chain coverage (furthest reached per target):")
	if len(targets) == 0 {
		fmt.Println("  (no stage/landed metadata in these findings)")
	}
	for _, t := range targets {
		r := perTarget[t]
		fmt.Printf("  %-40s %s / %s\n", tmTruncate(t, 40), tmOrDash(r.stage), tmOrDash(r.landed))
	}

	// 2. Crown jewels — deepest landed levels.
	fmt.Println("\nCrown jewels (deepest landed — what was actually reached):")
	crown := 0
	for _, want := range []string{"takeover-capable", "execution-confirmed", "read-confirmed"} {
		for _, f := range findings {
			if metaStr(f, "landed") == want {
				fmt.Printf("  [%s] %s — %s\n", want, tmTruncate(f.Target, 34), tmTruncate(f.Title, 60))
				crown++
			}
		}
	}
	if crown == 0 {
		fmt.Println("  (nothing beyond influenced/reachable — recon/access only)")
	}

	// 3. ATLAS-aligned tactic mapping (aipostex's curated map).
	type tinfo struct {
		count      int
		techniques map[string]string // technique -> id
	}
	byTactic := map[string]*tinfo{}
	var tacticOrder []string
	for _, f := range findings {
		m := atlasFor(metaStr(f, "module"), metaStr(f, "action"))
		ti, ok := byTactic[m.tactic]
		if !ok {
			ti = &tinfo{techniques: map[string]string{}}
			byTactic[m.tactic] = ti
			tacticOrder = append(tacticOrder, m.tactic)
		}
		ti.count++
		if _, seen := ti.techniques[m.technique]; !seen {
			ti.techniques[m.technique] = m.id
		}
	}
	sort.Slice(tacticOrder, func(i, j int) bool {
		return byTactic[tacticOrder[i]].count > byTactic[tacticOrder[j]].count
	})
	fmt.Println("\nMITRE ATLAS-aligned tactics (aipostex curated mapping):")
	for _, tac := range tacticOrder {
		ti := byTactic[tac]
		fmt.Printf("  %-22s (%d)\n", tac, ti.count)
		var techs []string
		for tech := range ti.techniques {
			techs = append(techs, tech)
		}
		sort.Strings(techs)
		for _, tech := range techs {
			id := ti.techniques[tech]
			if id != "" {
				fmt.Printf("      - %s [%s]\n", tech, id)
			} else {
				fmt.Printf("      - %s\n", tech)
			}
		}
	}
	fmt.Println("\n  Note: tactic/technique labels are the authoritative anchor; AML.T#### ids are")
	fmt.Println("  attached only where high-confidence. Mapping is aipostex's own, not MITRE's.")
}

func tmOrDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func tmTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
