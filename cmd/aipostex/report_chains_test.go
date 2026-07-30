package main

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// rayLeakFinding is a discovery finding whose runtime_env leaked a chainable MLflow
// Basic-auth credential unlocking a DIFFERENT host (the gateway) — the demo spine.
func rayLeakFinding() report.Finding {
	return report.Finding{
		ID:     "ray-aaa111",
		Source: "ray",
		Target: "http://172.16.50.20:8265",
		Title:  "Ray runtime_env exposes MLflow gateway credentials",
		Metadata: map[string]interface{}{
			"stage":  "access",
			"landed": "reachable",
			"extracted_credentials": []map[string]interface{}{{
				"type":       "mlflow-basic-auth",
				"name":       "mlflow-gw",
				"value":      "YWRtaW46c2VjcmV0",
				"target_url": "http://172.16.50.30:5000",
				"chainable":  true,
			}},
		},
	}
}

func mlflowProofFinding() report.Finding {
	return report.Finding{
		ID:     "mlflow-bbb222",
		Source: "mlflow",
		Target: "http://172.16.50.30:5000",
		Title:  "MLflow experiments enumerated",
		Metadata: map[string]interface{}{
			"stage":  "impact",
			"landed": "read-confirmed",
		},
	}
}

// A full chain: discovery finding → looted credential → follow-on command against the
// UNLOCKED target → a downstream finding already on that target = a reached hop
// (correlation, not a verified replay).
func TestReconstructChainsFindLootChainReached(t *testing.T) {
	chains := reconstructChains([]report.Finding{rayLeakFinding(), mlflowProofFinding()})
	if len(chains) != 1 {
		t.Fatalf("expected exactly one chain, got %d", len(chains))
	}
	ch := chains[0]
	if !ch.hasProof {
		t.Fatalf("expected the chain to reach a correlated downstream finding")
	}

	var kinds []string
	var body strings.Builder
	for _, s := range ch.steps {
		kinds = append(kinds, s.kind)
		body.WriteString(s.text)
		body.WriteString("\n")
	}
	order := strings.Join(kinds, ",")
	if !strings.HasPrefix(order, "find,loot,chain") {
		t.Fatalf("expected find→loot→chain spine, got %s", order)
	}
	if kinds[len(kinds)-1] != "reached" {
		t.Fatalf("expected the chain to end in a reached step, got %s", order)
	}

	// Title shows the cross-service hop (found on Ray, used against the MLflow gateway),
	// named by service rather than raw host:port.
	if !strings.Contains(ch.title, "Ray dashboard") || !strings.Contains(ch.title, "MLflow") {
		t.Fatalf("expected a Ray→MLflow service hop title, got %q", ch.title)
	}
	// The follow-on command targets the UNLOCKED host, not the discovery host.
	if !strings.Contains(body.String(), "mlflow --target http://172.16.50.30:5000") {
		t.Fatalf("expected a command against the unlocked mlflow target, got:\n%s", body.String())
	}
	// The looted secret is shown raw — aipostex never redacts evidence.
	if !strings.Contains(body.String(), "YWRtaW46c2VjcmV0") {
		t.Fatalf("expected the raw credential value in the loot step, got:\n%s", body.String())
	}
}

// A chainable credential whose next hop hasn't been run yet has no downstream
// finding — it must render as a gap that names the concrete next command.
func TestReconstructChainsGapWhenNextHopUnrun(t *testing.T) {
	chains := reconstructChains([]report.Finding{rayLeakFinding()})
	if len(chains) != 1 {
		t.Fatalf("expected exactly one chain, got %d", len(chains))
	}
	ch := chains[0]
	if ch.hasProof {
		t.Fatalf("expected a gap (no downstream finding present), got a proof")
	}
	last := ch.steps[len(ch.steps)-1]
	if last.kind != "gap" {
		t.Fatalf("expected the chain to end in a gap, got %q", last.kind)
	}
	// The command is still shown (the chain step before the gap) so the operator
	// knows the exact next move.
	var sawCommand bool
	for _, s := range ch.steps {
		if s.kind == "chain" && strings.Contains(s.text, "mlflow --target http://172.16.50.30:5000") {
			sawCommand = true
		}
	}
	if !sawCommand {
		t.Fatalf("expected the un-run chain to still surface its next command")
	}
}

func TestFormatChainStepIncludesRefAndStrength(t *testing.T) {
	line := formatChainStep(chainStep{kind: "reached", label: "mlflow", text: "MLflow experiments enumerated", ref: "mlflow-bbb222", strength: "read-confirmed"}, false)
	if !strings.Contains(line, "reached") || !strings.Contains(line, "mlflow-bbb222") || !strings.Contains(line, "read-confirmed") {
		t.Fatalf("formatted step missing fields: %q", line)
	}
}

// The abbreviated run step hides the --header/--target boilerplate for readability;
// with --commands (full=true) the exact runnable command must appear so the operator
// can follow the chain to the next hop without leaving the terminal.
func TestFormatChainStepFullShowsRunnableCommand(t *testing.T) {
	cmd := `huggingface --target http://172.16.50.40:8180 --header "Authorization: Bearer hf_FAKE" generate --prompt "x" --force-exploit`
	st := chainStep{kind: "chain", label: "next", text: cmd}

	abbrev := formatChainStep(st, false)
	if strings.Contains(abbrev, "--header") {
		t.Fatalf("abbreviated step should elide --header, got: %q", abbrev)
	}

	full := formatChainStep(st, true)
	if !strings.Contains(full, "--header \"Authorization: Bearer hf_FAKE\"") || !strings.Contains(full, "--target http://172.16.50.40:8180") {
		t.Fatalf("full step must contain the exact runnable command, got: %q", full)
	}
	if !strings.Contains(full, "aipostex huggingface") {
		t.Fatalf("full step must be a copy-pasteable aipostex command, got: %q", full)
	}
}
