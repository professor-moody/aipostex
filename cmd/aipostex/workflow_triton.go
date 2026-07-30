package main

import "github.com/professor-moody/aipostex/pkg/exploit/triton"

// buildTritonModelsWorkflowPlan turns a completed `triton models` enumeration into
// concrete follow-on commands. RepositoryIndex() discovered real model names, so
// model-config / infer name a discovered model instead of emitting a "<model>"
// placeholder. The gated infer step is only appended when a real model was
// discovered — an inference command carrying a placeholder would be a false lead,
// so we fill it or drop it (never emit the gated exploit with a bare token).
func buildTritonModelsWorkflowPlan(target string, models []triton.ModelRepoEntry) workflowPlan {
	target = canonicalServiceURL(target)
	names := make([]string, 0, len(models))
	for _, m := range models {
		names = append(names, m.Name)
	}
	model := shellSafeArg(firstOrPlaceholder(names, "<model>"))

	recs := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("triton --target "+target+" shm-probe"), "Probe shared memory regions for the IPC vulnerability chain (CVE-2025-23319/23320/23334).", false, 10),
	}
	if model != "<model>" {
		// A discovered model name makes model-config and inference concrete and copyable.
		recs = append(recs,
			newWorkflowRecommendation(formatCommandExample("triton --target "+target+" model-config --model "+model), "Inspect a discovered model's configuration (platform, backend, instance groups).", false, 20),
			newWorkflowRecommendation(formatCommandExample("triton --target "+target+" infer --model "+model+" --payload '{\"inputs\":[]}' --force-exploit"), "Test inference access against a discovered model.", true, 30),
			newWorkflowRecommendation(formatCommandExample("triton --target "+target+" model-load --model "+model+" --payload '{\"inputs\":[]}' --force-exploit"), "Load a repository model and verify it becomes inferable.", true, 40),
		)
	}

	return workflowPlan{
		Target:          target,
		Stage:           "models",
		Rationale:       "Discovered model names anchor model-config inspection, bounded inference testing, and repository load verification.",
		Recommendations: recs,
	}
}

// buildTritonExploitWorkflowPlan emits follow-ons for the triton model-lifecycle and
// probe verbs, chaining each to an existing triton verb that deepens what it found.
// model is the targeted model name ("" only for shm-probe, which carries none). The
// gated inference/load steps are only emitted when a concrete model is known, so a
// --force-exploit command never carries a "<model>" placeholder.
func buildTritonExploitWorkflowPlan(target, action, model string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "triton --target " + target + " "
	m := shellSafeArg(model)
	known := model != ""
	var rationale string
	var recs []workflowRecommendation
	switch action {
	case "model-config":
		rationale = "Disclosed model configuration (platform/backend) anchors inference testing and repository-load verification of the same model."
		if known {
			recs = []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample(base+"infer --model "+m+" --payload '{\"inputs\":[]}' --force-exploit"), "Test inference access against the inspected model.", true, 10),
				newWorkflowRecommendation(formatCommandExample(base+"model-load --model "+m+" --payload '{\"inputs\":[]}' --force-exploit"), "Load the model and verify it becomes inferable.", true, 20),
			}
		}
	case "infer":
		rationale = "Inference reachability confirmed; inspect the model configuration and probe the shared-memory IPC surface."
		if known {
			recs = append(recs, newWorkflowRecommendation(formatCommandExample(base+"model-config --model "+m), "Inspect the inferred model's configuration (platform, backend, instance groups).", false, 10))
		}
		recs = append(recs, newWorkflowRecommendation(formatCommandExample(base+"shm-probe"), "Probe shared-memory regions for the IPC vulnerability chain (CVE-2025-23319/23320/23334).", false, 20))
	case "model-load":
		rationale = "A repository model was loaded; verify it is inferable, inspect its configuration, then unload to restore state."
		if known {
			recs = []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample(base+"infer --model "+m+" --payload '{\"inputs\":[]}' --force-exploit"), "Verify the loaded model actually serves inference.", true, 10),
				newWorkflowRecommendation(formatCommandExample(base+"model-config --model "+m), "Inspect the loaded model's configuration.", false, 20),
				newWorkflowRecommendation(formatCommandExample(base+"model-unload --model "+m+" --force-exploit"), "Unload the model to restore the repository to its prior state.", true, 30),
			}
		}
	case "model-unload":
		rationale = "A model unload was accepted; confirm the repository state, and reload if continued access is required."
		recs = append(recs, newWorkflowRecommendation(formatCommandExample(base+"models"), "Re-enumerate the model repository to confirm the model's load state changed.", false, 10))
		if known {
			recs = append(recs, newWorkflowRecommendation(formatCommandExample(base+"model-load --model "+m+" --force-exploit"), "Reload the model if continued access is required.", true, 20))
		}
	case "shm-probe":
		rationale = "Exposed shared-memory regions indicate the IPC chain surface; enumerate models to pair the regions with a loadable target."
		recs = append(recs, newWorkflowRecommendation(formatCommandExample(base+"models"), "Enumerate the model repository to pair shared-memory regions with a concrete model.", false, 10))
	default:
		return workflowPlan{}
	}
	if len(recs) == 0 {
		return workflowPlan{}
	}
	return workflowPlan{
		Target:          target,
		Stage:           "impact",
		ChainSource:     "triton-" + action,
		Rationale:       rationale,
		Recommendations: recs,
	}
}
