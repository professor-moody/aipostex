package main

import (
	"fmt"
	"strings"

	"github.com/professor-moody/aipostex/pkg/exploit/kubeflow"
)

// buildKFPipelinesWorkflowPlan turns a completed pipeline enumeration into
// concrete follow-on commands. The enum discovered real pipeline IDs, so the
// gated run-pipeline step names a discovered pipeline instead of emitting a
// "<pipeline-id>" placeholder. That gated step is only appended when a real
// pipeline ID is known — a placeholder run-pipeline command would be an
// unfinished-looking false lead, so we keep it honest by omitting it.
func buildKFPipelinesWorkflowPlan(target string, pipelines []kubeflow.Pipeline) workflowPlan {
	target = canonicalServiceURL(target)
	recs := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("kubeflow --target "+target+" runs"), "List existing pipeline runs and status.", false, 10),
		newWorkflowRecommendation(formatCommandExample("kubeflow --target "+target+" experiments"), "List experiments for run context.", false, 20),
	}
	// Thread the first discovered pipeline ID into the gated run-pipeline
	// follow-on so the command is concrete and copyable. If no pipeline carries
	// a usable ID, leave the gated step out rather than emit a placeholder.
	if id := shellSafeArg(firstKFPipelineID(pipelines)); id != "" {
		cmd := fmt.Sprintf("kubeflow --target %s run-pipeline --pipeline-id %s --run-name injected --force-exploit", target, id)
		recs = append(recs, newWorkflowRecommendation(formatCommandExample(cmd), "Create a new pipeline run only with engagement approval.", true, 30))
	}
	return workflowPlan{
		Target:          target,
		Stage:           "pipelines",
		Rationale:       "Pipeline IDs are now known, so run history and gated run creation can use a concrete pipeline target.",
		Recommendations: recs,
	}
}

// firstKFPipelineID returns the ID of the first pipeline that carries one.
// That ID is a known, real run-pipeline target, so the gated follow-on is
// concrete rather than a "<pipeline-id>" placeholder.
func firstKFPipelineID(pipelines []kubeflow.Pipeline) string {
	ids := make([]string, 0, len(pipelines))
	for _, p := range pipelines {
		ids = append(ids, p.ID)
	}
	return firstNonPlaceholder(ids)
}

// buildKFExploitWorkflowPlan emits follow-ons for the kubeflow enumeration and run
// verbs, chaining each to an existing verb that deepens what it found. anchor is the
// case-relevant discovered identifier: a pipeline ID (runs) or a notebook server URL
// (notebooks). Gated steps are only emitted with a concrete anchor, so a
// --force-exploit command never carries a placeholder.
func buildKFExploitWorkflowPlan(target, action, anchor string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "kubeflow --target " + target + " "
	var rationale string
	var recs []workflowRecommendation
	switch action {
	case "runs":
		rationale = "Enumerated runs expose pipeline IDs and status; list experiments and pipelines, and with a known pipeline ID create a gated run."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"experiments"), "List experiments to correlate runs with their experiment context.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"pipelines"), "List pipeline definitions to map runnable targets.", false, 20),
		}
		if id := shellSafeArg(anchor); anchor != "" {
			recs = append(recs, newWorkflowRecommendation(formatCommandExample(base+"run-pipeline --pipeline-id "+id+" --run-name injected --force-exploit"), "Create a new pipeline run from a discovered pipeline ID (engagement approval only).", true, 30))
		}
	case "experiments":
		rationale = "Enumerated experiments provide run context; pivot into run and pipeline enumeration."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"runs"), "List pipeline runs and recover run/pipeline IDs.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"pipelines"), "List pipeline definitions for run creation.", false, 20),
		}
	case "notebooks":
		rationale = "A discovered Kubeflow notebook server is a Jupyter surface; pivot the aipostex jupyter module at its URL to enumerate and gain a kernel."
		if url := shellSafeArg(anchor); anchor != "" && strings.HasPrefix(strings.ToLower(anchor), "http") {
			recs = append(recs,
				newWorkflowRecommendation(formatCommandExample("jupyter --target "+url+" enum"), "Enumerate the notebook's Jupyter server (sessions, kernels, notebooks).", false, 10),
				newWorkflowRecommendation(formatCommandExample("jupyter --target "+url+" start-kernel --force-exploit"), "Start a kernel on the notebook server to enable code execution.", true, 20),
			)
		}
		recs = append(recs, newWorkflowRecommendation(formatCommandExample(base+"runs"), "Continue mapping the Kubeflow surface via run enumeration.", false, 30))
	case "run-pipeline":
		rationale = "A pipeline run was created; confirm it appears and progresses in the run history."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"runs"), "List runs to confirm the injected run appears and track its status.", false, 10),
		}
	default:
		return workflowPlan{}
	}
	if len(recs) == 0 {
		return workflowPlan{}
	}
	return workflowPlan{
		Target:          target,
		Stage:           "impact",
		ChainSource:     "kubeflow-" + action,
		Rationale:       rationale,
		Recommendations: recs,
	}
}
