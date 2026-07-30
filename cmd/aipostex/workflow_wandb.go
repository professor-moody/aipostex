package main

func buildWandBEnumWorkflowPlan(target, entity, project string) workflowPlan {
	target = canonicalServiceURL(target)
	// The viewer identity (username/team) surfaced by enum is a real W&B entity,
	// so thread it in when the caller resolved one; only fall back to a
	// supply-a-value token otherwise.
	entity = shellSafeArg(firstOrPlaceholder([]string{entity}, "<a-discovered-entity>"))
	// enum does not learn a project name, so this stays a parameter to supply.
	project = shellSafeArg(firstOrPlaceholder([]string{project}, "<a-listed-project>"))

	return workflowPlan{
		Target:    target,
		Stage:     "enumeration",
		Rationale: "W&B metadata is reachable; enumerate projects, runs, artifacts, and run config secrets to map exposed experiment data.",
		Landed:    "reachable",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("wandb --target "+target+" projects --entity "+entity), "List accessible projects for the discovered entity.", false, 10),
			newWorkflowRecommendation(formatCommandExample("wandb --target "+target+" runs --entity "+entity+" --project "+project), "Enumerate runs and recover run IDs for follow-on inspection.", false, 20),
			newWorkflowRecommendation(formatCommandExample("wandb --target "+target+" artifacts --entity "+entity+" --project "+project), "List model and dataset artifacts exposed through the W&B API.", false, 30),
			newWorkflowRecommendation(formatCommandExample("wandb --target "+target+" secrets --entity "+entity+" --project "+project), "Scan run configs and summaries for embedded credentials.", false, 40),
			newWorkflowRecommendation(formatCommandExample("scan targets --target "+target+" --tags wandb --mode detect"), "Run bundled W&B templates against the same endpoint.", false, 50),
		},
	}
}

// buildWandBExploitWorkflowPlan emits follow-ons for the wandb enumeration/loot
// verbs, chaining each to an existing verb that deepens what it found. entity is a
// concrete W&B entity (always known for these verbs); project is a discovered/known
// project name, falling back to a supply-a-value token in a read-only command (never
// a gated one). All wandb follow-ons are read-only.
func buildWandBExploitWorkflowPlan(target, action, entity, project string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "wandb --target " + target + " "
	e := shellSafeArg(firstOrPlaceholder([]string{entity}, "<a-discovered-entity>"))
	p := shellSafeArg(firstOrPlaceholder([]string{project}, "<a-listed-project>"))
	scope := " --entity " + e + " --project " + p
	var rationale string
	var recs []workflowRecommendation
	switch action {
	case "projects":
		rationale = "Discovered projects anchor run enumeration, artifact listing, and run-config secret scanning."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"runs"+scope), "Enumerate runs and recover run IDs for the discovered project.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"artifacts"+scope), "List model and dataset artifacts in the project.", false, 20),
			newWorkflowRecommendation(formatCommandExample(base+"secrets"+scope), "Scan run configs and summaries for embedded credentials.", false, 30),
		}
	case "runs":
		rationale = "Recovered run IDs anchor run-config secret scanning and artifact enumeration."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"secrets"+scope), "Scan the enumerated runs' configs and summaries for embedded credentials.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"artifacts"+scope), "List model and dataset artifacts for the same project.", false, 20),
		}
	case "artifacts":
		rationale = "Exposed artifacts confirm project data access; scan run configs for credentials to broaden the loot."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"secrets"+scope), "Scan run configs and summaries for embedded credentials.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"runs"+scope), "Enumerate runs to correlate artifacts with their producing runs.", false, 20),
		}
	case "secrets":
		rationale = "Run-config secrets were recovered; surface the looted credentials and continue mapping exposed project data."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("report view <dossier-dir> --credentials"), "Review the extracted run-config credentials (raw or as a table) from your accumulating engagement dossier — save runs with --format dossier -o <dir>.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"artifacts"+scope), "List artifacts to pair recovered credentials with model/dataset assets.", false, 20),
		}
	default:
		return workflowPlan{}
	}
	return workflowPlan{
		Target:          target,
		Stage:           "impact",
		ChainSource:     "wandb-" + action,
		Rationale:       rationale,
		Recommendations: recs,
	}
}
