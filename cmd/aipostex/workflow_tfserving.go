package main

// buildTFServingEnumWorkflowPlan turns a completed TF Serving enum into follow-on
// commands. Enumerate() only proves reachability — it returns no model names (TF
// Serving has no list endpoint), so the model-scoped metadata/predict steps cannot
// carry a concrete name here. They are worded to read as a value the operator
// supplies once `models` discovers it, rather than a bare "<name>" TODO token, and
// the predict exploit step is only appended once a name is known (never here).
func buildTFServingEnumWorkflowPlan(target string) workflowPlan {
	target = canonicalServiceURL(target)
	return workflowPlan{
		Target:    target,
		Stage:     "enum",
		Rationale: "Server discovery should flow into model enumeration, signature extraction, and inference testing.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" models"), "Probe for served model names.", false, 10),
			newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" metadata --model <a-discovered-model>"), "Once `models` names one, extract its signature definitions and tensor specs.", false, 20),
			newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" metrics"), "Extract Prometheus metrics.", false, 30),
		},
	}
}

// buildTFServingModelsWorkflowPlan turns discovered model names into concrete
// follow-on commands. The `models` probe resolved real names, so metadata/predict
// name a discovered model instead of a "<name>" placeholder. The predict exploit
// step is only appended when a name is actually known — a gated command carrying a
// placeholder would be a false lead.
func buildTFServingModelsWorkflowPlan(target string, modelNames []string) workflowPlan {
	target = canonicalServiceURL(target)
	model := shellSafeArg(firstOrPlaceholder(modelNames, "<a-discovered-model>"))

	recs := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" metadata --model "+model), "Extract the discovered model's signature definitions and tensor specs.", false, 10),
	}
	// Only guard the active inference exploit behind a known model name — never
	// emit a --force-exploit command carrying a placeholder.
	if model != "<a-discovered-model>" {
		recs = append(recs,
			newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" predict --model "+model+" --payload '{\"instances\":[]}' --force-exploit"), "Only after metadata confirms the input signature: test unauthenticated inference.", true, 20),
		)
	}

	return workflowPlan{
		Target:          target,
		Stage:           "models",
		Rationale:       "Discovered model names anchor signature extraction and bounded inference testing.",
		Recommendations: recs,
	}
}

func buildTFServingMetadataWorkflowPlan(target, model, payload string) workflowPlan {
	target = canonicalServiceURL(target)
	modelArg := shellSafeArg(model)
	payloadArg := shellSafeArg(payload)
	return workflowPlan{
		Target:    target,
		Stage:     "metadata",
		Rationale: "Signature metadata supplies a concrete, shape-aware prediction payload.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(
				formatCommandExample("tfserving --target "+target+" predict --model "+modelArg+" --payload "+payloadArg+" --force-exploit"),
				"Use the disclosed signature shape to verify input-dependent inference.",
				true,
				10,
			),
		},
	}
}

// buildTFServingPredictWorkflowPlan chains a completed inference test back into
// deeper signature extraction on the same model and enumeration of other served
// models, so an inference finding is never a dead end. All follow-ons are read-only.
func buildTFServingPredictWorkflowPlan(target, model string) workflowPlan {
	target = canonicalServiceURL(target)
	modelArg := shellSafeArg(model)
	return workflowPlan{
		Target:    target,
		Stage:     "impact",
		Rationale: "A reachable inference endpoint should flow into deeper signature extraction and enumeration of other served models.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" metadata --model "+modelArg), "Re-read the model signature to craft richer, shape-valid inference inputs.", false, 10),
			newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" models"), "Probe for other served model names to broaden the inference surface.", false, 20),
			newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" metrics"), "Extract Prometheus metrics for request volumes and served-model telemetry.", false, 30),
		},
	}
}

// buildTFServingMetricsWorkflowPlan turns an exposed metrics endpoint into model
// enumeration and signature disclosure. The model-scoped step carries a supplied-
// value token (not a gated command), consistent with the enum plan.
func buildTFServingMetricsWorkflowPlan(target string) workflowPlan {
	target = canonicalServiceURL(target)
	return workflowPlan{
		Target:    target,
		Stage:     "recon",
		Rationale: "An exposed metrics endpoint confirms reachability; pivot into model enumeration and signature disclosure.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" models"), "Probe for served model names.", false, 10),
			newWorkflowRecommendation(formatCommandExample("tfserving --target "+target+" metadata --model <a-discovered-model>"), "Once `models` names one, extract its signature definitions and tensor specs.", false, 20),
		},
	}
}
