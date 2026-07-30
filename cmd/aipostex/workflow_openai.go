package main

import (
	"fmt"
	"strings"

	openaicompat "github.com/professor-moody/aipostex/pkg/exploit/openaicompat"
)

// buildOpenAICompatInferenceWorkflowPlan chains confirmed unauthenticated inference
// (generate / proxy-test) into the LLM-abuse follow-ons on the same model: prompt
// injection, system-prompt / tool disclosure. --model is threaded; --prompt is
// generate-only, so the follow-ons rely on each verb's built-in probes.
func buildOpenAICompatInferenceWorkflowPlan(target, model string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "openai-compat --target " + target + " "
	mArg := ""
	if model != "" {
		mArg = " --model " + shellSafeArg(model)
	}
	return workflowPlan{
		Target:      target,
		Stage:       "impact",
		Landed:      "influenced",
		ChainSource: "openai-compat-inference",
		Rationale:   "Unauthenticated inference works; exercise the model for prompt-injection and system-prompt / tool disclosure.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"prompt-test"+mArg), "Test prompt-injection susceptibility with the built-in probes.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"prompt-extract"+mArg+" --force-exploit"), "Attempt to extract the system prompt / hidden instructions.", true, 20),
			newWorkflowRecommendation(formatCommandExample(base+"tool-enum"+mArg+" --force-exploit"), "Enumerate any exposed tools / function-calling surface.", true, 30),
		},
	}
}

func buildOpenAICompatEnumWorkflowPlan(target string, models []string, highValueModels []string) workflowPlan {
	target = canonicalServiceURL(target)
	model := shellSafeArg(preferredOpenAICompatValidationModel(models, "<model>"))
	recommendations := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" auth-sweep"), "Classify weak-auth acceptance patterns before higher-noise validation.", false, 10),
		newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" validate-inference --model "+model), "Confirm the model returns coherent output.", false, 20),
		newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" prompt-extract --model "+model), "Attempt bounded prompt extraction after model discovery.", false, 30),
		newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" tool-enum --model "+model), "Enumerate function/tool calling capabilities and test for tool injection.", false, 35),
		newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" prompt-test --model "+model), "Probe prompt injection resistance with bounded read-only system and jailbreak tests.", false, 38),
		newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" generate --model "+model+" --prompt \"Hello\" --force-exploit"), "Only after validation confirms prompt-sensitive model behavior.", true, 39),
	}
	if len(highValueModels) > 0 {
		highModel := shellSafeArg(firstOrPlaceholder(highValueModels, model))
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" throughput --model "+highModel+" --requests 5 --concurrency 2 --force-exploit"), "Only after a high-value model is confirmed and noise is acceptable.", true, 40),
			newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" proxy-test --model "+highModel+" --force-exploit"), "Only after read-only validation confirms a useful model.", true, 50),
		)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "enum",
		Rationale:       "Use discovered models to move from inventory into validation, then opt-in higher-noise proofs.",
		Recommendations: recommendations,
	}
}

func buildOpenAICompatAuthWorkflowPlan(target, model, acceptanceClass string, weakPatterns []string) workflowPlan {
	target = canonicalServiceURL(target)
	model = shellSafeArg(preferredOpenAICompatValidationModel([]string{model}, "<model>"))
	rationale := "Use the accepted auth pattern classification to move into concrete model validation."
	if len(weakPatterns) > 0 {
		rationale = fmt.Sprintf("Accepted weak auth patterns: %s.", strings.Join(uniqueSortedStrings(weakPatterns), ", "))
	}
	if acceptanceClass == "rejected" {
		return workflowPlan{
			Target:    target,
			Stage:     "auth-sweep",
			Rationale: "OpenAI-compatible inventory and inference checks were rejected; no OpenAI-compatible follow-on command is recommended for this target.",
		}
	}
	recommendations := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" enum"), "Capture normalized model inventory after the weak-auth sweep.", false, 10),
		newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" validate-inference --model "+model), "Validate usable inference on the best discovered model.", false, 20),
	}
	if acceptanceClass == "inference-capable" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" generate --model "+model+" --prompt \"Hello\" --force-exploit"), "Only after validation confirms prompt-sensitive model behavior.", true, 30),
			newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" throughput --model "+model+" --requests 5 --concurrency 2 --force-exploit"), "Only after confirming the endpoint is useful and noise is acceptable.", true, 40),
			newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" proxy-test --model "+model+" --force-exploit"), "Only after bounded validation confirms proxy usefulness.", true, 50),
		)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "auth-sweep",
		Rationale:       rationale,
		Recommendations: recommendations,
	}
}

func preferredOpenAICompatValidationModel(models []string, fallback string) string {
	ordered := make([]string, 0, len(models))
	seen := map[string]struct{}{}
	for _, model := range models {
		model = strings.TrimSpace(model)
		if model == "" {
			continue
		}
		if _, ok := seen[model]; ok {
			continue
		}
		seen[model] = struct{}{}
		ordered = append(ordered, model)
	}
	if len(ordered) == 0 {
		return fallback
	}
	for _, contains := range []string{
		"local-smollm",
		"local",
		"smollm",
		"llama",
		"mistral",
		"qwen",
		"phi",
		"ollama",
	} {
		for _, model := range ordered {
			if strings.Contains(strings.ToLower(model), contains) {
				return model
			}
		}
	}
	return ordered[0]
}

func preferredOpenAICompatAuthFollowOnModel(result *openaicompat.AuthSweepResult, explicitModel string) string {
	explicitModel = strings.TrimSpace(explicitModel)
	if explicitModel != "" {
		return explicitModel
	}
	if result == nil {
		return "<model>"
	}
	var candidates []string
	for _, pattern := range result.AcceptedPatterns {
		for _, attempt := range pattern.ModelAttempts {
			if attempt.Success {
				candidates = append(candidates, attempt.Model)
			}
		}
	}
	if len(candidates) > 0 {
		return preferredOpenAICompatValidationModel(candidates, result.BestModel)
	}
	for _, pattern := range result.AcceptedPatterns {
		for _, attempt := range pattern.ModelAttempts {
			candidates = append(candidates, attempt.Model)
		}
		if strings.TrimSpace(pattern.Model) != "" {
			candidates = append(candidates, pattern.Model)
		}
	}
	return preferredOpenAICompatValidationModel(candidates, firstOrPlaceholder([]string{result.BestModel}, "<model>"))
}

func buildOpenAICompatBackendFailureWorkflowPlan(target, model, apiKey string) workflowPlan {
	target = canonicalServiceURL(target)
	model = shellSafeArg(firstOrPlaceholder([]string{model}, "<model>"))
	plan := workflowPlan{
		Target:    target,
		Stage:     "backend-failure-triage",
		Rationale: "Inventory was reachable, but inference failed due backend errors; inspect proxy/provider wiring before repeating validation.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" litellm-probe"), "Probe LiteLLM health, readiness, and model-info for backend dependency or provider configuration failures.", false, 10),
			newWorkflowRecommendation(formatCommandExample("litellm --target "+target+" proxy-chain"), "Trace model aliases to backend providers and identify broken routes.", false, 20),
			newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" validate-inference --model "+model), "Retry inference only after backend dependency/configuration issues are understood.", false, 30),
		},
	}
	return injectOpenAICompatAPIKeyIntoPlan(plan, apiKey)
}

func injectOpenAICompatAPIKeyIntoPlan(plan workflowPlan, apiKey string) workflowPlan {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return plan
	}
	for i, rec := range plan.Recommendations {
		if strings.Contains(rec.Command, "openai-compat") && !strings.Contains(rec.Command, "--api-key") {
			rec.Command = insertFlagBeforeSubcommand(rec.Command, "--api-key "+shellSafeArg(apiKey))
			plan.Recommendations[i] = rec
		}
	}
	return plan
}

func authSweepAllInferenceFailuresAreBackend(patterns []openaicompat.AuthSweepPattern) bool {
	sawFailure := false
	for _, pattern := range patterns {
		if !pattern.AcceptedInventory || pattern.AcceptedInference || len(pattern.ModelAttempts) == 0 {
			continue
		}
		for _, attempt := range pattern.ModelAttempts {
			if attempt.Success {
				return false
			}
			sawFailure = true
			switch attempt.FailureClass {
			case "backend-dependency-missing", "backend-config-error", "model-route-error", "server-error":
				continue
			default:
				return false
			}
		}
	}
	return sawFailure
}

func uniqueFailureClassesFromAttempts(attempts []openaicompat.ModelAttempt) []string {
	var classes []string
	seen := map[string]struct{}{}
	for _, attempt := range attempts {
		if strings.TrimSpace(attempt.FailureClass) == "" {
			continue
		}
		if _, ok := seen[attempt.FailureClass]; ok {
			continue
		}
		seen[attempt.FailureClass] = struct{}{}
		classes = append(classes, attempt.FailureClass)
	}
	return uniqueSortedStrings(classes)
}
