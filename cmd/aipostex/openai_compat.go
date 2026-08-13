package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/inferenceprobe"
	"github.com/professor-moody/aipostex/internal/modelfingerprint"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	openaicompat "github.com/professor-moody/aipostex/pkg/exploit/openaicompat"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	openAICompatTarget      string
	openAICompatHeaders     []string
	openAICompatAPIKey      string
	openAICompatModel       string
	openAICompatPrompt      string
	openAICompatMaxTokens   int
	openAICompatRequests    int
	openAICompatConcurrency int
	openAICompatFPContext   bool
)

var openAICompatCmd = &cobra.Command{
	Use:   "openai-compat",
	Short: "Enumerate and validate generic OpenAI-compatible inference endpoints",
	Long: `Enumerate generic OpenAI-compatible inference endpoints, classify weak-auth acceptance,
validate whether inference is truly usable, attempt bounded prompt extraction, and run opt-in
higher-noise throughput or proxy validation.`,
	Example: strings.Join([]string{
		formatCommandExample("openai-compat --target http://127.0.0.1:8000 auth-sweep"),
		formatCommandExample("openai-compat --target http://127.0.0.1:8000 enum"),
		formatCommandExample("openai-compat --target http://127.0.0.1:8000 validate-inference --model llama3"),
		formatCommandExample("openai-compat --target http://127.0.0.1:8000 generate --model llama3 --prompt \"Hello\" --force-exploit"),
		formatCommandExample("openai-compat --target http://127.0.0.1:8000 prompt-test --model llama3"),
		formatCommandExample("openai-compat --target http://127.0.0.1:8000 throughput --model llama3 --requests 5 --concurrency 2 --force-exploit"),
	}, "\n"),
}

var openAICompatAuthSweepCmd = &cobra.Command{
	Use:   "auth-sweep",
	Short: "Classify weak-auth acceptance on the endpoint",
	Long: `Classify how the endpoint responds to weak or absent authentication.

OpenAI-compatible servers are frequently deployed with authentication disabled,
left at a default key, or accepting any bearer token. This sweeps those cases and
classifies which one is true, which decides whether the inference surface is
open to anyone who can reach it.

This is a read-only probing operation.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 auth-sweep"),
	RunE:    runOpenAICompatAuthSweep,
}

var openAICompatEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate exposed models and normalized model metadata",
	Long: `List the models the endpoint exposes, with normalized metadata.

Model ids are the currency of an OpenAI-compatible API — every later request
names one. Normalizing across implementations (vLLM, LiteLLM, llama.cpp, and
others) means the same enumeration works regardless of what is actually serving.

This is a read-only probing operation.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 enum"),
	RunE:    runOpenAICompatEnum,
}

var openAICompatValidateCmd = &cobra.Command{
	Use:   "validate-inference",
	Short: "Validate that the endpoint returns coherent inference output",
	Long: `Verify the endpoint returns coherent, input-dependent inference.

A 200 response is not proof of a working model: gateways return canned text,
stubs echo, and dead backends still answer. This sends a second, distinct prompt
and requires a distinct completion, so generation is only claimed when output
actually depends on input. An honest negative is reported when it does not.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 validate-inference --model llama3"),
	RunE:    runOpenAICompatValidateInference,
}

var openAICompatPromptExtractCmd = &cobra.Command{
	Use:   "prompt-extract",
	Short: "Run a bounded hidden-instruction extraction attempt",
	Long: `Run a bounded attempt to extract the endpoint's hidden system instructions.

If the deployment injects a system prompt, that prompt is the application's
private configuration — its rules, its persona, and sometimes its internal
context and keys. Recovering it is both a disclosure in itself and the map for
targeted injection afterwards.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 prompt-extract --model llama3"),
	RunE:    runOpenAICompatPromptExtract,
}

var openAICompatThroughputCmd = &cobra.Command{
	Use:   "throughput",
	Short: "Measure bounded inference throughput",
	Long: `Measure bounded inference throughput with explicit request and concurrency limits.

This is a higher-noise exploit action and requires --force-exploit.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 throughput --model llama3 --requests 5 --concurrency 2 --force-exploit"),
	RunE:    runOpenAICompatThroughput,
}

var openAICompatProxyTestCmd = &cobra.Command{
	Use:   "proxy-test",
	Short: "Prove the endpoint can proxy inference",
	Long: `Prove the endpoint can act as an inference proxy by sending a bounded test prompt and capturing the returned response.

This is a higher-noise exploit action and requires --force-exploit.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 proxy-test --model llama3 --force-exploit"),
	RunE:    runOpenAICompatProxyTest,
}

var openAICompatGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Send an operator-supplied prompt to an OpenAI-compatible model",
	Long: `Send an operator-supplied prompt through an OpenAI-compatible chat/completions
endpoint and capture the returned response.

This is a higher-noise exploit action and requires --force-exploit.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 generate --model llama3 --prompt \"Hello\" --force-exploit"),
	RunE:    runOpenAICompatGenerate,
}

var openAICompatToolEnumCmd = &cobra.Command{
	Use:   "tool-enum",
	Short: "Enumerate function/tool calling capabilities and test for tool injection",
	Long: `Probe whether the endpoint supports OpenAI-style function calling (tools parameter),
test if attacker-defined tool schemas are accepted, and check if forced tool invocation
bypasses guardrails. All probes are read-only chat completions.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 tool-enum --model llama3"),
	RunE:    runOpenAICompatToolEnum,
}

var openAICompatPromptTestCmd = &cobra.Command{
	Use:   "prompt-test",
	Short: "Probe prompt injection and jailbreak resistance with read-only prompts",
	Long: `Run bounded prompt injection probes against a model using standard chat completions.
The command tests instruction override, role confusion, delimiter escape, jailbreak,
and refusal-bypass heuristics without mutating target state.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 prompt-test --model llama3"),
	RunE:    runOpenAICompatPromptTest,
}

var openAICompatLiteLLMProbeCmd = &cobra.Command{
	Use:   "litellm-probe",
	Short: "Probe LiteLLM-specific health, readiness, and model-info endpoints",
	Long: `Probe the LiteLLM-specific health, readiness, and model-info endpoints.

Confirms whether an OpenAI-compatible front end is actually LiteLLM, and pulls
the proxy-specific detail those endpoints expose — backend topology and, in
misconfigured deployments, upstream provider credentials.

This is a read-only probing operation.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:4000 litellm-probe"),
	RunE:    runOpenAICompatLiteLLMProbe,
}

var openAICompatFingerprintCmd = &cobra.Command{
	Use:   "fingerprint",
	Short: "Behaviorally fingerprint the underlying model family (identity, contradiction, knowledge-cutoff)",
	Long: `Infer the underlying model family behind the endpoint through behavioral probing,
without trusting any self-reported name. Layers three independent read-only signals —
a direct identity probe, contradiction probes that assert a false vendor and watch for
the model's correction (which survives identity-masking system prompts), and a
knowledge-cutoff bracket from dated-event recall.

All probes are read-only chat completions. The optional --context-window probe is a
heavier needle-in-haystack test (multi-turn, sends filler to estimate the usable
context window) and is off by default.`,
	Example: formatCommandExample("openai-compat --target http://127.0.0.1:8000 fingerprint --model llama3"),
	RunE:    runOpenAICompatFingerprint,
}

func init() {
	openAICompatCmd.PersistentFlags().StringVarP(&openAICompatTarget, "target", "t", "", "OpenAI-compatible endpoint URL")
	openAICompatCmd.PersistentFlags().StringSliceVar(&openAICompatHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format")
	openAICompatCmd.PersistentFlags().StringVar(&openAICompatAPIKey, "api-key", "", "Bearer API key convenience flag")
	openAICompatCmd.PersistentFlags().StringVarP(&openAICompatModel, "model", "m", "", "Model ID (defaults to the best scored listed model)")

	openAICompatGenerateCmd.Flags().StringVar(&openAICompatPrompt, "prompt", "", "Text prompt to send (required)")
	openAICompatGenerateCmd.Flags().IntVar(&openAICompatMaxTokens, "max-tokens", 64, "Maximum tokens to generate")
	openAICompatThroughputCmd.Flags().IntVar(&openAICompatRequests, "requests", 0, "Number of bounded throughput requests to send")
	openAICompatThroughputCmd.Flags().IntVar(&openAICompatConcurrency, "concurrency", 0, "Concurrent workers for throughput probing")
	openAICompatFingerprintCmd.Flags().BoolVar(&openAICompatFPContext, "context-window", false, "Also run the heavier multi-turn context-window probe (sends filler)")

	openAICompatCmd.AddCommand(
		openAICompatAuthSweepCmd,
		openAICompatEnumCmd,
		openAICompatValidateCmd,
		openAICompatPromptExtractCmd,
		openAICompatToolEnumCmd,
		openAICompatPromptTestCmd,
		openAICompatGenerateCmd,
		openAICompatThroughputCmd,
		openAICompatProxyTestCmd,
		openAICompatLiteLLMProbeCmd,
		openAICompatFingerprintCmd,
	)
}

func runOpenAICompatAuthSweep(cmd *cobra.Command, args []string) error {
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	result, err := client.AuthSweep(openAICompatModel)
	if err != nil {
		return fmt.Errorf("running auth sweep: %w", err)
	}

	severity := report.SeverityInfo
	title := "Weak-auth sweep rejected"
	description := "No placeholder or weak auth patterns were accepted by the endpoint."
	switch result.Classification {
	case "inventory-only":
		severity = report.SeverityHigh
		title = "Weak-auth sweep exposed model inventory"
		description = "At least one placeholder or weak auth pattern exposed model inventory without confirming usable inference."
	case "inference-capable":
		severity = report.SeverityCritical
		title = "Weak-auth sweep confirmed unauthorized inference path"
		description = "At least one placeholder or weak auth pattern exposed inventory and bounded inference access."
	}

	labels := acceptedAuthLabels(result.AcceptedPatterns)
	mainFinding := newExploitFinding(
		report.SourceOpenAICompat,
		openAICompatTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":                 "openai-compat",
			"action":                 "auth-sweep",
			"mutating":               false,
			"provider":               "openai-compatible",
			"acceptance_class":       result.Classification,
			"accepted_patterns":      strings.Join(labels, ","),
			"accepted_pattern_count": len(labels),
			"model":                  result.BestModel,
			"model_attempts":         authSweepModelAttempts(result.AcceptedPatterns),
		},
	)
	followOnModel := preferredOpenAICompatAuthFollowOnModel(result, openAICompatModel)
	plan := injectOpenAICompatAPIKeyIntoPlan(
		buildOpenAICompatAuthWorkflowPlan(openAICompatTarget, followOnModel, result.Classification, labels),
		openAICompatAPIKey,
	)
	if result.Classification == "inventory-only" && authSweepAllInferenceFailuresAreBackend(result.AcceptedPatterns) {
		plan = buildOpenAICompatBackendFailureWorkflowPlan(openAICompatTarget, followOnModel, openAICompatAPIKey)
	}
	mainFinding.Metadata = attachWorkflowToMetadata(mainFinding.Metadata, plan)
	if result.Classification == "inference-capable" && result.BestModel != "" {
		mainFinding.Metadata["successful_model"] = result.BestModel
	}
	// Align the taxonomy with what the sweep actually proved: confirmed inference is a
	// landed impact (influenced); inventory-only exposure is a confirmed read.
	switch result.Classification {
	case "inference-capable":
		mainFinding.Metadata = applyStageLanded(mainFinding.Metadata, "impact", "influenced", "openai-compat-auth-sweep", "inference")
	case "inventory-only":
		mainFinding.Metadata = applyStageLanded(mainFinding.Metadata, "access", "read-confirmed", "openai-compat-auth-sweep", "inventory")
	}
	var patternLines []string
	for _, p := range result.AcceptedPatterns {
		patternLines = append(patternLines, fmt.Sprintf("%s: inventory=%t inference=%t model=%s failure_class=%s",
			p.Label, p.AcceptedInventory, p.AcceptedInference, p.Model, p.FailureClass))
	}
	mainFinding.Evidence = fmt.Sprintf("classification=%s best_model=%s\n%s",
		result.Classification, result.BestModel, strings.Join(patternLines, "\n"))

	findings := []report.Finding{mainFinding}
	for _, pattern := range result.AcceptedPatterns {
		if !pattern.AcceptedInventory && !pattern.AcceptedInference {
			continue
		}
		title := fmt.Sprintf("Weak auth accepted: %s", pattern.Label)
		description := fmt.Sprintf("Pattern %s exposed inventory=%t inference=%t", pattern.Label, pattern.AcceptedInventory, pattern.AcceptedInference)
		if pattern.Label == "provided-authorization" {
			title = "Provided authorization accepted"
			description = fmt.Sprintf("The supplied bearer credential exposed inventory=%t inference=%t", pattern.AcceptedInventory, pattern.AcceptedInference)
		}
		finding := newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			title,
			report.SeverityHigh,
			description,
			map[string]interface{}{
				"module":           "openai-compat",
				"action":           "auth-sweep",
				"mutating":         false,
				"provider":         "openai-compatible",
				"auth_pattern":     pattern.Label,
				"inventory_access": pattern.AcceptedInventory,
				"inference_access": pattern.AcceptedInference,
				"model":            pattern.Model,
				"acceptance_class": result.Classification,
				"failure_class":    pattern.FailureClass,
				"model_attempts":   pattern.ModelAttempts,
			},
		)
		if pattern.AcceptedInference {
			finding.Metadata["successful_model"] = pattern.Model
		}
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
		finding.Evidence = fmt.Sprintf("pattern=%s\ninventory=%t\ninference=%t\nmodel=%s\nfailure=%s",
			pattern.Label, pattern.AcceptedInventory, pattern.AcceptedInference, pattern.Model, pattern.Failure)
		findings = append(findings, finding)
	}

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "openai-compat",
		Action:              "auth-sweep",
		ResourcesEnumerated: len(result.AcceptedPatterns),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runOpenAICompatEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	models, err := client.ListModels()
	if err != nil {
		return fmt.Errorf("listing models: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			"OpenAI-compatible endpoint enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated %d model(s) from the OpenAI-compatible endpoint", len(models)),
			map[string]interface{}{
				"module":      "openai-compat",
				"action":      "enum",
				"mutating":    false,
				"provider":    "openai-compatible",
				"headers":     headerNames(headers),
				"model_count": len(models),
			},
		),
	}
	modelNames := make([]string, 0, len(models))
	highValueModels := make([]string, 0)
	for _, model := range models {
		modelNames = append(modelNames, model.ID)
		if openaicompat.HighValueModel(model) {
			highValueModels = append(highValueModels, model.ID)
		}
	}
	summaryPlan := injectOpenAICompatAPIKeyIntoPlan(
		buildOpenAICompatEnumWorkflowPlan(openAICompatTarget, modelNames, highValueModels),
		openAICompatAPIKey,
	)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)

	for _, model := range models {
		metadata := map[string]interface{}{
			"module":            "openai-compat",
			"action":            "enum",
			"mutating":          false,
			"provider":          "openai-compatible",
			"model":             model.ID,
			"context":           model.ContextWindow,
			"parameters":        model.ParameterHint,
			"model_provider":    model.Provider,
			"modality":          model.Modality,
			"precision":         model.Precision,
			"instruction_tuned": model.InstructionTuned,
			"reasoning_capable": model.ReasoningCapable,
			"value_score":       model.ValueScore,
		}
		modelPlan := injectOpenAICompatAPIKeyIntoPlan(
			buildOpenAICompatEnumWorkflowPlan(openAICompatTarget, []string{model.ID}, highValueSlice(model)),
			openAICompatAPIKey,
		)
		// Only surface attributes the endpoint actually reported. A bare proxy
		// /v1/models lists model IDs without context/params/modality, so drop the
		// blank fields rather than print "context= parameters= modality=".
		attrParts := []string{"provider=" + safeLabel(model.Provider)}
		if model.ContextWindow != "" {
			attrParts = append(attrParts, "context="+model.ContextWindow)
		}
		if model.ParameterHint != "" {
			attrParts = append(attrParts, "parameters="+model.ParameterHint)
		}
		if model.Modality != "" {
			attrParts = append(attrParts, "modality="+model.Modality)
		}
		finding := newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			fmt.Sprintf("OpenAI-compatible model discovered: %s", model.ID),
			report.SeverityInfo,
			fmt.Sprintf("Model %s is exposed (%s)", model.ID, strings.Join(attrParts, ", ")),
			cloneMap(metadata),
		)
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, modelPlan)
		findings = append(findings, finding)
		if openaicompat.HighValueModel(model) {
			high := newExploitFinding(
				report.SourceOpenAICompat,
				openAICompatTarget,
				fmt.Sprintf("High-value model exposed: %s", model.ID),
				report.SeverityHigh,
				fmt.Sprintf("Exposed model %s scored %d/100 for resale or LLMjacking value.", model.ID, model.ValueScore),
				cloneMap(metadata),
			)
			high.Metadata = attachWorkflowToMetadata(high.Metadata, modelPlan)
			evParts := []string{
				"model=" + model.ID,
				fmt.Sprintf("value_score=%d", model.ValueScore),
				"provider=" + model.Provider,
			}
			if model.ContextWindow != "" {
				evParts = append(evParts, "context="+model.ContextWindow)
			}
			if model.ParameterHint != "" {
				evParts = append(evParts, "parameters="+model.ParameterHint)
			}
			if model.Modality != "" {
				evParts = append(evParts, "modality="+model.Modality)
			}
			evParts = append(evParts,
				fmt.Sprintf("reasoning=%t", model.ReasoningCapable),
				fmt.Sprintf("instruction_tuned=%t", model.InstructionTuned),
			)
			high.Evidence = strings.Join(evParts, "\n")
			findings = append(findings, high)
		}
	}

	infof("Enumerated %d OpenAI-compatible model(s)", len(models))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "openai-compat",
		Action:              "enum",
		ResourcesEnumerated: len(models),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

// normalizeInferenceText lowercases and collapses whitespace so two model completions
// can be compared for the input-differential inference check (validate-inference).
func normalizeInferenceText(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func runOpenAICompatValidateInference(cmd *cobra.Command, args []string) error {
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	result, err := client.ValidateInference(openAICompatModel)
	if err != nil {
		var validationErr *openaicompat.InferenceValidationError
		if errors.As(err, &validationErr) {
			return writeOpenAICompatValidationFailure(validationErr)
		}
		return fmt.Errorf("validating inference: %w", err)
	}

	severity := report.SeverityMedium
	stage, landed := "recon", "reachable"
	inputDependent := false
	title := fmt.Sprintf("Inference responded on %s", result.Model)
	description := fmt.Sprintf("Endpoint returned a response from model %s with coherence score %d/100 (%s)", result.Model, result.CoherenceScore, result.CoherenceReason)
	if result.Coherent {
		severity = report.SeverityHigh
		// Input-differential check: a distinct second prompt must produce a distinct
		// completion. A canned fixture returns identical output for any input, so only a
		// differing completion earns execution-confirmed; an otherwise-coherent response
		// that cannot be told apart from a fixture is graded influenced (inference ran,
		// input-dependence unproven) — matching the serving modules' reality probe.
		if second, serr := client.Ask(result.Model, "Reply with a random primary color followed by a random two-digit number, e.g. 'green 47'."); serr == nil {
			a := normalizeInferenceText(second)
			inputDependent = a != "" && a != normalizeInferenceText(result.Response)
		}
		if inputDependent {
			stage, landed = "impact", "execution-confirmed"
			title = fmt.Sprintf("Coherent, input-dependent inference confirmed on %s", result.Model)
			description = fmt.Sprintf("Endpoint returned coherent inference from model %s in %s (score %d/100), and a distinct prompt produced a distinct completion — the model executes inference on the supplied input, not a canned fixture.", result.Model, result.Latency, result.CoherenceScore)
		} else {
			stage, landed = "impact", "influenced"
			title = fmt.Sprintf("Coherent inference validated on %s (input-dependence unconfirmed)", result.Model)
			description = fmt.Sprintf("Endpoint returned coherent inference from model %s in %s (score %d/100), but a distinct prompt did not yield a distinguishable completion — inference could not be told apart from a canned fixture (influenced, not execution-confirmed).", result.Model, result.Latency, result.CoherenceScore)
		}
	}

	finding := newExploitFinding(
		report.SourceOpenAICompat,
		openAICompatTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":             "openai-compat",
			"action":             "validate-inference",
			"mutating":           false,
			"provider":           "openai-compatible",
			"model":              result.Model,
			"latency_ms":         result.Latency.Milliseconds(),
			"coherence_score":    result.CoherenceScore,
			"coherence_reason":   result.CoherenceReason,
			"inference_verified": inputDependent,
			"model_attempts":     result.ModelAttempts,
		},
	)
	finding.Evidence = result.Response
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "openai-compat-validate-inference", "model")
	plan := suppressWorkflowCommands(
		injectOpenAICompatAPIKeyIntoPlan(
			buildOpenAICompatEnumWorkflowPlan(openAICompatTarget, []string{result.Model}, []string{result.Model}),
			openAICompatAPIKey,
		),
		formatCommandExample("openai-compat --target "+openAICompatTarget+" validate-inference --model "+result.Model),
	)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "openai-compat",
		Action:              "validate-inference",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func writeOpenAICompatValidationFailure(validationErr *openaicompat.InferenceValidationError) error {
	attempts := validationErr.Attempts
	model := ""
	if len(attempts) > 0 {
		model = attempts[0].Model
	}
	failureClasses := uniqueFailureClassesFromAttempts(attempts)
	plan := buildOpenAICompatBackendFailureWorkflowPlan(openAICompatTarget, model, openAICompatAPIKey)
	finding := newExploitFinding(
		report.SourceOpenAICompat,
		openAICompatTarget,
		"OpenAI-compatible inference validation failed",
		report.SeverityMedium,
		fmt.Sprintf("Inference validation failed across %d attempted model(s). Review backend failure classes before treating this as non-exposure.", len(attempts)),
		map[string]interface{}{
			"module":          "openai-compat",
			"action":          "validate-inference",
			"mutating":        false,
			"provider":        "openai-compatible",
			"model":           model,
			"model_attempts":  attempts,
			"failure_classes": strings.Join(failureClasses, ","),
		},
	)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	var lines []string
	for _, attempt := range attempts {
		lines = append(lines, fmt.Sprintf("model=%s success=%t failure_class=%s failure=%s",
			attempt.Model, attempt.Success, attempt.FailureClass, attempt.Failure))
	}
	finding.Evidence = strings.Join(lines, "\n")
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "openai-compat",
		Action:              "validate-inference",
		ResourcesEnumerated: len(attempts),
		PartialFailures:     len(attempts),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runOpenAICompatPromptExtract(cmd *cobra.Command, args []string) error {
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	result, err := client.PromptExtract(openAICompatModel)
	if err != nil {
		return fmt.Errorf("running prompt extraction: %w", err)
	}

	severity := report.SeverityInfo
	title := fmt.Sprintf("Prompt extraction inconclusive on %s", result.Model)
	description := fmt.Sprintf("Prompt extraction classification=%s after %d bounded attempts.", result.Classification, result.AttemptCount)
	switch result.Classification {
	case "likely-hidden-instruction-leak":
		severity = report.SeverityHigh
		title = fmt.Sprintf("Likely system prompt extracted from %s", result.Model)
		description = fmt.Sprintf("The endpoint returned content matching hidden-instruction marker %q", result.MatchedMarker)
	case "generic-refusal":
		severity = report.SeverityMedium
		title = fmt.Sprintf("Prompt extraction refused on %s", result.Model)
	case "generic-assistant-response":
		severity = report.SeverityLow
		title = fmt.Sprintf("Prompt extraction returned generic assistant output on %s", result.Model)
	case "error":
		severity = report.SeverityInfo
		title = fmt.Sprintf("Prompt extraction failed on %s — all %d probes errored", result.Model, result.AttemptCount)
		description = fmt.Sprintf("All %d prompt-extraction probes returned errors; the check could not execute. Operator follow-up required.", result.AttemptCount)
	}

	finding := newExploitFinding(
		report.SourceOpenAICompat,
		openAICompatTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":                "openai-compat",
			"action":                "prompt-extract",
			"mutating":              false,
			"provider":              "openai-compatible",
			"model":                 result.Model,
			"prompt_classification": result.Classification,
			"matched_marker":        result.MatchedMarker,
			"attempt_count":         result.AttemptCount,
			"failed_attempts":       result.FailedAttempts,
		},
	)
	landed := "read-confirmed"
	if result.Classification == "error" {
		landed = "inconclusive"
	}
	finding.Metadata = applyStageLanded(finding.Metadata, "recon", landed, "openai-compat-prompt-extract", "prompt")
	finding.Evidence = result.Response
	plan := suppressWorkflowCommands(
		buildOpenAICompatEnumWorkflowPlan(openAICompatTarget, []string{result.Model}, nil),
		formatCommandExample("openai-compat --target "+openAICompatTarget+" prompt-extract --model "+result.Model),
	)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "openai-compat",
		Action:              "prompt-extract",
		ResourcesEnumerated: 1,
		PartialFailures:     result.FailedAttempts,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runOpenAICompatThroughput(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("openai-compat throughput"); err != nil {
		return err
	}
	if openAICompatRequests <= 0 {
		return missingFlagError("requests", formatCommandExample("openai-compat --target http://127.0.0.1:8000 throughput --model llama3 --requests 5 --concurrency 2 --force-exploit"))
	}
	if openAICompatConcurrency <= 0 {
		return missingFlagError("concurrency", formatCommandExample("openai-compat --target http://127.0.0.1:8000 throughput --model llama3 --requests 5 --concurrency 2 --force-exploit"))
	}
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	result, err := client.Throughput(openAICompatModel, openAICompatRequests, openAICompatConcurrency)
	if err != nil {
		return fmt.Errorf("measuring throughput: %w", err)
	}

	// Only claim inference when requests actually succeeded. 0/N successful is a probe
	// that landed nothing — reachable, not execution-confirmed; and a completed
	// throughput has no realness probe, so it is influenced (inference ran), not
	// execution-confirmed.
	severity := report.SeverityInfo
	stage, landed := "recon", "reachable"
	title := fmt.Sprintf("Inference throughput probe: no successful requests on %s", result.Model)
	if result.Successful > 0 {
		severity = report.SeverityMedium
		if result.UsefulnessScore >= 70 {
			severity = report.SeverityHigh
		}
		stage, landed = "impact", "influenced"
		title = fmt.Sprintf("Inference throughput measured on %s", result.Model)
	}
	finding := newExploitFinding(
		report.SourceOpenAICompat,
		openAICompatTarget,
		title,
		severity,
		fmt.Sprintf("Measured %d/%d successful requests against %s (avg=%s max=%s, success=%.0f%%, score=%d/100)", result.Successful, result.Requests, result.Model, result.AverageLatency, result.MaxLatency, result.SuccessRate*100, result.UsefulnessScore),
		map[string]interface{}{
			"module":            "openai-compat",
			"action":            "throughput",
			"mutating":          false,
			"provider":          "openai-compatible",
			"model":             result.Model,
			"requests":          result.Requests,
			"concurrency_limit": openAICompatConcurrency,
			"successful":        result.Successful,
			"failed":            result.Failed,
			"success_rate":      fmt.Sprintf("%.2f", result.SuccessRate),
			"rate_limit_signal": result.RateLimitSignal,
			"throughput_score":  result.UsefulnessScore,
		},
	)
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "openai-compat-throughput", "inference")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildOpenAICompatAuthWorkflowPlan(openAICompatTarget, result.Model, "inference-capable", nil))
	finding.Evidence = fmt.Sprintf("model=%s\nrequests=%d successful=%d failed=%d\nsuccess_rate=%.2f\navg_latency=%s max_latency=%s\nrate_limit_signal=%s\nusefulness_score=%d",
		result.Model, result.Requests, result.Successful, result.Failed, result.SuccessRate,
		result.AverageLatency, result.MaxLatency, result.RateLimitSignal, result.UsefulnessScore)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "openai-compat",
		Action:              "throughput",
		ResourcesEnumerated: result.Requests,
		PartialFailures:     result.Failed,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{buildOpenAICompatAuthWorkflowPlan(openAICompatTarget, result.Model, "inference-capable", nil)},
	})
}

func runOpenAICompatProxyTest(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("openai-compat proxy-test"); err != nil {
		return err
	}
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	result, err := client.ProxyTest(openAICompatModel)
	if err != nil {
		return fmt.Errorf("running proxy test: %w", err)
	}

	severity := report.SeverityMedium
	title := fmt.Sprintf("Proxy test returned weak validation on %s", result.Model)
	description := fmt.Sprintf("Endpoint returned a response for the proxy test, but validation score was only %d/100 (%s)", result.CoherenceScore, result.CoherenceReason)
	if result.Coherent {
		severity = report.SeverityHigh
		title = fmt.Sprintf("Inference proxy path validated on %s", result.Model)
		description = fmt.Sprintf("Endpoint returned the routed proxy-test prompt from model %s (score %d/100)", result.Model, result.CoherenceScore)
	}

	finding := newExploitFinding(
		report.SourceOpenAICompat,
		openAICompatTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":           "openai-compat",
			"action":           "proxy-test",
			"mutating":         true,
			"provider":         "openai-compatible",
			"model":            result.Model,
			"coherence_score":  result.CoherenceScore,
			"coherence_reason": result.CoherenceReason,
		},
	)
	// Inference reality probe through the relay: a coherent-but-canned PROXY_OK stays influenced;
	// only input-dependent output through the proxy path earns execution-confirmed.
	ptStage, ptLanded := "recon", "reachable"
	if result.Coherent {
		ptStage, ptLanded = "impact", "influenced"
		ptProbe := inferenceprobe.Verify([]byte("aipostex relay reality probe"), func(input []byte) (string, int, error) {
			r, e := client.Generate(result.Model, string(input), 32)
			return r.Response, r.StatusCode, e
		})
		finding.Metadata["inference_input_dependent"] = ptProbe.Real
		if ptProbe.Real {
			ptLanded = "execution-confirmed"
		}
	}
	finding.Metadata = applyStageLanded(finding.Metadata, ptStage, ptLanded, "openai-compat-proxy-test", "inference")
	finding.Evidence = result.Response
	oaiPlan := buildOpenAICompatInferenceWorkflowPlan(openAICompatTarget, result.Model)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, oaiPlan)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "openai-compat",
		Action:              "proxy-test",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{oaiPlan},
	})
}

func runOpenAICompatGenerate(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("openai-compat generate"); err != nil {
		return err
	}
	if strings.TrimSpace(openAICompatPrompt) == "" {
		return missingFlagError("prompt", formatCommandExample("openai-compat --target http://127.0.0.1:8000 generate --model llama3 --prompt \"Hello\" --force-exploit"))
	}
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	result, err := client.Generate(openAICompatModel, openAICompatPrompt, openAICompatMaxTokens)
	if err != nil {
		return fmt.Errorf("running generation: %w", err)
	}

	// Inference reality probe: a canned/static completion must NOT read as execution-confirmed.
	// Send the prompt + a mutated variant and compare — only input-dependent output is real inference.
	probe := inferenceprobe.Verify([]byte(openAICompatPrompt), func(input []byte) (string, int, error) {
		r, e := client.Generate(openAICompatModel, string(input), openAICompatMaxTokens)
		return r.Response, r.StatusCode, e
	})
	genStage, genLanded := "recon", "reachable"
	if result.Success {
		genStage, genLanded = "impact", "influenced"
		if probe.Real {
			genLanded = "execution-confirmed"
		}
	}

	finding := newExploitFinding(
		report.SourceOpenAICompat,
		openAICompatTarget,
		fmt.Sprintf("Prompted inference completed on %s", result.Model),
		report.SeverityHigh,
		fmt.Sprintf("Endpoint accepted an operator-supplied prompt for model %s and returned a response in %s", result.Model, result.Latency),
		map[string]interface{}{
			"module":          "openai-compat",
			"action":          "generate",
			"mutating":        true,
			"provider":        "openai-compatible",
			"model":           result.Model,
			"status":          result.StatusCode,
			"success":         result.Success,
			"max_tokens":      result.MaxTokens,
			"latency_ms":      result.Latency.Milliseconds(),
			"prompt_length":   len(result.Prompt),
			"response_length": len(result.Response),
			"evidence_full":   true,
		},
	)
	finding.Metadata["inference_input_dependent"] = probe.Real
	finding.Metadata = applyStageLanded(finding.Metadata, genStage, genLanded, "openai-compat-generate", "inference")
	finding.Evidence = fmt.Sprintf("prompt=%q\nmodel=%s status=%d success=%t\nprobe=%s\nresponse:\n%s", result.Prompt, result.Model, result.StatusCode, result.Success, probe.Evidence, result.Response)
	oaiPlan := buildOpenAICompatInferenceWorkflowPlan(openAICompatTarget, result.Model)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, oaiPlan)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "openai-compat",
		Action:              "generate",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{oaiPlan},
	})
}

func runOpenAICompatToolEnum(cmd *cobra.Command, args []string) error {
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	result, err := client.ToolEnum(openAICompatModel)
	if err != nil {
		return fmt.Errorf("running tool enumeration: %w", err)
	}

	var findings []report.Finding
	probeFailures := strings.Join(result.ProbeFailures, "; ")

	if result.CompletedProbes == 0 {
		finding := newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			fmt.Sprintf("Tool calling probe inconclusive on %s", result.Model),
			report.SeverityInfo,
			"All tool-calling probes failed before the endpoint returned usable results. Treat capability as inconclusive rather than unsupported.",
			map[string]interface{}{
				"module":                "openai-compat",
				"action":                "tool-enum",
				"mutating":              false,
				"model":                 result.Model,
				"completed_probe_count": result.CompletedProbes,
				"probe_failures":        probeFailures,
			},
		)
		if result.ResponseEvidence != "" {
			finding.Evidence = result.ResponseEvidence
		} else if probeFailures != "" {
			// No response body came back, but the probe failures are the evidence for
			// why capability is inconclusive — surface them instead of an empty block.
			finding.Evidence = fmt.Sprintf("Probe failures: %s", probeFailures)
		}
		findings = append(findings, finding)
	} else if !result.ToolCallSupported {
		finding := newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			fmt.Sprintf("Tool calling not supported on %s", result.Model),
			report.SeverityInfo,
			"The endpoint returned chat-completion responses but did not show actual tool or function call behavior in the completed probes.",
			map[string]interface{}{
				"module":                "openai-compat",
				"action":                "tool-enum",
				"mutating":              false,
				"model":                 result.Model,
				"completed_probe_count": result.CompletedProbes,
				"probe_failures":        probeFailures,
			},
		)
		if result.ResponseEvidence != "" {
			finding.Evidence = result.ResponseEvidence
		}
		findings = append(findings, finding)
	} else {
		finding := newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			fmt.Sprintf("Tool/function calling supported on %s", result.Model),
			report.SeverityHigh,
			fmt.Sprintf("The endpoint accepts the tools parameter in chat completions. Discovered %d tool call(s).", len(result.DiscoveredTools)),
			map[string]interface{}{
				"module":                "openai-compat",
				"action":                "tool-enum",
				"mutating":              false,
				"model":                 result.Model,
				"discovered_tools":      strings.Join(result.DiscoveredTools, ","),
				"completed_probe_count": result.CompletedProbes,
				"probe_failures":        probeFailures,
			},
		)
		if result.ResponseEvidence != "" {
			finding.Evidence = result.ResponseEvidence
		}
		findings = append(findings, finding)
	}

	if result.InjectionAccepted {
		finding := newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			fmt.Sprintf("Tool injection accepted on %s", result.Model),
			report.SeverityCritical,
			"The endpoint executed an attacker-defined function schema. An adversary can inject arbitrary tool definitions to exfiltrate data or trigger actions.",
			map[string]interface{}{
				"module":                "openai-compat",
				"action":                "tool-enum",
				"mutating":              false,
				"model":                 result.Model,
				"injected_tool":         "aipostex_exfil_test",
				"injection_proof":       true,
				"completed_probe_count": result.CompletedProbes,
			},
		)
		if result.ResponseEvidence != "" {
			finding.Evidence = result.ResponseEvidence
		}
		findings = append(findings, finding)
	}

	if result.ForcedCallWorks {
		finding := newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			fmt.Sprintf("Forced tool invocation works on %s", result.Model),
			report.SeverityCritical,
			"The endpoint allows tool_choice to force a specific function call, bypassing model guardrails and enabling deterministic tool exploitation.",
			map[string]interface{}{
				"module":                "openai-compat",
				"action":                "tool-enum",
				"mutating":              false,
				"model":                 result.Model,
				"forced_tool":           "aipostex_probe",
				"forced_proof":          true,
				"completed_probe_count": result.CompletedProbes,
			},
		)
		if result.ResponseEvidence != "" {
			finding.Evidence = result.ResponseEvidence
		}
		findings = append(findings, finding)
	}

	plan := suppressWorkflowCommands(
		buildOpenAICompatEnumWorkflowPlan(openAICompatTarget, []string{result.Model}, nil),
		formatCommandExample("openai-compat --target "+openAICompatTarget+" tool-enum --model "+result.Model),
	)
	for i := range findings {
		// Honest per-finding proof: Info-severity results (not-supported /
		// inconclusive) only prove reachability; injection/forced-call proofs are
		// execution-confirmed; a plain "tool calling supported" stays "confirmed".
		stage, strength := "proof", "confirmed"
		switch {
		case findings[i].Severity == report.SeverityInfo:
			stage, strength = "discovery", "reachable"
		case findings[i].Metadata["injection_proof"] == true || findings[i].Metadata["forced_proof"] == true:
			stage, strength = "proof", "execution-confirmed"
		}
		findings[i].Metadata = applyStageLanded(findings[i].Metadata, stage, strength, "openai-compat-tool-enum", "tools")
		findings[i].Metadata = attachWorkflowToMetadata(findings[i].Metadata, plan)
	}

	infof("Tool enum on %s: completed=%d supported=%t injection=%t forced=%t tools=%d failures=%d",
		result.Model, result.CompletedProbes, result.ToolCallSupported, result.InjectionAccepted, result.ForcedCallWorks, len(result.DiscoveredTools), len(result.ProbeFailures))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "openai-compat",
		Action:              "tool-enum",
		ResourcesEnumerated: len(findings),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runOpenAICompatPromptTest(cmd *cobra.Command, args []string) error {
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	result, err := client.PromptInjectionTest(openAICompatModel)
	if err != nil {
		return fmt.Errorf("running prompt injection test: %w", err)
	}

	probeFailures := strings.Join(result.ProbeFailures, "; ")
	vulnerableCount := len(result.VulnerableProbes)
	severity, title, description := promptTestSummary(result)

	plan := suppressWorkflowCommands(
		buildOpenAICompatEnumWorkflowPlan(openAICompatTarget, []string{result.Model}, nil),
		formatCommandExample("openai-compat --target "+openAICompatTarget+" prompt-test --model "+result.Model),
	)

	findings := []report.Finding{
		newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			title,
			severity,
			description,
			map[string]interface{}{
				"module":                 "openai-compat",
				"action":                 "prompt-test",
				"mutating":               false,
				"provider":               "openai-compatible",
				"model":                  result.Model,
				"vulnerable_probe_count": vulnerableCount,
				"vulnerable_probes":      strings.Join(result.VulnerableProbes, ","),
				"completed_probe_count":  result.CompletedProbes,
				"probe_failures":         probeFailures,
			},
		),
	}
	if result.ResponseEvidence != "" {
		findings[0].Evidence = result.ResponseEvidence
	}
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	for _, probe := range result.VulnerableProbes {
		finding := newExploitFinding(
			report.SourceOpenAICompat,
			openAICompatTarget,
			promptProbeFindingTitle(probe, result.Model),
			promptProbeSeverity(probe),
			promptProbeFindingDescription(probe),
			map[string]interface{}{
				"module":       "openai-compat",
				"action":       "prompt-test",
				"mutating":     false,
				"provider":     "openai-compatible",
				"model":        result.Model,
				"prompt_probe": probe,
			},
		)
		if evidence := result.ProbeEvidence[probe]; evidence != "" {
			finding.Evidence = evidence
		}
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
		findings = append(findings, finding)
	}

	infof("Prompt test on %s: completed=%d vulnerable_probes=%d failures=%d", result.Model, result.CompletedProbes, vulnerableCount, len(result.ProbeFailures))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "openai-compat",
		Action:              "prompt-test",
		ResourcesEnumerated: len(findings),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func promptTestSummary(result *openaicompat.PromptInjectionResult) (severity, title, description string) {
	if result == nil {
		return report.SeverityInfo, "Prompt injection probe inconclusive", "Prompt injection probes did not return usable results."
	}

	vulnerableCount := len(result.VulnerableProbes)
	switch {
	case result.CompletedProbes == 0:
		return report.SeverityInfo,
			fmt.Sprintf("Prompt injection probe inconclusive on %s", result.Model),
			"All bounded prompt injection probes failed before the endpoint returned usable results. Treat resistance as inconclusive."
	case vulnerableCount >= 3:
		return report.SeverityCritical,
			fmt.Sprintf("Prompt injection vulnerable on %s", result.Model),
			fmt.Sprintf("%d prompt injection probes succeeded against the endpoint.", vulnerableCount)
	case vulnerableCount >= 1:
		return report.SeverityHigh,
			fmt.Sprintf("Partial prompt injection success on %s", result.Model),
			fmt.Sprintf("%d bounded prompt injection probes succeeded against the endpoint.", vulnerableCount)
	default:
		return report.SeverityInfo,
			fmt.Sprintf("Prompt injection probes resisted on %s", result.Model),
			"All bounded prompt injection probes were resisted or produced non-vulnerable responses."
	}
}

func runOpenAICompatLiteLLMProbe(cmd *cobra.Command, args []string) error {
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}

	var findings []report.Finding
	var plans []workflowPlan

	readiness, readinessErr := client.ReadinessInfo()
	if readinessErr == nil && readiness != nil {
		severity := report.SeverityMedium
		title := "LiteLLM readiness endpoint exposed"
		desc := fmt.Sprintf("LiteLLM version %s exposed via unprotected /health/readiness (status=%s)", readiness.Version, readiness.Status)
		if readiness.Version == "" {
			desc = fmt.Sprintf("LiteLLM readiness endpoint returned status=%s", readiness.Status)
		}
		finding := newExploitFinding(report.SourceOpenAICompat, openAICompatTarget, title, severity, desc, map[string]interface{}{
			"module": "openai-compat", "action": "litellm-probe", "mutating": false,
			"provider": "litellm", "litellm_version": readiness.Version,
			"db_connected": readiness.DB, "cache_status": readiness.Cache,
		})
		findings = append(findings, finding)
	}

	health, healthErr := client.HealthInfo()
	if healthErr == nil && health != nil {
		severity := report.SeverityHigh
		title := "LiteLLM health endpoint exposes backend topology"
		desc := fmt.Sprintf("LiteLLM /health exposes %d healthy and %d unhealthy backend endpoint(s)", health.HealthyCount, health.UnhealthyCount)

		var apiBases []string
		for _, ep := range health.HealthyEndpoints {
			if base, ok := ep["api_base"].(string); ok && base != "" {
				apiBases = append(apiBases, base)
			}
		}
		metadata := map[string]interface{}{
			"module": "openai-compat", "action": "litellm-probe", "mutating": false,
			"provider": "litellm", "healthy_count": health.HealthyCount,
			"unhealthy_count": health.UnhealthyCount,
		}
		if len(apiBases) > 0 {
			metadata["api_base"] = strings.Join(apiBases, ", ")
		}
		if readinessErr == nil && readiness != nil && readiness.Version != "" {
			metadata["litellm_version"] = readiness.Version
		}
		finding := newExploitFinding(report.SourceOpenAICompat, openAICompatTarget, title, severity, desc, metadata)
		finding.Evidence = fmt.Sprintf("Healthy: %d, Unhealthy: %d, API bases: %s", health.HealthyCount, health.UnhealthyCount, strings.Join(apiBases, ", "))
		findings = append(findings, finding)
	}

	modelInfo, modelInfoErr := client.ModelInfo()
	if modelInfoErr == nil && modelInfo != nil && len(modelInfo.Data) > 0 {
		secrets := openaicompat.ExtractLiteLLMSecrets(modelInfo)
		severity := report.SeverityHigh
		title := fmt.Sprintf("LiteLLM model info exposes %d model configuration(s)", len(modelInfo.Data))
		desc := fmt.Sprintf("LiteLLM /v1/model/info returns full model configurations for %d model(s)", len(modelInfo.Data))
		if len(secrets) > 0 {
			severity = report.SeverityCritical
			title = fmt.Sprintf("LiteLLM model info leaks %d secret(s) across %d model(s)", len(secrets), len(modelInfo.Data))
			desc = "LiteLLM /v1/model/info contains embedded API keys or credentials in litellm_params"
		}
		metadata := map[string]interface{}{
			"module": "openai-compat", "action": "litellm-probe", "mutating": false,
			"provider": "litellm", "model_count": len(modelInfo.Data), "secret_count": len(secrets),
		}
		finding := newExploitFinding(report.SourceOpenAICompat, openAICompatTarget, title, severity, desc, metadata)
		// Always attach the raw model configurations as evidence — this is the
		// "config extracted" surface (api_base backends, routing, versions) the
		// probe promises. Without it the finding claimed exposure but shipped no
		// evidence, dropping the api_base backend-topology leak.
		if cfgJSON, err := json.MarshalIndent(modelInfo.Data, "", "  "); err == nil {
			finding.Evidence = string(cfgJSON)
		}
		if len(secrets) > 0 {
			// Lead with the looted secrets, then the full config below.
			finding.Evidence = "Embedded secrets:\n" + strings.Join(secrets, "\n") +
				"\n\nModel configurations:\n" + finding.Evidence
			// Emit each looted litellm_params secret as a structured credential so the
			// loot index / dossier / credential-chaining pick it up. secrets are "key=value"
			// strings (e.g. api_key=sk-..., aws_secret_access_key=...); classify the value
			// the same way ray.go does (sk-ant- -> anthropic, sk- -> openai, else api-key)
			// and keep the value RAW. Shape matches the k8s/mlflow/ray loot channel.
			var creds []map[string]interface{}
			for _, s := range secrets {
				name, value, ok := strings.Cut(s, "=")
				if !ok || value == "" {
					continue
				}
				creds = append(creds, lootCredentialRecord(
					litellmSecretCredentialType(value), name, value, openAICompatTarget,
					"embedded in litellm_params of /v1/model/info")...)
			}
			if len(creds) > 0 {
				finding.Metadata["extracted_credentials"] = creds
			}
		}
		findings = append(findings, finding)
	}

	if len(findings) == 0 {
		errParts := []string{}
		if readinessErr != nil {
			errParts = append(errParts, "readiness: "+readinessErr.Error())
		}
		if healthErr != nil {
			errParts = append(errParts, "health: "+healthErr.Error())
		}
		if modelInfoErr != nil {
			errParts = append(errParts, "model-info: "+modelInfoErr.Error())
		}
		finding := newExploitFinding(report.SourceOpenAICompat, openAICompatTarget,
			"LiteLLM probe returned no results", report.SeverityInfo,
			"No LiteLLM-specific endpoints responded. Target may not be LiteLLM or endpoints may require authentication.",
			map[string]interface{}{"module": "openai-compat", "action": "litellm-probe", "mutating": false, "errors": strings.Join(errParts, "; ")},
		)
		findings = append(findings, finding)
	}

	plan := buildOpenAICompatEnumWorkflowPlan(openAICompatTarget, nil, nil)
	plans = append(plans, plan)
	for i := range findings {
		findings[i].Metadata = attachWorkflowToMetadata(findings[i].Metadata, plan)
	}

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "openai-compat",
		Action:              "litellm-probe",
		ResourcesEnumerated: len(findings),
		Mutating:            false,
		WorkflowPlans:       plans,
	})
}

// litellmSecretCredentialType classifies a raw provider key looted from litellm_params
// into a credential-type string the chaining layer understands. The value prefix is the
// reliable signal (same heuristic as ray.go's classifyRayEnvCredential): sk-ant- is an
// Anthropic key, sk- is an OpenAI key, everything else is a generic api-key.
func litellmSecretCredentialType(value string) string {
	trimmed := strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(trimmed, "sk-ant-"):
		return "anthropic-api-key"
	case strings.HasPrefix(trimmed, "sk-"):
		return "openai-api-key"
	default:
		return "api-key"
	}
}

func newOpenAICompatClient() (*openaicompat.Client, http.Header, error) {
	if strings.TrimSpace(openAICompatTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("openai-compat --target http://127.0.0.1:8000 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(openAICompatHeaders)
	if err != nil {
		return nil, nil, err
	}
	if headers == nil {
		headers = make(http.Header)
	}
	if strings.TrimSpace(openAICompatAPIKey) != "" && headers.Get("Authorization") == "" {
		headers.Set("Authorization", "Bearer "+strings.TrimSpace(openAICompatAPIKey))
	}
	target := normalizeAndWarnTarget(openAICompatTarget)
	openAICompatTarget = target
	client, err := openaicompat.NewClient(currentContext(), target, cfg.Timeout, headers)
	if err != nil {
		return nil, nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, nil, err
	}
	client.HTTPClient = httpClient
	return client, headers, nil
}

func runOpenAICompatFingerprint(cmd *cobra.Command, args []string) error {
	client, _, err := newOpenAICompatClient()
	if err != nil {
		return err
	}
	// Resolve once so every behavioral probe hits the same concrete model
	// instead of re-listing on each request.
	resolved, err := client.ResolveModel(openAICompatModel)
	if err != nil {
		return fmt.Errorf("resolving model for fingerprint: %w", err)
	}

	opts := modelfingerprint.Options{
		Send: func(prompt string) (string, error) { return client.Ask(resolved, prompt) },
	}
	if openAICompatFPContext {
		opts.MultiSend = func(messages []map[string]string) (string, error) {
			return client.AskMessages(resolved, messages)
		}
	}
	res := modelfingerprint.Identify(opts)

	// Recon-grade finding: severity reflects attribution confidence, not risk.
	severity := report.SeverityInfo
	title := fmt.Sprintf("Model fingerprint inconclusive on %s (no family signal)", resolved)
	if res.Family != "" {
		title = fmt.Sprintf("Model fingerprint: %s / %s (%s confidence) on %s", res.Family, safeLabel(res.Vendor), res.Confidence, resolved)
	}
	description := "Behavioral model fingerprint via identity, contradiction, and knowledge-cutoff probing. " + res.Evidence

	metadata := map[string]interface{}{
		"module":                 "openai-compat",
		"action":                 "fingerprint",
		"mutating":               false,
		"provider":               "openai-compatible",
		"model":                  resolved,
		"model_family":           res.Family,
		"model_vendor":           res.Vendor,
		"fingerprint_confidence": res.Confidence,
		"cutoff_hint":            res.CutoffHint,
		"signal_count":           len(res.Signals),
	}
	if res.ContextWindow.Tested {
		metadata["context_window_recalled"] = res.ContextWindow.MarkerRecalled
	}
	finding := newExploitFinding(
		report.SourceOpenAICompat,
		openAICompatTarget,
		title,
		severity,
		description,
		metadata,
	)
	// Fingerprinting is passive recon: the endpoint is reachable and answered,
	// but nothing was accessed or mutated.
	finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "openai-compat-fingerprint", "model")
	finding.Evidence = fingerprintEvidence(res)

	plan := suppressWorkflowCommands(
		buildOpenAICompatEnumWorkflowPlan(openAICompatTarget, []string{resolved}, nil),
		formatCommandExample("openai-compat --target "+openAICompatTarget+" fingerprint --model "+resolved),
	)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "openai-compat",
		Action:              "fingerprint",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

// fingerprintEvidence renders the per-probe signals into a readable evidence block.
func fingerprintEvidence(res modelfingerprint.Result) string {
	var b strings.Builder
	b.WriteString(res.Evidence)
	for _, s := range res.Signals {
		b.WriteString("\n[")
		b.WriteString(s.Probe)
		b.WriteString("] ")
		b.WriteString(s.Note)
		if s.Reply != "" {
			b.WriteString(" | reply: ")
			b.WriteString(s.Reply)
		}
	}
	return b.String()
}

func safeLabel(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func promptProbeSeverity(probe string) string {
	switch probe {
	case "instruction-override", "jailbreak", "refusal-bypass":
		return report.SeverityHigh
	default:
		return report.SeverityMedium
	}
}

func promptProbeFindingTitle(probe, model string) string {
	switch probe {
	case "instruction-override":
		return fmt.Sprintf("Instruction override succeeded on %s", model)
	case "role-confusion":
		return fmt.Sprintf("Role confusion prompt hijack succeeded on %s", model)
	case "delimiter-escape":
		return fmt.Sprintf("Delimiter escape prompt injection succeeded on %s", model)
	case "jailbreak":
		return fmt.Sprintf("Jailbreak prompt succeeded on %s", model)
	case "refusal-bypass":
		return fmt.Sprintf("Refusal bypass succeeded on %s", model)
	default:
		return fmt.Sprintf("Prompt probe succeeded on %s", model)
	}
}

func promptProbeFindingDescription(probe string) string {
	switch probe {
	case "instruction-override":
		return "A higher-priority system instruction was overridden by a direct user request."
	case "role-confusion":
		return "A fake system-style instruction embedded in user content altered the model response."
	case "delimiter-escape":
		return "Delimiter-style prompt boundaries were interpreted as higher-priority instructions."
	case "jailbreak":
		return "A jailbreak prompt overrode a system-level output prohibition, producing the explicitly forbidden response."
	case "refusal-bypass":
		return "A translation-style prompt bypassed refusal behavior and transformed protected instruction content."
	default:
		return "A bounded prompt injection probe produced a vulnerable response."
	}
}

func highValueSlice(model openaicompat.ModelInfo) []string {
	if openaicompat.HighValueModel(model) {
		return []string{model.ID}
	}
	return nil
}

func acceptedAuthLabels(patterns []openaicompat.AuthSweepPattern) []string {
	values := make([]string, 0)
	for _, pattern := range patterns {
		if pattern.AcceptedInventory || pattern.AcceptedInference {
			values = append(values, pattern.Label)
		}
	}
	return uniqueSortedStrings(values)
}

func authSweepModelAttempts(patterns []openaicompat.AuthSweepPattern) []openaicompat.ModelAttempt {
	attempts := make([]openaicompat.ModelAttempt, 0)
	for _, pattern := range patterns {
		attempts = append(attempts, pattern.ModelAttempts...)
	}
	return attempts
}

func cloneMap(values map[string]interface{}) map[string]interface{} {
	if len(values) == 0 {
		return map[string]interface{}{}
	}
	cloned := make(map[string]interface{}, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
