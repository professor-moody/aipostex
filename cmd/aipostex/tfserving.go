package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/inferenceprobe"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/tfserving"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	tfservingTarget  string
	tfservingHeaders []string
	tfservingModel   string
	tfservingVersion string
	tfservingPayload string
)

var tfservingCmd = &cobra.Command{
	Use:   "tfserving",
	Short: "Enumerate and exploit TensorFlow Serving endpoints",
	Long: `Post-exploitation module for TensorFlow Serving.

TF Serving exposes a REST API for model inference at /v1/models/<name>:predict.
This module enumerates served models, extracts model signatures, and tests
unauthenticated inference access.

Examples:
  aipostex tfserving --target http://10.0.0.40:8501 enum
  aipostex tfserving --target http://10.0.0.40:8501 models
  aipostex tfserving --target http://10.0.0.40:8501 metadata --model resnet
  aipostex tfserving --target http://10.0.0.40:8501 predict --model resnet --payload '{"instances":[[1.0,2.0]]}' --force-exploit`,
	Example: strings.Join([]string{
		formatCommandExample("tfserving --target http://127.0.0.1:8501 enum"),
		formatCommandExample("tfserving --target http://127.0.0.1:8501 models"),
		formatCommandExample("tfserving --target http://127.0.0.1:8501 predict --model default --payload '{\"instances\":[]}' --force-exploit"),
	}, "\n"),
}

var tfservingEnumCmd = &cobra.Command{
	Use:     "enum",
	Short:   "Enumerate TF Serving reachability and metrics",
	Example: formatCommandExample("tfserving --target http://127.0.0.1:8501 enum"),
	RunE:    runTFServingEnum,
}

var tfservingModelsCmd = &cobra.Command{
	Use:     "models",
	Short:   "Probe for served models by name",
	Example: formatCommandExample("tfserving --target http://127.0.0.1:8501 models"),
	RunE:    runTFServingModels,
}

var tfservingMetadataCmd = &cobra.Command{
	Use:     "metadata",
	Short:   "Extract model signature and tensor specs",
	Example: formatCommandExample("tfserving --target http://127.0.0.1:8501 metadata --model default"),
	RunE:    runTFServingMetadata,
}

var tfservingPredictCmd = &cobra.Command{
	Use:   "predict",
	Short: "Send an inference request to a model",
	Long: `Send an inference request to test unauthenticated model access.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("tfserving --target http://127.0.0.1:8501 predict --model default --payload '{\"instances\":[]}' --force-exploit"),
	RunE:    runTFServingPredict,
}

var tfservingMetricsCmd = &cobra.Command{
	Use:     "metrics",
	Short:   "Extract Prometheus metrics",
	Example: formatCommandExample("tfserving --target http://127.0.0.1:8501 metrics"),
	RunE:    runTFServingMetrics,
}

func init() {
	tfservingCmd.PersistentFlags().StringVarP(&tfservingTarget, "target", "t", "", "TF Serving URL (required)")
	tfservingCmd.PersistentFlags().StringSliceVar(&tfservingHeaders, "header", nil, "Additional HTTP header(s)")

	tfservingMetadataCmd.Flags().StringVar(&tfservingModel, "model", "", "Model name (required)")
	tfservingPredictCmd.Flags().StringVar(&tfservingModel, "model", "", "Model name (required)")
	tfservingPredictCmd.Flags().StringVar(&tfservingVersion, "version", "", "Model version (optional, defaults to latest)")
	tfservingPredictCmd.Flags().StringVar(&tfservingPayload, "payload", "", "JSON prediction payload (required)")

	tfservingCmd.AddCommand(tfservingEnumCmd, tfservingModelsCmd, tfservingMetadataCmd,
		tfservingPredictCmd, tfservingMetricsCmd)
}

func runTFServingEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := newTFServingClient()
	if err != nil {
		return err
	}
	info, err := client.Enumerate()
	if err != nil {
		return fmt.Errorf("enumerating TF Serving: %w", outcomeAnnotate(err))
	}

	severity := report.SeverityMedium
	if info.ModelsFound {
		severity = report.SeverityHigh
	}

	description := fmt.Sprintf("TF Serving reachable (models_found=%t, metrics_found=%t)",
		info.ModelsFound, info.MetricsFound)
	metadata := map[string]interface{}{
		"module":        "tfserving",
		"action":        "enum",
		"mutating":      false,
		"provider":      "tfserving",
		"models_found":  info.ModelsFound,
		"metrics_found": info.MetricsFound,
		"headers":       headerNames(headers),
	}
	if info.AuthRequired {
		// Present-but-gated: do not let the operator read this as "no service".
		metadata["access_denied"] = true
		description = "TF Serving REST API is present but access-denied (auth required; retry with credentials). Inference may still be exposed over gRPC."
	}
	finding := newExploitFinding(
		report.SourceTFServing,
		tfservingTarget,
		"TensorFlow Serving enumerated",
		severity,
		description,
		metadata,
	)
	finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "tfserving-enum", "server")
	if info.RawModelStatus != "" {
		finding.Evidence = info.RawModelStatus
	}

	enumPlan := buildTFServingEnumWorkflowPlan(tfservingTarget)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, enumPlan)

	infof("Enumerated TF Serving (models=%t, metrics=%t)", info.ModelsFound, info.MetricsFound)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "tfserving",
		Action:              "enum",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{enumPlan},
	})
}

func runTFServingModels(cmd *cobra.Command, args []string) error {
	client, _, err := newTFServingClient()
	if err != nil {
		return err
	}
	models, err := client.ListModels()
	if err != nil {
		return fmt.Errorf("probing for models: %w", err)
	}

	var findings []report.Finding
	summary := newExploitFinding(
		report.SourceTFServing,
		tfservingTarget,
		"TensorFlow Serving model probe",
		report.SeverityHigh,
		fmt.Sprintf("Discovered %d model(s) via name probing", len(models)),
		map[string]interface{}{
			"module":      "tfserving",
			"action":      "models",
			"mutating":    false,
			"provider":    "tfserving",
			"model_count": len(models),
		},
	)
	if len(models) == 0 {
		summary.Severity = report.SeverityInfo
		summary.Title = "TF Serving model probe: no models found by name probing"
		summary.Description = "No models were found using common model name probing. Use --model with a known name in the metadata subcommand."
	}
	findings = append(findings, summary)

	var modelNames []string
	for _, model := range models {
		var versionLines []string
		for _, v := range model.Versions {
			versionLines = append(versionLines, fmt.Sprintf("v%d state=%s", v.Version, safeLabel(v.State)))
		}
		f := newExploitFinding(
			report.SourceTFServing,
			tfservingTarget,
			fmt.Sprintf("TF Serving model: %s", model.Name),
			report.SeverityHigh,
			fmt.Sprintf("Model %q is served (%d version(s))", model.Name, len(model.Versions)),
			map[string]interface{}{
				"module":        "tfserving",
				"action":        "models",
				"mutating":      false,
				"provider":      "tfserving",
				"model":         model.Name,
				"version_count": len(model.Versions),
			},
		)
		f.Evidence = strings.Join(versionLines, "\n")
		findings = append(findings, f)
		modelNames = append(modelNames, model.Name)
	}

	// Thread the discovered model name into follow-on metadata/predict commands so
	// they are concrete and copyable instead of emitting a "<name>" placeholder.
	var plans []workflowPlan
	if len(modelNames) > 0 {
		plan := buildTFServingModelsWorkflowPlan(tfservingTarget, modelNames)
		summary.Metadata = attachWorkflowToMetadata(summary.Metadata, plan)
		findings[0] = summary
		plans = append(plans, plan)
	}

	infof("Discovered %d TF Serving model(s)", len(models))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "tfserving",
		Action:              "models",
		ResourcesEnumerated: len(models),
		Mutating:            false,
		WorkflowPlans:       plans,
	})
}

func runTFServingMetadata(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(tfservingModel) == "" {
		return missingFlagError("model", formatCommandExample("tfserving --target http://127.0.0.1:8501 metadata --model default"))
	}
	client, _, err := newTFServingClient()
	if err != nil {
		return err
	}
	meta, err := client.GetMetadata(tfservingModel)
	if err != nil {
		return fmt.Errorf("getting model metadata: %w", err)
	}

	sigCount := len(meta.SignatureDefs)
	finding := newExploitFinding(
		report.SourceTFServing,
		tfservingTarget,
		fmt.Sprintf("TF Serving model metadata: %s", tfservingModel),
		report.SeverityHigh,
		fmt.Sprintf("Model %q exposes %d signature definition(s) — input/output tensor specs disclosed",
			tfservingModel, sigCount),
		map[string]interface{}{
			"module":          "tfserving",
			"action":          "metadata",
			"mutating":        false,
			"provider":        "tfserving",
			"model":           tfservingModel,
			"signature_count": sigCount,
		},
	)
	// Model metadata from the REST API confirms the model is exposed (detection);
	// it is not a credential-gated read or real inference, so cap at reachable.
	finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "tfserving-metadata", "model")
	finding.Evidence = meta.RawResponse
	plans := []workflowPlan{}
	if payload, ok := tfservingExamplePayload(meta); ok {
		plan := buildTFServingMetadataWorkflowPlan(tfservingTarget, tfservingModel, payload)
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
		plans = append(plans, plan)
	}

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "tfserving",
		Action:              "metadata",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       plans,
	})
}

func runTFServingPredict(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("tfserving predict"); err != nil {
		return err
	}
	if strings.TrimSpace(tfservingModel) == "" {
		return missingFlagError("model", formatCommandExample("tfserving --target http://127.0.0.1:8501 predict --model default --payload '{}' --force-exploit"))
	}
	if strings.TrimSpace(tfservingPayload) == "" {
		return missingFlagError("payload", formatCommandExample("tfserving --target http://127.0.0.1:8501 predict --model default --payload '{\"instances\":[]}' --force-exploit"))
	}
	client, _, err := newTFServingClient()
	if err != nil {
		return err
	}

	result, err := client.Predict(tfservingModel, tfservingVersion, json.RawMessage(tfservingPayload))
	if err != nil {
		return fmt.Errorf("inference request: %w", err)
	}

	// Inference reality probe: distinguish real, input-dependent inference from a canned
	// fixture by sending a mutated input and comparing outputs. Only claim
	// execution-confirmed when verified real; otherwise reachable (detection).
	probe := inferenceprobe.Verify(json.RawMessage(tfservingPayload), func(input []byte) (string, int, error) {
		r, e := client.Predict(tfservingModel, tfservingVersion, json.RawMessage(input))
		return r.Body, r.StatusCode, e
	})
	// A 2xx envelope carrying an error/not-found body is NOT inference. Only claim
	// unauthenticated inference when the model actually served a prediction.
	bodyLower := strings.ToLower(result.Body)
	served := result.Success && result.StatusCode < 400 &&
		!strings.Contains(bodyLower, `"error"`) && !strings.Contains(bodyLower, "not found")

	versionLabel := safeLabel(result.Version)
	if versionLabel == "" {
		versionLabel = "latest"
	}

	stage, landed := "recon", "reachable"
	severity := report.SeverityLow
	title := fmt.Sprintf("TF Serving inference rejected: %s", tfservingModel)
	if served && probe.Real {
		stage, landed = "impact", probe.Landed()
		severity = report.SeverityCritical
		title = fmt.Sprintf("TF Serving input-dependent inference verified: %s", tfservingModel)
	} else if served {
		severity = report.SeverityMedium
		title = fmt.Sprintf("TF Serving inference not verified: %s", tfservingModel)
	}

	finding := newExploitFinding(
		report.SourceTFServing,
		tfservingTarget,
		title,
		severity,
		fmt.Sprintf("Inference request to model %q (version=%s) returned HTTP %d (success=%t, served=%t); %s",
			tfservingModel, versionLabel, result.StatusCode, result.Success, served, probe.Evidence),
		map[string]interface{}{
			"module":             "tfserving",
			"action":             "predict",
			"mutating":           false,
			"provider":           "tfserving",
			"model":              tfservingModel,
			"version":            versionLabel,
			"status_code":        result.StatusCode,
			"success":            result.Success,
			"served":             served,
			"stage":              stage,
			"landed":             landed,
			"inference_verified": probe.Real,
		},
	)
	finding.Evidence = result.Body

	plan := buildTFServingPredictWorkflowPlan(tfservingTarget, tfservingModel)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "tfserving",
		Action:              "predict",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func tfservingExamplePayload(meta *tfserving.ModelMetadata) (string, bool) {
	if meta == nil || len(meta.SignatureDefs) == 0 {
		return "", false
	}
	sig, ok := pickTFServingSignature(meta.SignatureDefs)
	if !ok {
		return "", false
	}
	inputs, ok := sig["inputs"].(map[string]interface{})
	if !ok || len(inputs) == 0 {
		return "", false
	}
	names := sortedTFServingKeys(inputs)
	if len(names) == 1 {
		spec, _ := inputs[names[0]].(map[string]interface{})
		payload := map[string]interface{}{
			"instances": []interface{}{tfservingTensorExample(spec, false)},
		}
		raw, err := json.Marshal(payload)
		return string(raw), err == nil
	}
	values := make(map[string]interface{}, len(names))
	for _, name := range names {
		spec, _ := inputs[name].(map[string]interface{})
		values[name] = tfservingTensorExample(spec, true)
	}
	raw, err := json.Marshal(map[string]interface{}{"inputs": values})
	return string(raw), err == nil
}

func pickTFServingSignature(signatures map[string]interface{}) (map[string]interface{}, bool) {
	if sig, ok := signatures["serving_default"].(map[string]interface{}); ok {
		return sig, true
	}
	keys := sortedTFServingKeys(signatures)
	for _, key := range keys {
		if sig, ok := signatures[key].(map[string]interface{}); ok {
			return sig, true
		}
	}
	return nil, false
}

func tfservingTensorExample(spec map[string]interface{}, keepBatch bool) interface{} {
	dtype := strings.ToUpper(exploitcommon.PickString(spec, "dtype"))
	dims := tfservingTensorDims(spec)
	if !keepBatch && len(dims) > 0 {
		dims = dims[1:]
	}
	return tfservingValueForShape(dtype, dims)
}

func tfservingTensorDims(spec map[string]interface{}) []int {
	shape, ok := spec["tensor_shape"].(map[string]interface{})
	if !ok {
		return nil
	}
	rawDims, ok := shape["dim"].([]interface{})
	if !ok {
		return nil
	}
	dims := make([]int, 0, len(rawDims))
	for _, raw := range rawDims {
		dim, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		size := 1
		switch v := dim["size"].(type) {
		case string:
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				size = parsed
			}
		case float64:
			if v > 0 {
				size = int(v)
			}
		case int:
			if v > 0 {
				size = v
			}
		}
		if size > 32 {
			size = 32
		}
		dims = append(dims, size)
	}
	return dims
}

func tfservingValueForShape(dtype string, dims []int) interface{} {
	if len(dims) == 0 {
		return tfservingScalar(dtype)
	}
	n := dims[0]
	if n <= 0 {
		n = 1
	}
	out := make([]interface{}, n)
	for i := range out {
		out[i] = tfservingValueForShape(dtype, dims[1:])
	}
	return out
}

func tfservingScalar(dtype string) interface{} {
	switch {
	case strings.Contains(dtype, "STRING"):
		return "aipostex-sample"
	case strings.Contains(dtype, "BOOL"):
		return true
	case strings.Contains(dtype, "INT"):
		return 1
	default:
		return 0.25
	}
}

func sortedTFServingKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func runTFServingMetrics(cmd *cobra.Command, args []string) error {
	client, _, err := newTFServingClient()
	if err != nil {
		return err
	}
	raw, err := client.Metrics()
	if err != nil {
		return fmt.Errorf("fetching metrics: %w", err)
	}

	hasTFData := strings.Contains(raw, "tensorflow") || strings.Contains(raw, ":predict") ||
		strings.Contains(raw, "request_count") || strings.Contains(raw, "HELP")

	severity := report.SeverityMedium
	if hasTFData {
		severity = report.SeverityHigh
	}

	finding := newExploitFinding(
		report.SourceTFServing,
		tfservingTarget,
		"TF Serving Prometheus metrics exposed",
		severity,
		fmt.Sprintf("Metrics endpoint exposed (%d bytes, tensorflow_metrics=%t)", len(raw), hasTFData),
		map[string]interface{}{
			"module":         "tfserving",
			"action":         "metrics",
			"mutating":       false,
			"provider":       "tfserving",
			"has_tf_metrics": hasTFData,
			"response_bytes": len(raw),
		},
	)
	finding.Evidence = raw

	plan := buildTFServingMetricsWorkflowPlan(tfservingTarget)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	infof("TF Serving metrics: %d bytes (tf_data=%t)", len(raw), hasTFData)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "tfserving",
		Action:              "metrics",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func newTFServingClient() (*tfserving.Client, http.Header, error) {
	if strings.TrimSpace(tfservingTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("tfserving --target http://127.0.0.1:8501 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(tfservingHeaders)
	if err != nil {
		return nil, nil, err
	}
	target := normalizeAndWarnTarget(tfservingTarget)
	tfservingTarget = target
	client, err := tfserving.NewClient(currentContext(), target, cfg.Timeout, headers)
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
