package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/inferenceprobe"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/triton"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	tritonTarget  string
	tritonHeaders []string
	tritonModel   string
	tritonPayload string
)

var tritonCmd = &cobra.Command{
	Use:   "triton",
	Short: "Enumerate and exploit Triton Inference Server",
	Long: `Post-exploitation module for NVIDIA Triton Inference Server.

Examples:
  aipostex triton --target http://10.0.0.60:8000 enum
  aipostex triton --target http://10.0.0.60:8000 models
  aipostex triton --target http://10.0.0.60:8000 infer --model resnet50 --payload '{"inputs":[]}' --force-exploit`,
	Example: strings.Join([]string{
		formatCommandExample("triton --target http://127.0.0.1:8000 enum"),
		formatCommandExample("triton --target http://127.0.0.1:8000 models"),
		formatCommandExample("triton --target http://127.0.0.1:8000 shm-probe"),
	}, "\n"),
}

var tritonEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate Triton server metadata",
	Long: `Enumerate Triton server metadata, health status, and enabled extensions.

The extension list is the offensive detail: it declares which optional APIs this
build exposes — including shared-memory and model-repository control, the
surfaces behind the IPC and model-load chains.

This is a read-only probing operation.`,
	Example: formatCommandExample("triton --target http://127.0.0.1:8000 enum"),
	RunE:    runTritonEnum,
}

var tritonModelsCmd = &cobra.Command{
	Use:   "models",
	Short: "List all loaded models",
	Long: `List all loaded models with their metadata.

Names the models currently in memory and their versions — the identifiers needed
for inference, configuration reads, and lifecycle operations.

This is a read-only probing operation.`,
	Example: formatCommandExample("triton --target http://127.0.0.1:8000 models"),
	RunE:    runTritonModels,
}

var tritonModelConfigCmd = &cobra.Command{
	Use:   "model-config",
	Short: "Get detailed model configuration",
	Long: `Retrieve a model's full configuration: instance groups, scheduling, and
optimization settings.

The configuration shows how and where the model executes — GPU placement,
batching, and backend — revealing what the server actually runs and which knobs
a write-capable caller could turn.

This is a read-only probing operation.`,
	Example: formatCommandExample("triton --target http://127.0.0.1:8000 model-config --model resnet50"),
	RunE:    runTritonModelConfig,
}

var tritonInferCmd = &cobra.Command{
	Use:         "infer",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Send an inference request to a model",
	Long: `Send an inference request to test model access.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("triton --target http://127.0.0.1:8000 infer --model resnet50 --payload '{\"inputs\":[]}' --force-exploit"),
	RunE:    runTritonInfer,
}

var tritonModelLoadCmd = &cobra.Command{
	Use:         "model-load",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Attempt to load a model from the repository",
	Long: `Attempt to load a model from the model repository, proving write access to model lifecycle.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("triton --target http://127.0.0.1:8000 model-load --model test --force-exploit"),
	RunE:    runTritonModelLoad,
}

var tritonModelUnloadCmd = &cobra.Command{
	Use:         "model-unload",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Attempt to unload a model",
	Long: `Attempt to unload a model, proving destructive access to the model lifecycle.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("triton --target http://127.0.0.1:8000 model-unload --model test --force-exploit"),
	RunE:    runTritonModelUnload,
}

var tritonSHMProbeCmd = &cobra.Command{
	Use:   "shm-probe",
	Short: "Probe shared memory regions (IPC vulnerability chain)",
	Long: `Probe for shared memory regions. Tests for the Wiz-discovered IPC vulnerability chain
(CVE-2025-23319/23320/23334) by checking system and CUDA shared memory status endpoints.`,
	Example: formatCommandExample("triton --target http://127.0.0.1:8000 shm-probe"),
	RunE:    runTritonSHMProbe,
}

func init() {
	tritonCmd.PersistentFlags().StringVarP(&tritonTarget, "target", "t", "", "Triton server URL (required)")
	tritonCmd.PersistentFlags().StringSliceVar(&tritonHeaders, "header", nil, "Additional HTTP header(s)")

	tritonModelConfigCmd.Flags().StringVar(&tritonModel, "model", "", "Model name (required)")
	tritonInferCmd.Flags().StringVar(&tritonModel, "model", "", "Model name (required)")
	tritonInferCmd.Flags().StringVar(&tritonPayload, "payload", "", "JSON inference payload (required)")
	tritonModelLoadCmd.Flags().StringVar(&tritonModel, "model", "", "Model name to load (required)")
	tritonModelLoadCmd.Flags().StringVar(&tritonPayload, "payload", "", "Optional JSON inference payload to verify the model is inferable after load")
	tritonModelUnloadCmd.Flags().StringVar(&tritonModel, "model", "", "Model name to unload (required)")

	tritonCmd.AddCommand(tritonEnumCmd, tritonModelsCmd, tritonModelConfigCmd, tritonInferCmd,
		tritonModelLoadCmd, tritonModelUnloadCmd, tritonSHMProbeCmd)
}

func runTritonEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := newTritonClient()
	if err != nil {
		return err
	}
	meta, err := client.Enumerate()
	if err != nil {
		return fmt.Errorf("enumerating triton server: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceTriton,
			tritonTarget,
			"Triton Inference Server enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated Triton server (name=%s, version=%s, ready=%t, live=%t, extensions=%d)",
				safeLabel(meta.Name), safeLabel(meta.Version), meta.Ready, meta.Live, len(meta.Extensions)),
			map[string]interface{}{
				"module":     "triton",
				"action":     "enum",
				"mutating":   false,
				"provider":   "triton",
				"version":    meta.Version,
				"headers":    headerNames(headers),
				"ready":      meta.Ready,
				"live":       meta.Live,
				"extensions": len(meta.Extensions),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "triton-enum", "server")

	// Enumerate() returns only server metadata (no model names), so no real model
	// is known here — model discovery happens in the `models` step below. Rather
	// than emit a gated infer command carrying a "<model>" placeholder, the plan
	// stops at listing models; the models flow builds the concrete infer follow-on
	// once a real model name is in scope.
	enumPlan := workflowPlan{
		Target:    tritonTarget,
		Stage:     "enum",
		Rationale: "Server discovery flows into model enumeration; once models is run, inference testing can name a discovered model.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("triton --target "+tritonTarget+" models"), "List loaded models to discover a model name for inference testing.", false, 10),
			newWorkflowRecommendation(formatCommandExample("triton --target "+tritonTarget+" shm-probe"), "Probe shared memory regions for IPC vulnerabilities.", false, 20),
		},
	}
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, enumPlan)

	infof("Enumerated Triton server (version=%s)", safeLabel(meta.Version))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "triton",
		Action:              "enum",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{enumPlan},
	})
}

func runTritonModels(cmd *cobra.Command, args []string) error {
	client, _, err := newTritonClient()
	if err != nil {
		return err
	}
	// KServe (which Triton implements) has no GET /v2/models list endpoint; model
	// listing is POST /v2/repository/index. ListModels() (GET /v2/models) 404s on
	// a real Triton, so the `models` subcommand must use RepositoryIndex().
	models, err := client.RepositoryIndex()
	if err != nil {
		return fmt.Errorf("listing models: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceTriton,
			tritonTarget,
			"Triton models enumerated",
			report.SeverityHigh,
			fmt.Sprintf("Enumerated %d loaded model(s)", len(models)),
			map[string]interface{}{
				"module":      "triton",
				"action":      "models",
				"mutating":    false,
				"provider":    "triton",
				"model_count": len(models),
			},
		),
	}

	for _, model := range models {
		detail, _ := client.ModelDetail(model.Name)
		finding := newExploitFinding(
			report.SourceTriton,
			tritonTarget,
			fmt.Sprintf("Triton model: %s", model.Name),
			report.SeverityInfo,
			fmt.Sprintf("Model %s (version=%s, platform=%s, state=%s)", model.Name, safeLabel(detail.Version), safeLabel(detail.Platform), safeLabel(model.State)),
			map[string]interface{}{
				"module":   "triton",
				"action":   "models",
				"mutating": false,
				"provider": "triton",
				"model":    model.Name,
				"platform": detail.Platform,
			},
		)
		finding.Evidence = fmt.Sprintf("model=%s\nversion=%s\nplatform=%s\nstate=%s\ninputs=%d\noutputs=%d",
			model.Name, detail.Version, detail.Platform, model.State, len(detail.Inputs), len(detail.Outputs))
		findings = append(findings, finding)
	}

	var modelLines []string
	for _, m := range models {
		modelLines = append(modelLines, fmt.Sprintf("%s: state=%s", m.Name, safeLabel(m.State)))
	}
	findings[0].Evidence = strings.Join(modelLines, "\n")

	// The enumeration discovered real model names, so the follow-on plan threads a
	// discovered model into model-config / infer instead of a "<model>" placeholder.
	modelsPlan := buildTritonModelsWorkflowPlan(tritonTarget, models)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, modelsPlan)

	infof("Enumerated %d Triton model(s)", len(models))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "triton",
		Action:              "models",
		ResourcesEnumerated: len(models),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{modelsPlan},
	})
}

func runTritonModelConfig(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(tritonModel) == "" {
		return missingFlagError("model", formatCommandExample("triton --target http://127.0.0.1:8000 model-config --model resnet50"))
	}
	client, _, err := newTritonClient()
	if err != nil {
		return err
	}
	config, err := client.ModelConfigDetail(tritonModel)
	if err != nil {
		return fmt.Errorf("getting model config: %w", err)
	}

	configJSON, _ := json.MarshalIndent(config.Raw, "", "  ")
	finding := newExploitFinding(
		report.SourceTriton,
		tritonTarget,
		fmt.Sprintf("Triton model config: %s", tritonModel),
		report.SeverityMedium,
		fmt.Sprintf("Model config for %s (platform=%s, backend=%s, instance_groups=%d)",
			tritonModel, safeLabel(config.Platform), safeLabel(config.Backend), len(config.InstanceGroups)),
		map[string]interface{}{
			"module":   "triton",
			"action":   "model-config",
			"mutating": false,
			"provider": "triton",
			"model":    tritonModel,
			"platform": config.Platform,
		},
	)
	finding.Evidence = string(configJSON)

	plan := buildTritonExploitWorkflowPlan(tritonTarget, "model-config", tritonModel)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "triton",
		Action:              "model-config",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runTritonInfer(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("triton infer"); err != nil {
		return err
	}
	if strings.TrimSpace(tritonModel) == "" {
		return missingFlagError("model", formatCommandExample("triton --target http://127.0.0.1:8000 infer --model resnet50 --payload '{}' --force-exploit"))
	}
	if strings.TrimSpace(tritonPayload) == "" {
		return missingFlagError("payload", formatCommandExample("triton --target http://127.0.0.1:8000 infer --model resnet50 --payload '{\"inputs\":[]}' --force-exploit"))
	}
	client, _, err := newTritonClient()
	if err != nil {
		return err
	}
	result, err := client.Infer(tritonModel, json.RawMessage(tritonPayload))
	if err != nil {
		return fmt.Errorf("inference request: %w", err)
	}

	// Inference reality probe: distinguish real, input-dependent inference from a canned
	// fixture by sending a mutated input and comparing outputs. Only claim
	// execution-confirmed when verified real; otherwise reachable (detection).
	probe := inferenceprobe.Verify(json.RawMessage(tritonPayload), func(input []byte) (string, int, error) {
		r, e := client.Infer(tritonModel, json.RawMessage(input))
		return r.Body, r.StatusCode, e
	})
	stage := "discovery"
	if probe.Real {
		stage = "impact"
	}

	severity := report.SeverityHigh
	if !result.Success {
		severity = report.SeverityMedium
	}

	finding := newExploitFinding(
		report.SourceTriton,
		tritonTarget,
		fmt.Sprintf("Triton inference tested: %s", tritonModel),
		severity,
		fmt.Sprintf("Inference request to model %s returned status %d (success=%t); %s", tritonModel, result.StatusCode, result.Success, probe.Evidence),
		map[string]interface{}{
			"module":             "triton",
			"action":             "infer",
			"mutating":           true,
			"provider":           "triton",
			"model":              tritonModel,
			"status_code":        result.StatusCode,
			"stage":              stage,
			"landed":             probe.Landed(),
			"inference_verified": probe.Real,
		},
	)
	finding.Evidence = result.Body

	plan := buildTritonExploitWorkflowPlan(tritonTarget, "infer", tritonModel)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "triton",
		Action:              "infer",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runTritonModelLoad(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("triton model-load"); err != nil {
		return err
	}
	if strings.TrimSpace(tritonModel) == "" {
		return missingFlagError("model", formatCommandExample("triton --target http://127.0.0.1:8000 model-load --model test --force-exploit"))
	}
	client, _, err := newTritonClient()
	if err != nil {
		return err
	}
	loadErr := client.LoadModel(tritonModel)
	success := loadErr == nil
	verificationRequested := strings.TrimSpace(tritonPayload) != ""
	var (
		detail        triton.ModelInfo
		inferResult   triton.InferResult
		verifyErr     string
		verified      bool
		probeEvidence string
	)
	addVerifyErr := func(msg string) {
		if strings.TrimSpace(msg) == "" {
			return
		}
		if verifyErr != "" {
			verifyErr += "; "
		}
		verifyErr += msg
	}
	if success && verificationRequested {
		var detailErr error
		detail, detailErr = client.ModelDetail(tritonModel)
		if detailErr != nil {
			addVerifyErr(fmt.Sprintf("model detail: %v", detailErr))
		}
		var inferErr error
		inferResult, inferErr = client.Infer(tritonModel, json.RawMessage(tritonPayload))
		if inferErr != nil {
			addVerifyErr(fmt.Sprintf("infer: %v", inferErr))
		} else if !inferResult.Success {
			addVerifyErr(fmt.Sprintf("infer returned status %d", inferResult.StatusCode))
		} else {
			// Input-differential reality probe (matches `triton infer` and the other
			// serving modules): send a mutated input and only claim execution-confirmed
			// when output VARIES — a bare 2xx with a static prediction is a canned
			// fixture, not proof the loaded handler ran input-dependent code.
			probe := inferenceprobe.Verify(json.RawMessage(tritonPayload), func(input []byte) (string, int, error) {
				r, e := client.Infer(tritonModel, json.RawMessage(input))
				return r.Body, r.StatusCode, e
			})
			verified = probe.Real
			probeEvidence = probe.Evidence
			if !probe.Real {
				addVerifyErr("inference returned identical output for distinct inputs (canned fixture; input-dependent handler execution not confirmed)")
			}
		}
	}

	stage, landed := "recon", "reachable"
	if success {
		stage, landed = "impact", "influenced"
	}
	if verified {
		stage, landed = "own", "execution-confirmed"
	}

	severity := report.SeverityHigh
	if !success {
		severity = report.SeverityMedium
	}
	if verified {
		severity = report.SeverityCritical
	}

	title := fmt.Sprintf("Triton model load request accepted (unverified): %s", tritonModel)
	description := fmt.Sprintf("Model load request for %s accepted (success=%t); load was not verified against inference.", tritonModel, success)
	if verified {
		title = fmt.Sprintf("Triton model loaded and handler execution confirmed: %s", tritonModel)
		description = fmt.Sprintf("Model load request for %s succeeded, model metadata was reachable, and an input-differential inference probe confirmed the loaded model returned input-dependent output (%s). This proves the repository model became runnable and executes input-dependent handler code through Triton's inference API.", tritonModel, probeEvidence)
	} else if verificationRequested && verifyErr != "" {
		description = fmt.Sprintf("Model load request for %s accepted (success=%t), but post-load inference verification did not complete: %s", tritonModel, success, verifyErr)
	}

	finding := newExploitFinding(
		report.SourceTriton,
		tritonTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":                 "triton",
			"action":                 "model-load",
			"mutating":               true,
			"provider":               "triton",
			"model":                  tritonModel,
			"success":                success,
			"stage":                  stage,
			"landed":                 landed,
			"load_verified":          verified,
			"verification_requested": verificationRequested,
		},
	)
	if detail.State != "" {
		finding.Metadata["model_state"] = detail.State
	}
	if detail.Platform != "" {
		finding.Metadata["platform"] = detail.Platform
	}
	if verificationRequested {
		finding.Metadata["prediction_status_code"] = inferResult.StatusCode
	}
	if verifyErr != "" {
		finding.Metadata["verification_error"] = verifyErr
	}
	loadErrMsg := ""
	if loadErr != nil {
		loadErrMsg = loadErr.Error()
	}
	var evidence strings.Builder
	evidence.WriteString(fmt.Sprintf("model=%s\nsuccess=%t\nerror=%s", tritonModel, success, loadErrMsg))
	if detail.Name != "" || detail.State != "" || detail.Platform != "" {
		evidence.WriteString(fmt.Sprintf("\nmodel_detail_name=%s\nmodel_state=%s\nplatform=%s\ninputs=%d\noutputs=%d",
			detail.Name, detail.State, detail.Platform, len(detail.Inputs), len(detail.Outputs)))
	}
	if verificationRequested {
		evidence.WriteString(fmt.Sprintf("\ninfer_status=%d\nload_verified=%t", inferResult.StatusCode, verified))
		if inferResult.Body != "" {
			evidence.WriteString("\ninfer_response=")
			evidence.WriteString(inferResult.Body)
		}
		if verifyErr != "" {
			evidence.WriteString("\nverification_error=")
			evidence.WriteString(verifyErr)
		}
	}
	finding.Evidence = evidence.String()

	plan := buildTritonExploitWorkflowPlan(tritonTarget, "model-load", tritonModel)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "triton",
		Action:              "model-load",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runTritonModelUnload(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("triton model-unload"); err != nil {
		return err
	}
	if strings.TrimSpace(tritonModel) == "" {
		return missingFlagError("model", formatCommandExample("triton --target http://127.0.0.1:8000 model-unload --model test --force-exploit"))
	}
	client, _, err := newTritonClient()
	if err != nil {
		return err
	}
	unloadErr := client.UnloadModel(tritonModel)
	success := unloadErr == nil
	// Accepting an unload request does not prove the model was removed — claim the
	// lifecycle mutation (influenced), not execution.
	severity := report.SeverityHigh
	if !success {
		severity = report.SeverityMedium
	}

	finding := newExploitFinding(
		report.SourceTriton,
		tritonTarget,
		fmt.Sprintf("Triton model unload request accepted (unverified): %s", tritonModel),
		severity,
		fmt.Sprintf("Model unload request for %s accepted (success=%t); removal was not verified against the model repository.", tritonModel, success),
		map[string]interface{}{
			"module":   "triton",
			"action":   "model-unload",
			"mutating": true,
			"provider": "triton",
			"model":    tritonModel,
			"success":  success,
			"stage":    gatedStrength(success, "exploited", "attempted"),
			"landed":   gatedStrength(success, "influenced", "reachable"),
		},
	)
	unloadErrMsg := ""
	if unloadErr != nil {
		unloadErrMsg = unloadErr.Error()
	}
	finding.Evidence = fmt.Sprintf("model=%s\nsuccess=%t\nerror=%s", tritonModel, success, unloadErrMsg)

	plan := buildTritonExploitWorkflowPlan(tritonTarget, "model-unload", tritonModel)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "triton",
		Action:              "model-unload",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runTritonSHMProbe(cmd *cobra.Command, args []string) error {
	client, _, err := newTritonClient()
	if err != nil {
		return err
	}
	system, cuda, err := client.SHMProbe()
	if err != nil {
		return fmt.Errorf("shm probe: %w", err)
	}

	findings := make([]report.Finding, 0)
	if system.HasData {
		finding := newExploitFinding(
			report.SourceTriton,
			tritonTarget,
			"Triton system shared memory regions exposed",
			report.SeverityHigh,
			fmt.Sprintf("System shared memory status endpoint exposes %d region(s) — potential IPC vulnerability chain (CVE-2025-23319/23320/23334)", len(system.Regions)),
			map[string]interface{}{
				"module":       "triton",
				"action":       "shm-probe",
				"mutating":     false,
				"provider":     "triton",
				"shm_type":     "system",
				"region_count": len(system.Regions),
				"stage":        "access",
			},
		)
		regionJSON, _ := json.MarshalIndent(system.Regions, "", "  ")
		finding.Evidence = string(regionJSON)
		findings = append(findings, finding)
	}
	if cuda.HasData {
		finding := newExploitFinding(
			report.SourceTriton,
			tritonTarget,
			"Triton CUDA shared memory regions exposed",
			report.SeverityHigh,
			fmt.Sprintf("CUDA shared memory status endpoint exposes %d region(s)", len(cuda.Regions)),
			map[string]interface{}{
				"module":       "triton",
				"action":       "shm-probe",
				"mutating":     false,
				"provider":     "triton",
				"shm_type":     "cuda",
				"region_count": len(cuda.Regions),
				"stage":        "access",
			},
		)
		cudaJSON, _ := json.MarshalIndent(cuda.Regions, "", "  ")
		finding.Evidence = string(cudaJSON)
		findings = append(findings, finding)
	}

	if len(findings) == 0 {
		findings = append(findings, newExploitFinding(
			report.SourceTriton,
			tritonTarget,
			"Triton shared memory probe: no exposed regions",
			report.SeverityInfo,
			"Shared memory status endpoints did not expose any region data",
			map[string]interface{}{
				"module":   "triton",
				"action":   "shm-probe",
				"mutating": false,
				"provider": "triton",
			},
		))
	}

	plan := buildTritonExploitWorkflowPlan(tritonTarget, "shm-probe", "")
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	infof("SHM probe completed (system=%t, cuda=%t)", system.HasData, cuda.HasData)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "triton",
		Action:              "shm-probe",
		ResourcesEnumerated: len(findings),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func newTritonClient() (*triton.Client, http.Header, error) {
	if strings.TrimSpace(tritonTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("triton --target http://127.0.0.1:8000 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(tritonHeaders)
	if err != nil {
		return nil, nil, err
	}
	target := normalizeAndWarnTarget(tritonTarget)
	tritonTarget = target
	client, err := triton.NewClient(currentContext(), target, cfg.Timeout, headers)
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
