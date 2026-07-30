package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/wandb"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	wandbTarget       string
	wandbHeaders      []string
	wandbEntity       string
	wandbProject      string
	wandbArtifactType string
	wandbLimit        int
	wandbAPIKey       string
)

var wandbClientFactory = newWandbClient

var wandbCmd = &cobra.Command{
	Use:   "wandb",
	Short: "Enumerate and extract data from Weights & Biases servers",
	Long: `Enumerate W&B server metadata, list projects, runs, and artifacts,
and scan run configs for embedded secrets.`,
	Example: strings.Join([]string{
		formatCommandExample("wandb --target http://127.0.0.1:8080 enum"),
		formatCommandExample("wandb --target http://127.0.0.1:8080 projects --entity default"),
		formatCommandExample("wandb --target http://127.0.0.1:8080 runs --entity default --project my-project"),
		formatCommandExample("wandb --target http://127.0.0.1:8080 artifacts --entity default --project my-project --type model"),
		formatCommandExample("wandb --target http://127.0.0.1:8080 secrets --entity default --project my-project"),
	}, "\n"),
}

var wandbEnumCmd = &cobra.Command{
	Use:     "enum",
	Short:   "Enumerate W&B server metadata and viewer identity",
	Example: formatCommandExample("wandb --target http://127.0.0.1:8080 enum"),
	RunE:    runWandbEnum,
}

var wandbProjectsCmd = &cobra.Command{
	Use:     "projects",
	Short:   "List projects for an entity",
	Example: formatCommandExample("wandb --target http://127.0.0.1:8080 projects --entity default"),
	RunE:    runWandbProjects,
}

var wandbRunsCmd = &cobra.Command{
	Use:     "runs",
	Short:   "List runs for a project",
	Example: formatCommandExample("wandb --target http://127.0.0.1:8080 runs --entity default --project my-project"),
	RunE:    runWandbRuns,
}

var wandbArtifactsCmd = &cobra.Command{
	Use:     "artifacts",
	Short:   "List artifacts for a project",
	Example: formatCommandExample("wandb --target http://127.0.0.1:8080 artifacts --entity default --project my-project --type model"),
	RunE:    runWandbArtifacts,
}

var wandbSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Scan run configs and summaries for embedded credentials",
	Long: `Enumerate runs for a project, then scan the config and summary
metadata of each run for embedded API keys, tokens, and other secrets.`,
	Example: formatCommandExample("wandb --target http://127.0.0.1:8080 secrets --entity default --project my-project"),
	RunE:    runWandbSecrets,
}

func init() {
	wandbCmd.PersistentFlags().StringVarP(&wandbTarget, "target", "t", "", "W&B server URL (required)")
	wandbCmd.PersistentFlags().StringSliceVar(&wandbHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format")
	wandbCmd.PersistentFlags().StringVar(&wandbAPIKey, "api-key", "", "W&B API key (defaults to WANDB_API_KEY; ignored when Authorization header is supplied)")
	wandbCmd.PersistentFlags().StringVar(&wandbEntity, "entity", "", "W&B entity (user or team)")
	wandbCmd.PersistentFlags().StringVar(&wandbProject, "project", "", "W&B project name")

	wandbArtifactsCmd.Flags().StringVar(&wandbArtifactType, "type", "model", "Artifact type filter")
	wandbRunsCmd.Flags().IntVar(&wandbLimit, "limit", 25, "Maximum runs to return")
	wandbSecretsCmd.Flags().IntVar(&wandbLimit, "limit", 25, "Maximum runs to scan")

	wandbCmd.AddCommand(wandbEnumCmd, wandbProjectsCmd, wandbRunsCmd, wandbArtifactsCmd, wandbSecretsCmd)
}

func runWandbEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := wandbClientFactory()
	if err != nil {
		return err
	}

	version, verErr := client.ServerVersion()
	if verErr != nil {
		warnf("server version: %v", verErr)
	}

	viewer, viewerErr := client.Viewer()
	if viewerErr != nil {
		warnf("viewer: %v", viewerErr)
	}

	meta := map[string]interface{}{
		"module":   "wandb",
		"action":   "enum",
		"mutating": false,
		"headers":  headerNames(headers),
	}
	if version != "" {
		meta["version"] = version
	}

	// If BOTH the server-version and viewer probes failed, the endpoint answered but
	// nothing was actually enumerated — don't claim "server enumerated".
	bothFailed := verErr != nil && viewerErr != nil && version == "" && viewer == nil
	title := "W&B server enumerated"
	desc := fmt.Sprintf("Server version: %s", version)
	if viewer != nil {
		meta["username"] = viewer.Username
		meta["email"] = viewer.Email
		meta["admin"] = viewer.Admin
		meta["teams"] = viewer.Teams
		desc = fmt.Sprintf("Server version: %s, viewer: %s (admin=%t)", version, viewer.Username, viewer.Admin)
	}
	if bothFailed {
		title = "W&B endpoint reachable but not enumerated"
		desc = fmt.Sprintf("The endpoint responded but neither probe succeeded (server version: %v; viewer: %v); no server metadata or identity was read.", verErr, viewerErr)
	}
	meta = applyStageLanded(meta, "recon", "reachable", "wandb-enum", "server")

	// Prefer an explicit --entity flag, then a TEAM the viewer belongs to (team entities
	// own the shared projects an operator actually wants — a personal username usually
	// owns none), and only then the viewer's own username. All are valid W&B entities.
	entityCandidates := []string{wandbEntity}
	if viewer != nil {
		entityCandidates = append(entityCandidates, viewer.Teams...)
		entityCandidates = append(entityCandidates, viewer.Username)
	}
	discoveredEntity := firstNonPlaceholder(entityCandidates)
	plan := buildWandBEnumWorkflowPlan(wandbTarget, discoveredEntity, wandbProject)
	findings := []report.Finding{
		newExploitFinding(report.SourceWandB, wandbTarget, title, report.SeverityInfo, desc, attachWorkflowToMetadata(meta, plan)),
	}
	partialFailures := 0
	if bothFailed {
		partialFailures = 1
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "wandb",
		Action:              "enum",
		ResourcesEnumerated: 1,
		PartialFailures:     partialFailures,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runWandbProjects(cmd *cobra.Command, args []string) error {
	client, headers, err := wandbClientFactory()
	if err != nil {
		return err
	}
	if wandbEntity == "" {
		return missingFlagError("entity", formatCommandExample("wandb --target http://127.0.0.1:8080 projects --entity default"))
	}

	projects, err := client.ListProjects(wandbEntity)
	if err != nil {
		return fmt.Errorf("listing projects: %w", outcomeAnnotate(err))
	}

	meta := map[string]interface{}{
		"module":        "wandb",
		"action":        "projects",
		"mutating":      false,
		"headers":       headerNames(headers),
		"entity":        wandbEntity,
		"project_count": len(projects),
	}
	names := make([]string, 0, len(projects))
	for _, p := range projects {
		names = append(names, p.Name)
	}
	meta["project_names"] = names

	findings := []report.Finding{
		newExploitFinding(
			report.SourceWandB, wandbTarget,
			fmt.Sprintf("W&B: %d project(s) enumerated for entity %q", len(projects), wandbEntity),
			report.SeverityInfo,
			fmt.Sprintf("Found %d projects for entity %s", len(projects), wandbEntity),
			meta,
		),
	}
	firstProject := ""
	if len(names) > 0 {
		firstProject = names[0]
	}
	plan := buildWandBExploitWorkflowPlan(wandbTarget, "projects", wandbEntity, firstProject)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "wandb",
		Action:              "projects",
		ResourcesEnumerated: len(projects),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runWandbRuns(cmd *cobra.Command, args []string) error {
	client, headers, err := wandbClientFactory()
	if err != nil {
		return err
	}
	if wandbEntity == "" || wandbProject == "" {
		return missingFlagError("entity/project", formatCommandExample("wandb --target http://127.0.0.1:8080 runs --entity default --project my-project"))
	}

	runs, err := client.ListRuns(wandbEntity, wandbProject)
	if err != nil {
		return fmt.Errorf("listing runs: %w", outcomeAnnotate(err))
	}

	if wandbLimit > 0 && len(runs) > wandbLimit {
		runs = runs[:wandbLimit]
	}

	meta := map[string]interface{}{
		"module":    "wandb",
		"action":    "runs",
		"mutating":  false,
		"headers":   headerNames(headers),
		"entity":    wandbEntity,
		"project":   wandbProject,
		"run_count": len(runs),
	}
	var runIDs []string
	for _, r := range runs {
		runIDs = append(runIDs, r.ID)
	}
	meta["run_ids"] = runIDs

	findings := []report.Finding{
		newExploitFinding(
			report.SourceWandB, wandbTarget,
			fmt.Sprintf("W&B: %d run(s) enumerated in %s/%s", len(runs), wandbEntity, wandbProject),
			report.SeverityInfo,
			fmt.Sprintf("Found %d runs in %s/%s", len(runs), wandbEntity, wandbProject),
			meta,
		),
	}
	plan := buildWandBExploitWorkflowPlan(wandbTarget, "runs", wandbEntity, wandbProject)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "wandb",
		Action:              "runs",
		ResourcesEnumerated: len(runs),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runWandbArtifacts(cmd *cobra.Command, args []string) error {
	client, headers, err := wandbClientFactory()
	if err != nil {
		return err
	}
	if wandbEntity == "" || wandbProject == "" {
		return missingFlagError("entity/project", formatCommandExample("wandb --target http://127.0.0.1:8080 artifacts --entity default --project my-project --type model"))
	}

	artifacts, err := client.ListArtifacts(wandbEntity, wandbProject, wandbArtifactType)
	if err != nil {
		return fmt.Errorf("listing artifacts: %w", outcomeAnnotate(err))
	}

	meta := map[string]interface{}{
		"module":         "wandb",
		"action":         "artifacts",
		"mutating":       false,
		"headers":        headerNames(headers),
		"entity":         wandbEntity,
		"project":        wandbProject,
		"artifact_type":  wandbArtifactType,
		"artifact_count": len(artifacts),
	}
	var artifactNames []string
	for _, a := range artifacts {
		artifactNames = append(artifactNames, a.Name)
	}
	meta["artifact_names"] = artifactNames

	findings := []report.Finding{
		newExploitFinding(
			report.SourceWandB, wandbTarget,
			fmt.Sprintf("W&B: %d %s artifact(s) found in %s/%s", len(artifacts), wandbArtifactType, wandbEntity, wandbProject),
			report.SeverityInfo,
			fmt.Sprintf("Found %d artifacts of type %q in %s/%s", len(artifacts), wandbArtifactType, wandbEntity, wandbProject),
			meta,
		),
	}
	plan := buildWandBExploitWorkflowPlan(wandbTarget, "artifacts", wandbEntity, wandbProject)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "wandb",
		Action:              "artifacts",
		ResourcesEnumerated: len(artifacts),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runWandbSecrets(cmd *cobra.Command, args []string) error {
	client, headers, err := wandbClientFactory()
	if err != nil {
		return err
	}
	if wandbEntity == "" || wandbProject == "" {
		return missingFlagError("entity/project", formatCommandExample("wandb --target http://127.0.0.1:8080 secrets --entity default --project my-project"))
	}

	runs, err := client.ListRuns(wandbEntity, wandbProject)
	if err != nil {
		return fmt.Errorf("listing runs: %w", outcomeAnnotate(err))
	}
	if wandbLimit > 0 && len(runs) > wandbLimit {
		runs = runs[:wandbLimit]
	}

	matches := client.ScanRunSecrets(runs)

	findings := []report.Finding{}
	if len(matches) == 0 {
		findings = append(findings, newExploitFinding(
			report.SourceWandB, wandbTarget,
			fmt.Sprintf("W&B: scanned %d run(s), no embedded secrets found", len(runs)),
			report.SeverityInfo,
			fmt.Sprintf("Scanned %d runs in %s/%s, no embedded secrets found", len(runs), wandbEntity, wandbProject),
			map[string]interface{}{
				"module":    "wandb",
				"action":    "secrets",
				"mutating":  false,
				"headers":   headerNames(headers),
				"entity":    wandbEntity,
				"project":   wandbProject,
				"run_count": len(runs),
				"secrets":   0,
				"stage":     "impact",
				"landed":    "read-confirmed",
			},
		))
	} else {
		meta := map[string]interface{}{
			"module":       "wandb",
			"action":       "secrets",
			"mutating":     false,
			"headers":      headerNames(headers),
			"entity":       wandbEntity,
			"project":      wandbProject,
			"run_count":    len(runs),
			"secret_count": len(matches),
			"stage":        "impact",
			"landed":       "read-confirmed",
		}
		var details []map[string]string
		var evidenceLines []string
		extractedCredentials := make([]interface{}, 0, len(matches))
		for _, m := range matches {
			details = append(details, map[string]string{
				"run_id":         m.RunID,
				"section":        m.Section,
				"key":            m.Key,
				"value":          m.Value,
				"value_redacted": m.ValueRedacted,
				"pattern":        m.Pattern,
			})
			// Surface each secret in the console finding with its real value —
			// consistent with the kubeflow/ray modules, where the operator needs the
			// credential itself, not a count or a redaction. The bounded preview keeps
			// the default view short; -v shows every value in full. The redacted form
			// stays in metadata.secrets[].value_redacted for anyone who wants it.
			evidenceLines = append(evidenceLines, fmt.Sprintf("%s = %s  (run %s, %s)",
				m.Key, m.Value, m.RunID, m.Section))
			// Feed the structured credential channel so `report view --credentials`
			// lists each named secret with its real value, not just the count.
			extractedCredentials = append(extractedCredentials, map[string]interface{}{
				"type":          "wandb-run-secret",
				"name":          m.Key,
				"value":         m.Value,
				"source_label":  "wandb-run-config",
				"source_target": wandbTarget,
				"target_url":    wandbTarget,
				"chainable":     false,
				"note":          fmt.Sprintf("run %s, %s section", m.RunID, m.Section),
			})
		}
		meta["secrets"] = details
		meta["extracted_credentials"] = extractedCredentials

		f := newExploitFinding(
			report.SourceWandB, wandbTarget,
			fmt.Sprintf("W&B: %d embedded secret(s) found in run configs", len(matches)),
			report.SeverityHigh,
			fmt.Sprintf("Found %d embedded secrets across %d runs in %s/%s", len(matches), len(runs), wandbEntity, wandbProject),
			meta,
		)
		f.Evidence = strings.Join(evidenceLines, "\n")
		findings = append(findings, f)
	}

	plan := buildWandBExploitWorkflowPlan(wandbTarget, "secrets", wandbEntity, wandbProject)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "wandb",
		Action:              "secrets",
		ResourcesEnumerated: len(runs),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func newWandbClient() (*wandb.Client, http.Header, error) {
	if strings.TrimSpace(wandbTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("wandb --target http://127.0.0.1:8080 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(wandbHeaders)
	if err != nil {
		return nil, nil, err
	}
	if headers.Get("Authorization") == "" {
		key := strings.TrimSpace(wandbAPIKey)
		if key == "" {
			key = strings.TrimSpace(os.Getenv("WANDB_API_KEY"))
		}
		if key != "" {
			headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("api:"+key)))
		}
	}
	target := normalizeAndWarnTarget(wandbTarget)
	wandbTarget = target
	client, err := wandb.NewClient(currentContext(), target, cfg.Timeout, headers)
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
