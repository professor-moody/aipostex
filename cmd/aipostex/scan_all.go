package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/credchain"
	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/exploit/a2a"
	"github.com/professor-moody/aipostex/pkg/exploit/bentoml"
	"github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/gradio"
	"github.com/professor-moody/aipostex/pkg/exploit/huggingface"
	"github.com/professor-moody/aipostex/pkg/exploit/jupyter"
	"github.com/professor-moody/aipostex/pkg/exploit/kubeflow"
	"github.com/professor-moody/aipostex/pkg/exploit/mcp"
	"github.com/professor-moody/aipostex/pkg/exploit/mlflow"
	"github.com/professor-moody/aipostex/pkg/exploit/ollama"
	openaicompat "github.com/professor-moody/aipostex/pkg/exploit/openaicompat"
	"github.com/professor-moody/aipostex/pkg/exploit/ray"
	"github.com/professor-moody/aipostex/pkg/exploit/tfserving"
	"github.com/professor-moody/aipostex/pkg/exploit/torchserve"
	"github.com/professor-moody/aipostex/pkg/exploit/triton"
	"github.com/professor-moody/aipostex/pkg/exploit/vectordb"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/vulncheck"
)

var (
	scanAllTargets     []string
	scanAllPorts       []string
	scanAllTopPorts    int
	scanAllSkipExploit bool
	scanAllSkipScan    bool
)

var scanAllServiceEnumerator = enumerateScanAllService

var assessNetworkCmd = &cobra.Command{
	Use:   "network [target...]",
	Short: "Full assessment: discover, scan, and enumerate AI services",
	Long: `Run a complete assessment pipeline against AI infrastructure:

  Phase 1: Network fingerprinting to discover AI services
  Phase 2: Vulnerability template scanning against discovered services
  Phase 3: Exploit module enumeration of each discovered service

Targets can be IPs, hostnames, or CIDR ranges.`,
	Example: strings.Join([]string{
		formatCommandExample("assess network --target 10.0.0.0/24"),
		formatCommandExample("assess network --target 10.0.0.50 --ports 11434,8000"),
		formatCommandExample("assess network --target 10.0.0.0/24 --skip-exploit"),
	}, "\n"),
	RunE: runScanAll,
}

func init() {
	assessNetworkCmd.Flags().StringSliceVarP(&scanAllTargets, "target", "t", nil, "Target host(s) or CIDR range(s)")
	assessNetworkCmd.Flags().StringSliceVar(&scanAllPorts, "ports", nil, "Ports to scan (comma-separated, ranges like 1-1000 supported)")
	assessNetworkCmd.Flags().IntVar(&scanAllTopPorts, "top-ports", 0, "Scan the top-N most common TCP ports (e.g. 100, 1000)")
	assessNetworkCmd.Flags().BoolVar(&scanAllSkipExploit, "skip-exploit", false, "Stop after vulnerability scanning (skip exploit enumeration)")
	assessNetworkCmd.Flags().BoolVar(&scanAllSkipScan, "skip-scan", false, "Stop after fingerprinting (skip vulnerability scanning and exploits)")
	assessNetworkCmd.Flags().StringSliceVar(&scanTags, "tags", nil, "Filter vuln templates by tags")
	assessNetworkCmd.Flags().StringSliceVar(&scanSeverities, "severity", nil, "Filter vuln templates by severity")
	assessNetworkCmd.Flags().StringVar(&scanTemplDir, "templates-dir", "", "Additional templates directory")
	assessNetworkCmd.Flags().StringVar(&scanMode, "mode", "detect", "Scan mode: detect (safe, default) or full (includes exploitation templates)")
}

func runScanAll(cmd *cobra.Command, args []string) error {
	if err := validateScanMode(scanMode); err != nil {
		return err
	}
	combined := append(append([]string{}, scanAllTargets...), args...)
	targets := uniqueSortedStrings(combined)
	if len(targets) == 0 {
		return missingFlagError("target", formatCommandExample("assess network --target 10.0.0.0/24"))
	}

	writer, err := getGroupedWriter()
	if err != nil {
		return err
	}
	defer writer.Close()

	if err := writer.WriteHeader(); err != nil {
		return err
	}

	var extractedPorts []int
	preferHTTPSPorts := explicitHTTPSPorts(targets)
	targets, extractedPorts = stripURLTargets(targets)

	// Validate and expand targets
	for _, target := range targets {
		if _, err := fingerprint.EstimateCIDRSize(target); err != nil {
			return fmt.Errorf("invalid target %s: %w", target, err)
		}
	}

	var hosts []string
	for _, target := range targets {
		if currentContext().Err() != nil {
			break
		}
		expanded, err := fingerprint.ExpandCIDR(target)
		if err != nil {
			return fmt.Errorf("invalid target %s: %w", target, err)
		}
		hosts = append(hosts, expanded...)
	}
	hosts = uniqueSortedHosts(hosts)
	if err := validateExpandedHosts(len(hosts)); err != nil {
		return err
	}

	ports, err := parsePorts(scanAllPorts)
	if err != nil {
		return err
	}
	if scanAllTopPorts > 0 {
		topPorts, err := topNPorts(scanAllTopPorts)
		if err != nil {
			return err
		}
		ports = append(ports, topPorts...)
	}
	ports = append(ports, extractedPorts...)
	ports = uniqueSortedPorts(ports)

	concurrency := cfg.Concurrency
	if cfg.Stealth {
		concurrency = 1
	}
	fingerprintConcurrency := networkFingerprintConcurrency(cmd, len(hosts)*len(ports), concurrency)

	allFindings := make([]report.Finding, 0)
	summary := scanAllSummary{}
	checkpointPath := fmt.Sprintf("aipostex-checkpoint-%d.jsonl", time.Now().UnixNano())
	infof("Checkpoint file: %s (removed on clean exit)", checkpointPath)

	// ── Phase 1: Fingerprint ──
	infof("Phase 1: Discovering AI services on %d host(s) across %d port(s)", len(hosts), len(ports))
	if cfg.Verbose {
		infof("TCP scan concurrency=%d dial-timeout=%s fingerprint-timeout=%s", fingerprintConcurrency, cfg.DialTimeout, cfg.FingerprintTimeout)
	}

	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return err
	}
	fingerprintHTTPClient, err := cfg.NewFingerprintHTTPClient()
	if err != nil {
		return err
	}
	scanner := fingerprint.NewScannerWithClient(fingerprintHTTPClient, cfg.FingerprintTimeout, fingerprintConcurrency)
	scanner.PreferHTTPSPorts = intSet(preferHTTPSPorts)
	if cfg.DialTimeout > 0 {
		scanner.DialTimeout = cfg.DialTimeout
	}
	scanner.Verbose = cfg.Verbose
	scanner.Context = currentContext()
	scanner.OnProgress = func(ev fingerprint.ScanProgressEvent) {
		logFingerprintProgress(ev, cfg.Verbose)
	}
	observations := dedupePortObservations(scanner.ScanRange(hosts, ports))
	selection := selectableFingerprintResults(observations)
	templateResults := selection.ResultsOnly()
	results := selection.AllResults()
	summary.ServicesDiscovered = len(results)
	summary.AmbiguousServicesExpanded = selection.AmbiguousExpanded
	summary.NonHTTPTemplateSkips = selection.NonHTTPTemplateSkips

	honeypotSignals := fingerprint.DetectHoneypotSignals(observations, len(ports))

	infof("Discovered %d open port(s)", len(observations))
	printDiscoveryTable(stderrWriter, observations)
	printHoneypotWarnings(honeypotSignals)

	for _, observation := range observations {
		allFindings = append(allFindings, portObservationToFinding(observation))
	}
	for _, skipped := range selection.NonHTTPResults {
		allFindings = append(allFindings, nonHTTPTemplateSkipFinding(skipped))
	}

	writeCheckpoint(checkpointPath, allFindings)

	if scanAllSkipScan || currentContext().Err() != nil {
		result := writeScanAllResults(writer, allFindings, observations, results, summary)
		maybeRemoveCheckpoint(checkpointPath, result)
		return result
	}

	// ── Phase 2: Vulnerability Scan ──
	if len(templateResults) > 0 {
		fmt.Fprintf(stderrWriter, "%s\n", consoleSectionHeader("Phase 2: Vulnerability Scan"))
		if parseScanMode(scanMode) == vulncheck.ModeFull {
			infof("Mode: Full Assessment (detection + exploitation)")
		} else {
			infof("Mode: Detection Only (no exploitation templates)")
		}

		engine := vulncheck.NewEngine(cfg.Timeout, concurrency)
		engine.Verbose = cfg.Verbose
		engine.Context = currentContext()
		engine.HTTPClient = httpClient
		engine.Mode = parseScanMode(scanMode)

		engine.OnProgress = func(ev vulncheck.ProgressEvent) {
			if ev.Type == "match" && cfg.Format != "console" {
				for _, f := range ev.Findings {
					fmt.Fprintf(stderrWriter, " %s [%s] %s\n",
						output.FormatSeverity(f.Severity), f.TemplateID, f.Title)
				}
			}
		}

		if err := engine.LoadEmbeddedTemplates(); err != nil {
			warnf("loading embedded templates: %v", err)
		}
		if scanTemplDir != "" {
			if err := engine.LoadTemplates(scanTemplDir); err != nil {
				warnf("loading templates from %s: %v", scanTemplDir, err)
			}
		}

		for _, selected := range selection.Results {
			if currentContext().Err() != nil {
				break
			}
			r := selected.Result
			tags := normalizeServiceTags(r.Service, scanTags)
			matching := engine.FilteredTemplates(tags, scanSeverities)
			if len(matching) == 0 {
				continue
			}
			summary.TemplateScanAttempts++
			findings, metrics, err := engine.ScanDetailed(r.URL, tags, scanSeverities)
			if err != nil {
				summary.ServicesWithScanFailures++
				if cfg.Verbose {
					warnf("vuln scan %s: %v", r.URL, err)
				}
				continue
			}
			hadFailure := false
			summary.TemplateRequestErrors += metrics.RequestErrors
			if metrics.RequestErrors > 0 {
				hadFailure = true
			}
			summary.TemplateErrors += metrics.TemplateErrors
			if metrics.TemplateErrors > 0 {
				hadFailure = true
			}
			if hadFailure {
				summary.ServicesWithScanFailures++
			}
			annotateFindingsForSelectedFingerprint(findings, selected)
			allFindings = append(allFindings, findings...)
		}
	}

	writeCheckpoint(checkpointPath, allFindings)

	if scanAllSkipExploit || currentContext().Err() != nil {
		result := writeScanAllResults(writer, allFindings, observations, results, summary)
		maybeRemoveCheckpoint(checkpointPath, result)
		return result
	}

	// ── Phase 3: Exploit Enumeration ──
	if len(results) > 0 {
		fmt.Fprintf(stderrWriter, "%s\n", consoleSectionHeader("Phase 3: Service Enumeration"))
		enumOut := runExploitEnumeration(results, httpClient)
		summary.EnumerationAttempts = enumOut.Attempts
		summary.EnumerationFailures = enumOut.Failures
		summary.EnumerationPartialFailures = enumOut.PartialFailures
		summary.EnumerationSkipped = enumOut.Skipped
		summary.EnumerationNotApplicable = enumOut.NotApplicable
		allFindings = append(allFindings, enumOut.Findings...)
	}

	writeCheckpoint(checkpointPath, allFindings)
	result := writeScanAllResults(writer, allFindings, observations, results, summary)
	maybeRemoveCheckpoint(checkpointPath, result)
	return result
}

func writeCheckpoint(path string, findings []report.Finding) {
	f, err := os.Create(path)
	if err != nil {
		warnf("checkpoint write failed: %v", err)
		return
	}
	enc := json.NewEncoder(f)
	for _, finding := range findings {
		_ = enc.Encode(finding)
	}
	_ = f.Close()
}

func removeCheckpoint(path string) {
	_ = os.Remove(path)
}

func maybeRemoveCheckpoint(path string, result error) {
	code := exitcode.Code(result)
	if code == exitcode.OK || code == exitcode.Findings {
		removeCheckpoint(path)
	} else {
		infof("Checkpoint preserved at %s (non-success exit)", path)
	}
}

func writeScanAllResults(writer output.Writer, allFindings []report.Finding, observations []fingerprint.PortObservation, results []fingerprint.Result, summary scanAllSummary) error {
	workflowPlans := make([]workflowPlan, 0, len(results))
	workflowPlans = append(workflowPlans, buildObservationWorkflowPlans(observations)...)

	credStore := credchain.ExtractFromFindings(allFindings)
	if credStore.TotalCredentials() > 0 {
		infof("Discovered %d credential(s) for %d target(s)", credStore.TotalCredentials(), credStore.TotalTargets())
		workflowPlans = enrichWorkflowPlansWithCredentials(workflowPlans, credStore)

		if cfg.AutoChain {
			chainActions := credchain.GenerateChainActions(credStore)
			if len(chainActions) > 0 {
				infof("Auto-chain: generated %d follow-up action suggestion(s) from discovered credentials", len(chainActions))
				for _, action := range chainActions {
					infof("  -> %s", action.Description)
				}
				chainFinding := newExploitFinding(
					report.SourceCredential,
					"auto-chain",
					fmt.Sprintf("Auto-chain: %d credential-forwarding action(s) available", len(chainActions)),
					report.SeverityInfo,
					fmt.Sprintf("Discovered %d credential(s) across %d target(s). Auto-chain generated %d follow-up commands.", credStore.TotalCredentials(), credStore.TotalTargets(), len(chainActions)),
					map[string]interface{}{
						"module":       "credchain",
						"action":       "auto-chain",
						"mutating":     false,
						"action_count": len(chainActions),
					},
				)
				var evidence []string
				for _, a := range chainActions {
					evidence = append(evidence, fmt.Sprintf("[%s] %s\n  Command: aipostex %s", a.CredentialType, a.Description, a.Command))
				}
				chainFinding.Evidence = strings.Join(evidence, "\n\n")
				allFindings = append(allFindings, chainFinding)
			}
		}
	}

	plansByURL := buildWorkflowPlanIndex(workflowPlans)
	for i := range allFindings {
		if plan, ok := plansByURL[allFindings[i].Target]; ok {
			allFindings[i].Metadata = attachWorkflowToMetadata(allFindings[i].Metadata, plan)
		}
	}

	deduped := dedupeAndSortFindings(annotateFindingsForOutput(allFindings))
	stats := findingStats(deduped)

	applyHostNextSteps(writer, workflowPlans, deduped)
	for _, finding := range deduped {
		if err := writer.WriteFinding(finding); err != nil {
			warnf("writing finding: %v", err)
		}
	}

	if err := writer.WriteFooter(stats); err != nil {
		return err
	}

	// Summary
	summary.FindingsEmitted = len(deduped)
	printScanAllSummary(stderrWriter, summary, stats)
	if cfg.Verbose {
		printWorkflowPlans(stderrWriter, workflowPlans, cfg.Verbose)
	} else {
		printGatedSummary(stderrWriter, workflowPlans)
	}

	hasFailures := summary.ServicesWithScanFailures > 0 || summary.TemplateRequestErrors > 0 || summary.TemplateErrors > 0 || summary.EnumerationFailures > 0 || summary.EnumerationPartialFailures > 0
	if len(deduped) > 0 && hasFailures {
		succeeded := summary.TemplateScanAttempts - summary.ServicesWithScanFailures
		succeeded += summary.EnumerationAttempts - summary.EnumerationFailures - summary.EnumerationPartialFailures
		failed := summary.ServicesWithScanFailures + summary.EnumerationFailures + summary.EnumerationPartialFailures
		return &exitcode.FindingsPartialError{
			FindingsCount: len(deduped),
			Succeeded:     succeeded,
			Failed:        failed,
			Cause: fmt.Errorf(
				"assessment incomplete: %d scan failure(s), %d request error(s), %d template error(s), %d enumeration failure(s), %d partial enumeration(s)",
				summary.ServicesWithScanFailures,
				summary.TemplateRequestErrors,
				summary.TemplateErrors,
				summary.EnumerationFailures,
				summary.EnumerationPartialFailures,
			),
		}
	}
	if len(deduped) > 0 {
		return &exitcode.FindingsError{Count: len(deduped)}
	}
	if hasFailures {
		succeeded := summary.TemplateScanAttempts - summary.ServicesWithScanFailures
		succeeded += summary.EnumerationAttempts - summary.EnumerationFailures - summary.EnumerationPartialFailures
		failed := summary.ServicesWithScanFailures + summary.EnumerationFailures + summary.EnumerationPartialFailures
		return &exitcode.PartialError{
			Succeeded: succeeded,
			Failed:    failed,
			Cause: fmt.Errorf(
				"assessment incomplete: %d scan failure(s), %d request error(s), %d template error(s), %d enumeration failure(s), %d partial enumeration(s)",
				summary.ServicesWithScanFailures,
				summary.TemplateRequestErrors,
				summary.TemplateErrors,
				summary.EnumerationFailures,
				summary.EnumerationPartialFailures,
			),
		}
	}
	return nil
}

func parsePorts(portFlags []string) ([]int, error) {
	if len(portFlags) == 0 {
		return cfg.Ports, nil
	}
	var ports []int
	for _, p := range portFlags {
		for _, ps := range strings.Split(p, ",") {
			ps = strings.TrimSpace(ps)
			if ps == "" {
				continue
			}
			expanded, err := parsePortToken(ps)
			if err != nil {
				return nil, err
			}
			ports = append(ports, expanded...)
		}
	}
	return uniqueSortedPorts(ports), nil
}

// parsePortToken parses a single port token which can be either a plain
// number ("8080") or a range ("1-10000").
func parsePortToken(token string) ([]int, error) {
	if parts := strings.SplitN(token, "-", 2); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		lo, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q: %w", token, err)
		}
		hi, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q: %w", token, err)
		}
		if err := validatePortNumber(lo); err != nil {
			return nil, fmt.Errorf("invalid port range %q: %w", token, err)
		}
		if err := validatePortNumber(hi); err != nil {
			return nil, fmt.Errorf("invalid port range %q: %w", token, err)
		}
		if lo > hi {
			return nil, fmt.Errorf("invalid port range %q: start (%d) must be <= end (%d)", token, lo, hi)
		}
		ports := make([]int, 0, hi-lo+1)
		for p := lo; p <= hi; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}
	port, err := strconv.Atoi(token)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", token, err)
	}
	if err := validatePortNumber(port); err != nil {
		return nil, err
	}
	return []int{port}, nil
}

// topNPorts returns the top-N most commonly open TCP ports.
func topNPorts(n int) ([]int, error) {
	all := fingerprint.TopTCPPorts()
	if n <= 0 {
		return nil, fmt.Errorf("--top-ports must be greater than 0, got %d", n)
	}
	if n > len(all) {
		n = len(all)
	}
	return all[:n], nil
}

type enumResult struct {
	Findings        []report.Finding
	Attempts        int
	Failures        int
	PartialFailures int
	NotApplicable   int
	Skipped         int
}

func runExploitEnumeration(results []fingerprint.Result, httpClient *http.Client) enumResult {
	var out enumResult

	serviceMap := make(map[string][]fingerprint.Result)
	for _, r := range results {
		serviceMap[r.Service] = append(serviceMap[r.Service], r)
	}

	services := make([]string, 0, len(serviceMap))
	for service := range serviceMap {
		services = append(services, service)
	}
	sort.Strings(services)

	skippedServices := make(map[string]struct{})

	for _, service := range services {
		svcResults := serviceMap[service]
		sort.Slice(svcResults, func(i, j int) bool {
			return svcResults[i].URL < svcResults[j].URL
		})
		for _, r := range svcResults {
			if currentContext().Err() != nil {
				return out
			}

			out.Attempts++
			enumFindings, err := scanAllServiceEnumerator(service, r.URL, httpClient)
			if err != nil {
				if errors.Is(err, errNoEnumerator) {
					out.Skipped++
					if _, seen := skippedServices[service]; !seen {
						skippedServices[service] = struct{}{}
						infof("No enumerator for %q at %s (template scan still applied)", service, r.URL)
					}
					continue
				}
				if common.IsPartialResult(err) {
					out.PartialFailures++
					out.Findings = append(out.Findings, enumFindings...)
					warnf("partial enumeration of %s at %s: %v", service, r.URL, err)
					continue
				}
				// A definitive "not this service type" response (404/405/501) to a
				// type-specific enumeration probe means the host:port is reachable but is not
				// the fingerprinted identity. This is expected ONLY when this identity was a
				// speculative candidate — an ambiguous/proxy/suspected expansion (e.g. an MCP
				// Inspector's HTML hit by an API probe). For a CONFIRMED fingerprint a 404/501
				// is a real coverage gap, so it stays a hard failure. Honest on any target.
				if isNotApplicableEnumError(err) && r.MatchKind != fingerprint.MatchKindConfirmed {
					out.NotApplicable++
					status, _ := common.HTTPErrorStatus(err)
					infof("not applicable: %s is reachable but not %s (candidate identity, HTTP %d)", r.URL, service, status)
					continue
				}
				out.Failures++
				warnf("enumerating %s at %s: %v", service, r.URL, err)
				continue
			}
			out.Findings = append(out.Findings, enumFindings...)
		}
	}

	return out
}

var errNoEnumerator = fmt.Errorf("no enumerator implemented")

// isNotApplicableEnumError reports whether an enumeration error is a definitive
// "not this service type" HTTP response (404 Not Found / 405 Method Not Allowed /
// 501 Not Implemented) to a type-specific probe — i.e. the host:port is reachable but
// is not the fingerprinted identity (common when an ambiguous port is probed as several
// candidates). This is expected on ANY target and must not be counted as an assessment
// failure. A transport error, auth challenge, or 5xx from the correct service is NOT
// not-applicable and still counts as a real failure.
func isNotApplicableEnumError(err error) bool {
	status, ok := common.HTTPErrorStatus(err)
	if !ok {
		return false
	}
	return status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented
}

func enumerateScanAllService(service, target string, httpClient *http.Client) ([]report.Finding, error) {
	switch service {
	case "ollama":
		return runScanAllOllamaEnum(target, httpClient)
	case "chromadb", "qdrant", "weaviate", "milvus":
		return runScanAllVectorDBEnum(target, service, httpClient)
	case "pgvector", "postgresql":
		return runScanAllPgvectorEnum(target)
	case "jupyter":
		return runScanAllJupyterEnum(target, httpClient)
	case "ray":
		return runScanAllRayEnum(target, httpClient)
	case "mlflow":
		return runScanAllMLflowEnum(target, httpClient)
	case "gradio":
		return runScanAllGradioEnum(target, httpClient)
	case "bentoml":
		return runScanAllBentoMLEnum(target, httpClient)
	case "mcp-sse", "mcp-inspector", "mcpjam-inspector":
		return runScanAllMCPEnum(target, httpClient)
	case "triton":
		return runScanAllTritonEnum(target, httpClient)
	case "torchserve", "torchserve-mgmt":
		return runScanAllTorchServeEnum(target, httpClient)
	case "tfserving":
		return runScanAllTFServingEnum(target, httpClient)
	case "hf-tgi", "hf-tei":
		return runScanAllHuggingFaceEnum(target, httpClient)
	case "kubeflow":
		return runScanAllKubeflowEnum(target, httpClient)
	case "a2a":
		return runScanAllA2AEnum(target, httpClient)
	case "litellm":
		return runScanAllLiteLLMEnum(target, httpClient)
	case "openai-compatible", "vllm", "lmstudio", "localai":
		return runScanAllOpenAICompatEnum(target, httpClient)
	default:
		return nil, errNoEnumerator
	}
}

func runScanAllOllamaEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := ollama.NewClientWithHeaders(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	result, err := client.Enumerate()
	if err != nil {
		return nil, err
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceOllama,
			target,
			"Ollama service enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated Ollama %s with %d model(s)", result.Version, result.TotalModels),
			map[string]interface{}{
				"module":         "ollama",
				"action":         "enum",
				"mutating":       false,
				"provider":       "ollama",
				"version":        result.Version,
				"installed":      result.TotalModels,
				"running_models": len(result.RunningModels),
			},
		),
	}
	modelNames := make([]string, 0, len(result.Models))
	for _, model := range result.Models {
		modelNames = append(modelNames, model.Name)
	}
	summaryPlan := buildOllamaEnumWorkflowPlan(target, modelNames)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)

	for _, model := range result.Models {
		finding := newExploitFinding(
			report.SourceOllama,
			target,
			fmt.Sprintf("Ollama model discovered: %s", model.Name),
			report.SeverityInfo,
			fmt.Sprintf("Model %s is installed (%s, %s)", model.Name, model.Details.Family, model.Details.ParameterSize),
			map[string]interface{}{
				"module":     "ollama",
				"action":     "enum",
				"mutating":   false,
				"provider":   "ollama",
				"model":      model.Name,
				"family":     model.Details.Family,
				"parameters": model.Details.ParameterSize,
			},
		)
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildOllamaModelWorkflowPlan(target, model.Name))
		findings = append(findings, finding)
	}

	for _, running := range result.RunningModels {
		finding := newExploitFinding(
			report.SourceOllama,
			target,
			fmt.Sprintf("Ollama model currently running: %s", running.Name),
			report.SeverityInfo,
			fmt.Sprintf("Model %s is loaded in VRAM until %s", running.Name, running.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")),
			map[string]interface{}{
				"module":    "ollama",
				"action":    "running",
				"mutating":  false,
				"provider":  "ollama",
				"model":     running.Name,
				"size_vram": running.SizeVRAM,
			},
		)
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildOllamaModelWorkflowPlan(target, running.Name))
		findings = append(findings, finding)
	}
	return findings, nil
}

func runScanAllVectorDBEnum(target, provider string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := vectordb.NewProviderClient(currentContext(), provider, target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	if configurable, ok := client.(vectordb.RuntimeConfigurable); ok {
		configurable.SetHTTPClient(httpClient)
	}

	version, err := client.ServiceVersion()
	if err != nil {
		return nil, err
	}
	collections, err := client.ListCollectionsInfo()
	if err != nil {
		return nil, err
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceVectorDB,
			target,
			fmt.Sprintf("%s service enumerated", englishTitleCaser.String(client.ProviderName())),
			report.SeverityInfo,
			fmt.Sprintf("Enumerated %d collection(s) from %s (version: %s)", len(collections), client.ProviderName(), version),
			map[string]interface{}{
				"module":           "vectordb",
				"action":           "enum",
				"mutating":         false,
				"provider":         client.ProviderName(),
				"version":          version,
				"collection_count": len(collections),
			},
		),
	}
	collectionNames := make([]string, 0, len(collections))
	for _, collection := range collections {
		collectionNames = append(collectionNames, collection.Name)
	}
	summaryPlan := buildVectorDBEnumWorkflowPlan(target, client.ProviderName(), collectionNames)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)

	for _, collection := range collections {
		metadata := map[string]interface{}{
			"module":     "vectordb",
			"action":     "enum",
			"mutating":   false,
			"provider":   client.ProviderName(),
			"collection": collection.Name,
			"class":      collection.Name,
			"count":      collection.Count,
		}
		if collection.ID != "" {
			metadata["collection_id"] = collection.ID
		}
		finding := newExploitFinding(
			report.SourceVectorDB,
			target,
			fmt.Sprintf("%s collection discovered: %s", englishTitleCaser.String(client.ProviderName()), collection.Name),
			report.SeverityInfo,
			fmt.Sprintf("Collection %s is accessible with %s record count", collection.Name, renderCount(collection.Count)),
			metadata,
		)
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildVectorDBCollectionWorkflowPlan(target, client.ProviderName(), collection.Name))
		findings = append(findings, finding)
	}
	return findings, nil
}

func runScanAllJupyterEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := jupyter.NewClient(currentContext(), target, "", cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient

	status, err := client.ServerStatus()
	if err != nil {
		return nil, err
	}
	kernels, kernelErr := client.ListKernels()
	notebooks, notebookErr := client.ListNotebooks()

	findings := []report.Finding{
		newExploitFinding(
			report.SourceJupyter,
			target,
			"Jupyter server enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated Jupyter server with %d kernel(s) and %d notebook item(s)", len(kernels), len(notebooks)),
			map[string]interface{}{
				"module":       "jupyter",
				"action":       "enum",
				"mutating":     false,
				"provider":     "jupyter",
				"kernel_count": len(kernels),
				"started":      status.Started,
			},
		),
	}
	notebookPaths := make([]string, 0, len(notebooks))
	for _, notebook := range notebooks {
		if strings.EqualFold(notebook.Type, "notebook") {
			notebookPaths = append(notebookPaths, notebook.Path)
		}
	}
	kernelIDs := make([]string, 0, len(kernels))
	for _, kernel := range kernels {
		kernelIDs = append(kernelIDs, kernel.ID)
	}
	summaryPlan := buildJupyterEnumWorkflowPlan(target, notebookPaths, kernelIDs)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	if kernelErr != nil {
		warnf("listing jupyter kernels at %s: %v", target, kernelErr)
		findings[0].Metadata["enumeration_partial"] = true
	}
	if notebookErr != nil {
		warnf("listing jupyter notebooks at %s: %v", target, notebookErr)
		findings[0].Metadata["enumeration_partial"] = true
		if pe, ok := common.AsPartialResult(notebookErr); ok {
			findings[0].Metadata["failed_paths"] = pe.FailedPaths
		}
	}
	if kernelErr != nil || notebookErr != nil {
		var failedComponents []string
		if kernelErr != nil {
			failedComponents = append(failedComponents, "kernels")
		}
		if notebookErr != nil {
			failedComponents = append(failedComponents, "notebooks")
		}
		findings = append(findings, newExploitFinding(
			report.SourceJupyter,
			target,
			"Jupyter enumeration incomplete",
			report.SeverityInfo,
			fmt.Sprintf("Could not fully enumerate Jupyter at %s: %s", target, strings.Join(failedComponents, ", ")),
			map[string]interface{}{
				"module":            "jupyter",
				"action":            "enum-incomplete",
				"mutating":          false,
				"failed_components": strings.Join(failedComponents, ","),
			},
		))
		return findings, &common.PartialResultError{
			FailedPaths: failedComponents,
			Cause:       errors.Join(kernelErr, notebookErr),
		}
	}
	return findings, nil
}

func runScanAllRayEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := ray.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient

	info, err := client.DashboardInfo()
	if err != nil {
		return nil, err
	}
	jobs, jobsErr := client.ListJobs()
	jobIDs := make([]string, 0, len(jobs))
	for _, job := range jobs {
		jobIDs = append(jobIDs, job.ID)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceRay,
			target,
			"Ray dashboard enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated Ray dashboard metadata (version=%s, jobs_api=%t, session=%s)", safeLabel(info.Version), info.JobsAPIReachable, safeLabel(info.SessionName)),
			map[string]interface{}{
				"module":              "ray",
				"action":              "enum",
				"mutating":            false,
				"provider":            "ray",
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
	summaryPlan := buildRayEnumWorkflowPlan(target, info.JobsAPIReachable, jobIDs)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	if info.JobsAPIReachable {
		finding := newExploitFinding(
			report.SourceRay,
			target,
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
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildRayEnumWorkflowPlan(target, true, jobIDs))
		findings = append(findings, finding)
	}
	if jobsErr != nil {
		warnf("listing ray jobs at %s: %v", target, jobsErr)
		findings[0].Metadata["enumeration_partial"] = true
		findings = append(findings, newExploitFinding(
			report.SourceRay,
			target,
			"Ray enumeration incomplete",
			report.SeverityInfo,
			fmt.Sprintf("Could not fully enumerate Ray jobs at %s: %v", target, jobsErr),
			map[string]interface{}{
				"module":            "ray",
				"action":            "enum-incomplete",
				"mutating":          false,
				"failed_components": "jobs",
			},
		))
		return findings, &common.PartialResultError{
			FailedPaths: []string{"jobs"},
			Cause:       jobsErr,
		}
	}
	return findings, nil
}

func runScanAllMLflowEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := mlflow.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient

	limit := mlflowLimit
	if limit <= 0 {
		limit = 10
	}
	info, err := client.ServerInfo()
	if err != nil {
		return nil, err
	}
	experiments, expErr := client.ListExperiments(limit)
	runs, runErr := client.ListRuns("", limit)
	models, registryErr := client.ListRegisteredModels(limit)

	findings := []report.Finding{
		newExploitFinding(
			report.SourceMLflow,
			target,
			"MLflow tracking server enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated MLflow server with %d experiment(s), %d visible run(s), registry_reachable=%t", len(experiments), len(runs), info.RegistryReachable),
			map[string]interface{}{
				"module":             "mlflow",
				"action":             "enum",
				"mutating":           false,
				"provider":           "mlflow",
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
	summaryPlan := buildMLflowEnumWorkflowPlan(target, experimentNames, runIDs)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	if len(runs) > 0 {
		finding := newExploitFinding(
			report.SourceMLflow,
			target,
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
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowRunWorkflowPlan(target, runs[0].ID, ""))
		findings = append(findings, finding)
	}
	if len(models) > 0 {
		finding := newExploitFinding(
			report.SourceMLflow,
			target,
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
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildMLflowRegistryWorkflowPlan(target, models[0].Name))
		findings = append(findings, finding)
	}
	if expErr != nil {
		warnf("listing mlflow experiments at %s: %v", target, expErr)
	}
	if runErr != nil {
		warnf("listing mlflow runs at %s: %v", target, runErr)
	}
	if registryErr != nil && cfg.Verbose {
		warnf("listing mlflow registry models at %s: %v", target, registryErr)
	}
	if expErr != nil || runErr != nil {
		var failedComponents []string
		if expErr != nil {
			failedComponents = append(failedComponents, "experiments")
		}
		if runErr != nil {
			failedComponents = append(failedComponents, "runs")
		}
		if registryErr != nil {
			failedComponents = append(failedComponents, "registry")
		}
		findings[0].Metadata["enumeration_partial"] = true
		findings[0].Metadata["failed_components"] = strings.Join(failedComponents, ",")
		findings = append(findings, newExploitFinding(
			report.SourceMLflow,
			target,
			"MLflow enumeration incomplete",
			report.SeverityInfo,
			fmt.Sprintf("Could not fully enumerate MLflow at %s: %s", target, strings.Join(failedComponents, ", ")),
			map[string]interface{}{
				"module":            "mlflow",
				"action":            "enum-incomplete",
				"mutating":          false,
				"failed_components": strings.Join(failedComponents, ","),
			},
		))
		return findings, &common.PartialResultError{
			FailedPaths: failedComponents,
			Cause:       errors.Join(expErr, runErr, registryErr),
		}
	}
	return findings, nil
}

func runScanAllGradioEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := gradio.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient

	cfgResult, err := client.Config()
	if err != nil {
		return nil, err
	}
	findings := []report.Finding{
		newExploitFinding(
			report.SourceGradio,
			target,
			"Gradio app enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated Gradio app %s with %d endpoint(s)", safeLabel(cfgResult.Title), len(cfgResult.Endpoints)),
			map[string]interface{}{
				"module":         "gradio",
				"action":         "enum",
				"mutating":       false,
				"provider":       "gradio",
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
	summaryPlan := buildGradioEnumWorkflowPlan(target, apiNames, fnIndexes)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)
	if len(cfgResult.Endpoints) > 0 {
		finding := newExploitFinding(
			report.SourceGradio,
			target,
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
		findings = append(findings, finding)
	}
	for _, endpoint := range cfgResult.Endpoints {
		finding := newExploitFinding(
			report.SourceGradio,
			target,
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
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildGradioEndpointWorkflowPlan(target, endpoint.APIName, endpoint.FnIndex))
		findings = append(findings, finding)
	}
	return findings, nil
}

func runScanAllBentoMLEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := bentoml.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	info, err := client.Enumerate()
	if err != nil {
		return nil, err
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceBentoML,
			target,
			"BentoML service enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated BentoML service (name=%s, version=%s, healthy=%t, routes=%d)",
				safeLabel(info.Name), safeLabel(info.Version), info.Healthy, len(info.Routes)),
			map[string]interface{}{
				"module":      "bentoml",
				"action":      "enum",
				"mutating":    false,
				"provider":    "bentoml",
				"version":     info.Version,
				"healthy":     info.Healthy,
				"route_count": len(info.Routes),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "bentoml-enum", "service")
	return findings, nil
}

func runScanAllMCPEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := mcp.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	defer client.Close()

	if err := client.Initialize(); err != nil {
		return nil, err
	}
	tools, toolsErr := client.ListTools()
	prompts, promptsErr := client.ListPrompts()
	resources, resourcesErr := client.ListResources()

	transport := mcp.InferTransport(target)
	findings := []report.Finding{
		newExploitFinding(
			report.SourceMCP,
			target,
			"MCP server enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated MCP server with %d tool(s), %d prompt(s), %d resource(s) via %s",
				len(tools), len(prompts), len(resources), transport),
			map[string]interface{}{
				"module":         "mcp",
				"action":         "enum",
				"mutating":       false,
				"provider":       "mcp",
				"transport":      transport,
				"tool_count":     len(tools),
				"prompt_count":   len(prompts),
				"resource_count": len(resources),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "mcp-enum", "server")

	for _, tool := range tools {
		finding := newExploitFinding(
			report.SourceMCP,
			target,
			fmt.Sprintf("MCP tool discovered: %s", tool.Name),
			report.SeverityInfo,
			fmt.Sprintf("MCP tool %s: %s", tool.Name, safeLabel(tool.Description)),
			map[string]interface{}{
				"module":   "mcp",
				"action":   "enum",
				"mutating": false,
				"provider": "mcp",
				"tool":     tool.Name,
			},
		)
		findings = append(findings, finding)
	}

	if toolsErr != nil {
		warnf("listing MCP tools at %s: %v", target, toolsErr)
	}
	if promptsErr != nil {
		warnf("listing MCP prompts at %s: %v", target, promptsErr)
	}
	if resourcesErr != nil {
		warnf("listing MCP resources at %s: %v", target, resourcesErr)
	}
	if toolsErr != nil || promptsErr != nil || resourcesErr != nil {
		var failedComponents []string
		if toolsErr != nil {
			failedComponents = append(failedComponents, "tools")
		}
		if promptsErr != nil {
			failedComponents = append(failedComponents, "prompts")
		}
		if resourcesErr != nil {
			failedComponents = append(failedComponents, "resources")
		}
		findings[0].Metadata["enumeration_partial"] = true
		findings[0].Metadata["failed_components"] = strings.Join(failedComponents, ",")
		findings = append(findings, newExploitFinding(
			report.SourceMCP,
			target,
			"MCP enumeration incomplete",
			report.SeverityInfo,
			fmt.Sprintf("Could not fully enumerate MCP server at %s: %s", target, strings.Join(failedComponents, ", ")),
			map[string]interface{}{
				"module":            "mcp",
				"action":            "enum-incomplete",
				"mutating":          false,
				"failed_components": strings.Join(failedComponents, ","),
			},
		))
		return findings, &common.PartialResultError{
			FailedPaths: failedComponents,
			Cause:       errors.Join(toolsErr, promptsErr, resourcesErr),
		}
	}
	return findings, nil
}

func runScanAllTritonEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := triton.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	meta, err := client.Enumerate()
	if err != nil {
		return nil, err
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceTriton,
			target,
			"Triton Inference Server enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated Triton server (name=%s, version=%s, ready=%t, live=%t)",
				safeLabel(meta.Name), safeLabel(meta.Version), meta.Ready, meta.Live),
			map[string]interface{}{
				"module":     "triton",
				"action":     "enum",
				"mutating":   false,
				"provider":   "triton",
				"version":    meta.Version,
				"ready":      meta.Ready,
				"live":       meta.Live,
				"extensions": len(meta.Extensions),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "triton-enum", "server")
	return findings, nil
}

func runScanAllTorchServeEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := torchserve.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	models, healthy, err := client.Enumerate()
	if err != nil {
		return nil, err
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceTorchServe,
			target,
			"TorchServe service enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated TorchServe (healthy=%t, models=%d)", healthy, len(models)),
			map[string]interface{}{
				"module":      "torchserve",
				"action":      "enum",
				"mutating":    false,
				"provider":    "torchserve",
				"healthy":     healthy,
				"model_count": len(models),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "torchserve-enum", "service")

	for _, model := range models {
		finding := newExploitFinding(
			report.SourceTorchServe,
			target,
			fmt.Sprintf("TorchServe model: %s", model.Name),
			report.SeverityInfo,
			fmt.Sprintf("Model %s (status=%s)", model.Name, safeLabel(model.Status)),
			map[string]interface{}{
				"module":   "torchserve",
				"action":   "enum",
				"mutating": false,
				"provider": "torchserve",
				"model":    model.Name,
			},
		)
		findings = append(findings, finding)
	}
	return findings, nil
}

func runScanAllTFServingEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := tfserving.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	info, err := client.Enumerate()
	if err != nil {
		return nil, err
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceTFServing,
			target,
			"TensorFlow Serving enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated TF Serving (reachable=%t, models_found=%t, metrics=%t)",
				info.Reachable, info.ModelsFound, info.MetricsFound),
			map[string]interface{}{
				"module":       "tfserving",
				"action":       "enum",
				"mutating":     false,
				"provider":     "tfserving",
				"reachable":    info.Reachable,
				"models_found": info.ModelsFound,
				"metrics":      info.MetricsFound,
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "tfserving-enum", "service")

	models, err := client.ListModels()
	if err == nil {
		for _, m := range models {
			for _, v := range m.Versions {
				finding := newExploitFinding(
					report.SourceTFServing,
					target,
					fmt.Sprintf("TF Serving model: %s (v%d)", m.Name, v.Version),
					report.SeverityInfo,
					fmt.Sprintf("Model %s version %d state=%s", m.Name, v.Version, safeLabel(v.State)),
					map[string]interface{}{
						"module":   "tfserving",
						"action":   "models",
						"mutating": false,
						"provider": "tfserving",
						"model":    m.Name,
						"version":  v.Version,
						"state":    v.State,
					},
				)
				findings = append(findings, finding)
			}
		}
	}
	return findings, nil
}

func runScanAllLiteLLMEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := openaicompat.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient

	readiness, readErr := client.ReadinessInfo()
	models, modelsErr := client.ListModels()

	var findings []report.Finding
	if readErr == nil && readiness != nil {
		findings = append(findings, newExploitFinding(
			report.SourceOpenAICompat,
			target,
			fmt.Sprintf("LiteLLM proxy identified: v%s", safeLabel(readiness.Version)),
			report.SeverityHigh,
			fmt.Sprintf("LiteLLM proxy v%s is accessible. Status: %s", safeLabel(readiness.Version), safeLabel(readiness.Status)),
			map[string]interface{}{
				"module": "litellm", "action": "enum", "mutating": false,
				"provider": "litellm", "version": readiness.Version,
			},
		))
	}
	if modelsErr == nil && len(models) > 0 {
		modelNames := make([]string, 0, len(models))
		for _, m := range models {
			modelNames = append(modelNames, m.ID)
		}
		findings = append(findings, newExploitFinding(
			report.SourceOpenAICompat,
			target,
			fmt.Sprintf("LiteLLM exposes %d model(s)", len(models)),
			report.SeverityHigh,
			fmt.Sprintf("LiteLLM proxy exposes %d models: %s", len(models), joinPreview(modelNames, 5)),
			map[string]interface{}{
				"module": "litellm", "action": "enum", "mutating": false,
				"provider": "litellm", "model_count": len(models),
			},
		))
	}
	if len(findings) == 0 {
		errMeta := map[string]interface{}{"module": "litellm", "action": "enum", "mutating": false}
		if readErr != nil {
			errMeta["readiness_error"] = readErr.Error()
		}
		if modelsErr != nil {
			errMeta["models_error"] = modelsErr.Error()
		}
		findings = append(findings, newExploitFinding(
			report.SourceOpenAICompat, target,
			"LiteLLM enumeration inconclusive", report.SeverityInfo,
			"LiteLLM was fingerprinted but neither readiness nor model endpoints responded during enumeration.",
			errMeta,
		))
		return findings, &common.PartialResultError{
			FailedPaths: []string{"readiness", "models"},
			Cause:       fmt.Errorf("litellm: readiness and models endpoints both failed"),
		}
	}
	return findings, nil
}

func runScanAllOpenAICompatEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := openaicompat.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	models, err := client.ListModels()
	if err != nil {
		return nil, err
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceOpenAICompat,
			target,
			"OpenAI-compatible endpoint enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated %d model(s) from the OpenAI-compatible endpoint", len(models)),
			map[string]interface{}{
				"module":      "openai-compat",
				"action":      "enum",
				"mutating":    false,
				"provider":    "openai-compatible",
				"model_count": len(models),
			},
		),
	}
	for _, model := range models {
		finding := newExploitFinding(
			report.SourceOpenAICompat,
			target,
			fmt.Sprintf("OpenAI-compatible model discovered: %s", model.ID),
			report.SeverityInfo,
			fmt.Sprintf("Model %s is exposed (provider=%s)", model.ID, safeLabel(model.Provider)),
			map[string]interface{}{
				"module":   "openai-compat",
				"action":   "enum",
				"mutating": false,
				"provider": "openai-compatible",
				"model":    model.ID,
			},
		)
		findings = append(findings, finding)
	}
	return findings, nil
}

func runScanAllA2AEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := a2a.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	card, err := client.GetAgentCard()
	if err != nil {
		return nil, err
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceA2A,
			target,
			fmt.Sprintf("A2A agent card exposed: %s", safeLabel(card.Name)),
			report.SeverityMedium,
			fmt.Sprintf("Agent %s (version=%s) advertises %d skill(s) via its public agent card",
				safeLabel(card.Name), safeLabel(card.Version), len(card.Skills)),
			map[string]interface{}{
				"module":        "a2a",
				"action":        "enum",
				"mutating":      false,
				"provider":      "a2a",
				"agent_name":    card.Name,
				"agent_version": card.Version,
				"agent_url":     card.URL,
				"skill_count":   len(card.Skills),
			},
		),
	}
	findings[0].Evidence = card.ResponseRaw
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "a2a-enum", "agent-card")
	plan := buildA2AEnumWorkflowPlan(target)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	for _, skill := range card.Skills {
		finding := newExploitFinding(
			report.SourceA2A,
			target,
			fmt.Sprintf("A2A skill discovered: %s", safeLabel(skill.Name)),
			report.SeverityInfo,
			fmt.Sprintf("Skill %s: %s", safeLabel(skill.Name), safeLabel(skill.Description)),
			map[string]interface{}{
				"module":   "a2a",
				"action":   "enum",
				"mutating": false,
				"provider": "a2a",
				"skill":    skill.Name,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "a2a-enum", "skill")
		findings = append(findings, finding)
	}
	return findings, nil
}

func runScanAllPgvectorEnum(target string) ([]report.Finding, error) {
	// Parse host:port from the HTTP-style URL provided by the fingerprint layer.
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parsing pgvector target URL: %w", err)
	}
	host := u.Hostname()
	port := 5432
	if p := u.Port(); p != "" {
		if pv, err := strconv.Atoi(p); err == nil {
			port = pv
		}
	}

	client, err := vectordb.NewPgvectorClient(currentContext(), vectordb.PgvectorConfig{
		Host: host,
		Port: port,
	}, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	version, err := client.ServiceVersion()
	if err != nil {
		return nil, fmt.Errorf("postgresql enumeration failed (may require credentials): %w", err)
	}

	hasPgvector, _ := client.HasPgvectorExtension()

	collections, err := client.ListCollectionsInfo()
	if err != nil {
		return nil, err
	}

	provider := "pgvector"
	title := "pgvector service enumerated"
	desc := fmt.Sprintf("Enumerated %d collection(s) from pgvector (PostgreSQL %s, default credentials)", len(collections), safeLabel(version))
	if !hasPgvector {
		provider = "postgresql"
		title = "PostgreSQL reachable (pgvector extension not installed)"
		desc = fmt.Sprintf("PostgreSQL %s is reachable with default credentials but the pgvector extension is not installed. Found %d public table(s).", safeLabel(version), len(collections))
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceVectorDB,
			target,
			title,
			report.SeverityInfo,
			desc,
			map[string]interface{}{
				"module":             "vectordb",
				"action":             "enum",
				"mutating":           false,
				"provider":           provider,
				"version":            version,
				"collection_count":   len(collections),
				"auth":               "default-credentials",
				"pgvector_confirmed": hasPgvector,
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "pgvector-enum", "service")

	collectionNames := make([]string, 0, len(collections))
	for _, collection := range collections {
		collectionNames = append(collectionNames, collection.Name)
	}
	summaryPlan := buildVectorDBEnumWorkflowPlan(target, provider, collectionNames)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, summaryPlan)

	for _, collection := range collections {
		metadata := map[string]interface{}{
			"module":     "vectordb",
			"action":     "enum",
			"mutating":   false,
			"provider":   provider,
			"collection": collection.Name,
			"count":      collection.Count,
		}
		if collection.ID != "" {
			metadata["collection_id"] = collection.ID
		}
		finding := newExploitFinding(
			report.SourceVectorDB,
			target,
			fmt.Sprintf("%s collection discovered: %s", provider, collection.Name),
			report.SeverityInfo,
			fmt.Sprintf("Collection %s is accessible with %s record count", collection.Name, renderCount(collection.Count)),
			metadata,
		)
		finding.Metadata = attachWorkflowToMetadata(finding.Metadata, buildVectorDBCollectionWorkflowPlan(target, provider, collection.Name))
		findings = append(findings, finding)
	}
	return findings, nil
}

func runScanAllHuggingFaceEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := huggingface.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	info, err := client.Enumerate()
	if err != nil {
		return nil, err
	}

	severity := report.SeverityMedium
	if info.ModelID != "" {
		severity = report.SeverityHigh
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceHuggingFace,
			target,
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
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "huggingface-enum", "server")
	return findings, nil
}

func runScanAllKubeflowEnum(target string, httpClient *http.Client) ([]report.Finding, error) {
	client, err := kubeflow.NewClient(currentContext(), target, cfg.Timeout, nil)
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	info, err := client.Enumerate()
	if err != nil {
		return nil, err
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceKubeflow,
			target,
			"Kubeflow Pipelines API enumerated",
			report.SeverityHigh,
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
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "kubeflow-enum", "server")

	pipelines, _, err := client.ListPipelines()
	if err == nil {
		for _, p := range pipelines {
			f := newExploitFinding(
				report.SourceKubeflow,
				target,
				fmt.Sprintf("Kubeflow pipeline: %s", p.Name),
				report.SeverityHigh,
				fmt.Sprintf("Pipeline %q (id=%s, params=%d)", p.Name, p.ID, len(p.Parameters)),
				map[string]interface{}{
					"module":        "kubeflow",
					"action":        "enum",
					"mutating":      false,
					"provider":      "kubeflow",
					"pipeline_id":   p.ID,
					"pipeline_name": p.Name,
				},
			)
			findings = append(findings, f)
		}
	}
	return findings, nil
}
