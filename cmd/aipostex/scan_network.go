package main

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/credchain"
	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/vulncheck"
)

var (
	netTargets       []string
	netPorts         []string
	netTopPorts      int
	netAutoScan      bool
	netDiscoveryOnly bool
)

var discoverNetworkCmd = &cobra.Command{
	Use:   "network [target...]",
	Short: "Scan network for AI services and auto-run vulnerability templates",
	Long: `Discover AI services on the network via fingerprinting, then optionally
run vulnerability templates against discovered services.

Targets can be passed as positional arguments or via --target:
  aipostex discover network 10.0.0.0/24
  aipostex discover network 10.0.0.50 10.0.0.60 --ports 11434,8000
  aipostex discover network --target 10.0.0.0/24 --auto-scan
  aipostex discover network 192.168.1.0/24 --auto-scan --tags bizarre-bazaar`,
	Example: strings.Join([]string{
		formatCommandExample("discover network --target 10.0.0.0/24"),
		formatCommandExample("discover network --target 127.0.0.1 --ports 11434,8000"),
	}, "\n"),
	RunE: runScanNetwork,
}

func init() {
	discoverNetworkCmd.Flags().StringSliceVarP(&netTargets, "target", "t", nil, "Target host(s) or CIDR range(s) (required)")
	discoverNetworkCmd.Flags().StringSliceVar(&netPorts, "ports", nil, "Ports to scan (comma-separated, ranges like 1-1000 supported)")
	discoverNetworkCmd.Flags().IntVar(&netTopPorts, "top-ports", 0, "Scan the top-N most common TCP ports (e.g. 100, 1000)")
	discoverNetworkCmd.Flags().BoolVar(&netAutoScan, "auto-scan", true, "Auto-run vulnerability templates against discovered services")
	discoverNetworkCmd.Flags().BoolVar(&netDiscoveryOnly, "discovery-only", false, "Only perform service discovery, skip vulnerability scanning")
	discoverNetworkCmd.Flags().StringSliceVar(&scanTags, "tags", nil, "Filter vuln templates by tags")
	discoverNetworkCmd.Flags().StringSliceVar(&scanSeverities, "severity", nil, "Filter vuln templates by severity")
	discoverNetworkCmd.Flags().StringVar(&scanTemplDir, "templates-dir", "", "Additional templates directory")
	discoverNetworkCmd.Flags().StringVar(&scanMode, "mode", "detect", "Scan mode: detect (safe, default) or full (includes exploitation templates)")
}

func runScanNetwork(cmd *cobra.Command, args []string) error {
	if err := validateScanMode(scanMode); err != nil {
		return err
	}
	combined := append(append([]string{}, netTargets...), args...)
	targets := uniqueSortedStrings(combined)
	if len(targets) == 0 {
		return missingFlagError("target", formatCommandExample("discover network 10.0.0.0/24"))
	}

	writer, err := getGroupedWriter()
	if err != nil {
		return err
	}
	defer writer.Close()

	if err := writer.WriteHeader(); err != nil {
		return err
	}
	maybeWarnJSONLForLongRunning("discover network")

	// Strip URL schemes and extract host/port before CIDR expansion
	var extractedPorts []int
	preferHTTPSPorts := explicitHTTPSPorts(targets)
	targets, extractedPorts = stripURLTargets(targets)

	// Reject obviously huge single CIDRs before allocating
	for _, target := range targets {
		if _, err := fingerprint.EstimateCIDRSize(target); err != nil {
			return fmt.Errorf("invalid target %s: %w", target, err)
		}
	}

	// Expand, dedup, then validate against --max-hosts
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

	// Parse ports, merging any ports extracted from URL-format targets
	ports, err := parsePorts(netPorts)
	if err != nil {
		return err
	}
	if netTopPorts > 0 {
		topPorts, err := topNPorts(netTopPorts)
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

	// Phase 1: Fingerprint
	infof("Scanning %d host(s) across %d port(s)", len(hosts), len(ports))
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
	if currentContext().Err() != nil {
		fmt.Fprintln(stderrWriter)
	}
	selection := selectableFingerprintResults(observations)
	templateResults := selection.ResultsOnly()

	summary := networkScanSummary{
		HostsExpanded:             len(hosts),
		PortsScanned:              len(ports),
		OpenPorts:                 len(observations),
		AmbiguousServicesExpanded: selection.AmbiguousExpanded,
		NonHTTPTemplateSkips:      selection.NonHTTPTemplateSkips,
		ServiceCounts:             make(map[string]int),
	}
	summarizeObservations(observations, &summary)

	honeypotSignals := fingerprint.DetectHoneypotSignals(observations, len(ports))
	summary.HoneypotWarnings = len(honeypotSignals)

	infof("Discovered %d open port(s)", len(observations))

	printDiscoveryTable(stderrWriter, observations)

	printHoneypotWarnings(honeypotSignals)

	proxyWarned := make(map[string]struct{})
	for _, observation := range observations {
		for _, result := range observation.Results {
			if !result.ProxyLikely {
				continue
			}
			key := fmt.Sprintf("%s:%d", result.Host, result.Port)
			if _, warned := proxyWarned[key]; !warned {
				proxyWarned[key] = struct{}{}
				warnf("Reverse proxy likely on %s -- multiple services detected on same port", key)
			}
		}
	}

	workflowPlans := buildObservationWorkflowPlans(observations)

	allFindings := make([]report.Finding, 0, len(observations))
	for _, observation := range observations {
		allFindings = append(allFindings, portObservationToFinding(observation))
	}
	for _, skipped := range selection.NonHTTPResults {
		allFindings = append(allFindings, nonHTTPTemplateSkipFinding(skipped))
	}

	// Phase 2: Auto vulnerability scan (unless --discovery-only)
	runAutoScan := netAutoScan && !netDiscoveryOnly && len(templateResults) > 0
	if runAutoScan {
		fmt.Fprintf(stderrWriter, "%s\n", consoleSectionHeader("Vulnerability Scan"))
		if parseScanMode(scanMode) == vulncheck.ModeFull {
			infof("Mode: Full Assessment (detection + exploitation)")
		} else {
			infof("Mode: Detection Only (no exploitation templates)")
		}
		infof("Running templates against %d service identity(s)", len(templateResults))

		engine := vulncheck.NewEngine(cfg.Timeout, concurrency)
		engine.Verbose = cfg.Verbose
		engine.Context = currentContext()
		engine.HTTPClient = httpClient
		engine.Mode = parseScanMode(scanMode)

		var progressFindings []report.Finding
		var progressMu sync.Mutex
		engine.OnProgress = func(ev vulncheck.ProgressEvent) {
			switch ev.Type {
			case "start":
				if cfg.Verbose {
					infof("Testing %s against %s", ev.TemplateID, ev.Target)
				}
			case "match":
				if cfg.Format != "console" {
					progressMu.Lock()
					progressFindings = append(progressFindings, ev.Findings...)
					progressMu.Unlock()
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
		if len(engine.Templates) == 0 {
			warnf("no templates loaded -- auto-scan is effectively disabled; check embedded templates and --templates-dir")
		}

		detCount, expCount := templateTypeCounts(engine.Templates)
		infof("Loaded %d templates (%d detection, %d exploit)", len(engine.Templates), detCount, expCount)

		scannedURLs := make(map[string]struct{})

		for _, selected := range selection.Results {
			if currentContext().Err() != nil {
				infof("Scan-network interrupted")
				break
			}
			r := selected.Result
			tags := normalizeServiceTags(r.Service, scanTags)
			matching := engine.FilteredTemplates(tags, scanSeverities)
			if len(matching) == 0 {
				summary.ServicesSkippedNoTemplates++
				continue
			}
			scannedURLs[canonicalServiceURL(r.URL)] = struct{}{}

			findings, metrics, err := engine.ScanDetailed(r.URL, tags, scanSeverities)
			if err != nil {
				summary.TemplateScanErrors++
				summary.ServicesWithFailures++
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
				summary.ServicesWithFailures++
			}
			annotateFindingsForSelectedFingerprint(findings, selected)
			allFindings = append(allFindings, findings...)
		}
		summary.UniqueServiceURLsScanned = len(scannedURLs)

		if cfg.Format != "console" && len(progressFindings) > 0 {
			printGroupedVulnProgress(progressFindings)
		}
	}

	workflowPlans = append(workflowPlans, inferWorkflowPlansFromFindings(allFindings, targets)...)

	credStore := credchain.ExtractFromFindings(allFindings)
	if credStore.TotalCredentials() > 0 {
		infof("Discovered %d credential(s) for %d target(s)", credStore.TotalCredentials(), credStore.TotalTargets())
		workflowPlans = enrichWorkflowPlansWithCredentials(workflowPlans, credStore)

		if cfg.AutoChain {
			chainActions := credchain.GenerateChainActions(credStore)
			if len(chainActions) > 0 {
				infof("Auto-chain: generated %d follow-up action suggestion(s) from discovered credentials", len(chainActions))
				chainFinding := newExploitFinding(
					report.SourceCredential,
					"auto-chain",
					fmt.Sprintf("Auto-chain: %d credential-forwarding action(s) available", len(chainActions)),
					report.SeverityInfo,
					fmt.Sprintf("Discovered %d credential(s) across %d target(s). Use --auto-chain to generate credential-aware follow-up commands for operator review.", credStore.TotalCredentials(), credStore.TotalTargets()),
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
	summary.FindingsEmitted = len(deduped)
	summary.WorkflowPlans = workflowPlans
	summary.WorkflowTargets, summary.GatedSuggestions = workflowStats(workflowPlans)
	stats := findingStats(deduped)

	applyHostNextSteps(writer, workflowPlans, deduped)
	if netDiscoveryOnly {
		for _, finding := range deduped {
			if err := writer.WriteFinding(finding); err != nil {
				warnf("writing finding: %v", err)
			}
		}
		if err := writer.WriteFooter(stats); err != nil {
			return err
		}
		printDiscoverySummary(stderrWriter, summary, stats)
	} else {
		for _, finding := range deduped {
			if err := writer.WriteFinding(finding); err != nil {
				warnf("writing finding: %v", err)
			}
		}

		if err := writer.WriteFooter(stats); err != nil {
			return err
		}
		printNetworkScanSummary(stderrWriter, summary, stats, cfg.Verbose)
		if cfg.Verbose {
			printWorkflowPlans(stderrWriter, workflowPlans, cfg.Verbose)
		} else {
			printGatedSummary(stderrWriter, workflowPlans)
		}
	}
	if currentContext().Err() != nil {
		infof("Scan-network interrupted")
	}

	hasFailures := summary.ServicesWithFailures > 0
	if len(deduped) > 0 && hasFailures {
		return &exitcode.FindingsPartialError{
			FindingsCount: len(deduped),
			Succeeded:     summary.UniqueServiceURLsScanned - summary.ServicesWithFailures,
			Failed:        summary.ServicesWithFailures,
			Cause: fmt.Errorf(
				"assessment incomplete: %d scan error(s), %d request error(s), %d template error(s)",
				summary.TemplateScanErrors,
				summary.TemplateRequestErrors,
				summary.TemplateErrors,
			),
		}
	}
	if len(deduped) > 0 {
		return &exitcode.FindingsError{Count: len(deduped)}
	}
	if hasFailures {
		return &exitcode.PartialError{
			Succeeded: summary.UniqueServiceURLsScanned - summary.ServicesWithFailures,
			Failed:    summary.ServicesWithFailures,
			Cause: fmt.Errorf(
				"assessment incomplete: %d scan error(s), %d request error(s), %d template error(s)",
				summary.TemplateScanErrors,
				summary.TemplateRequestErrors,
				summary.TemplateErrors,
			),
		}
	}
	return nil
}

func validateExpandedHosts(hostCount int) error {
	if cfg.MaxHosts == 0 || hostCount <= cfg.MaxHosts {
		return nil
	}
	return fmt.Errorf("expanded %d hosts, which exceeds --max-hosts %d (raise the limit or use --max-hosts 0 to disable)", hostCount, cfg.MaxHosts)
}

func validatePortNumber(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}
	return nil
}

// stripURLTargets extracts hosts and optional ports from URL-format targets.
// E.g., "http://10.0.0.1:8000" becomes host "10.0.0.1" with port 8000 added
// to the extracted ports list.
func stripURLTargets(targets []string) ([]string, []int) {
	var cleaned []string
	var ports []int
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if !strings.Contains(t, "://") {
			cleaned = append(cleaned, t)
			continue
		}
		parsed, err := url.Parse(t)
		if err != nil || parsed.Host == "" {
			cleaned = append(cleaned, t)
			continue
		}
		host := parsed.Hostname()
		if host == "" {
			cleaned = append(cleaned, t)
			continue
		}
		cleaned = append(cleaned, host)
		if portStr := parsed.Port(); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil && port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}
	return uniqueSortedStrings(cleaned), uniqueSortedPorts(ports)
}

func explicitHTTPSPorts(targets []string) []int {
	var ports []int
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if !strings.Contains(t, "://") {
			continue
		}
		parsed, err := url.Parse(t)
		if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
			continue
		}
		if portStr := parsed.Port(); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil && port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
			continue
		}
		ports = append(ports, 443)
	}
	return uniqueSortedPorts(ports)
}

func intSet(values []int) map[int]bool {
	if len(values) == 0 {
		return nil
	}
	out := make(map[int]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

// tagsToService maps a template tag back to a service name for workflow
// plan generation in the scan command. Generic/umbrella tags (vectordb,
// llmjacking) are not mapped because they can't be resolved to a single
// vendor without additional context.
func tagsToService(tag string) string {
	reverseMap := map[string]string{
		"ollama":            "ollama",
		"chromadb":          "chromadb",
		"triton":            "triton",
		"tgi":               "hf-tgi",
		"tei":               "hf-tei",
		"kubeflow":          "kubeflow",
		"langserve":         "langserve",
		"vllm":              "vllm",
		"litellm":           "litellm",
		"lmstudio":          "lmstudio",
		"localai":           "localai",
		"weaviate":          "weaviate",
		"qdrant":            "qdrant",
		"milvus":            "milvus",
		"jupyter":           "jupyter",
		"mlflow":            "mlflow",
		"gradio":            "gradio",
		"ray":               "ray",
		"streamlit":         "streamlit",
		"wandb":             "wandb",
		"bentoml":           "bentoml",
		"torchserve":        "torchserve",
		"tfserving":         "tfserving",
		"mcp":               "mcp-sse",
		"inspector":         "mcp-inspector",
		"openai-compatible": "openai-compatible",
		"open-webui":        "open-webui",
		"a2a":               "a2a",
	}
	if svc, ok := reverseMap[strings.ToLower(tag)]; ok {
		return svc
	}
	return ""
}

// serviceToTags maps a fingerprinted service name to template tags
func serviceToTags(service string) []string {
	mapping := map[string][]string{
		"ollama":            {"ollama", "llmjacking"},
		"chromadb":          {"vectordb", "chromadb"},
		"triton":            {"triton"},
		"hf-tgi":            {"huggingface", "tgi"},
		"hf-tei":            {"huggingface", "tei"},
		"kubeflow":          {"kubeflow"},
		"kube-apiserver":    {"k8s", "kubernetes"},
		"langserve":         {"langchain", "langserve"},
		"vllm":              {"vllm", "llmjacking", "openai-compatible"},
		"litellm":           {"litellm", "llmjacking", "openai-compatible"},
		"lmstudio":          {"lmstudio", "llmjacking", "openai-compatible"},
		"localai":           {"localai", "llmjacking", "openai-compatible"},
		"weaviate":          {"vectordb", "weaviate"},
		"qdrant":            {"vectordb", "qdrant"},
		"milvus":            {"vectordb", "milvus"},
		"jupyter":           {"jupyter"},
		"mlflow":            {"mlflow"},
		"bentoml":           {"bentoml"},
		"wandb":             {"wandb"},
		"torchserve":        {"torchserve"},
		"tfserving":         {"tfserving"},
		"gradio":            {"gradio"},
		"ray":               {"ray"},
		"streamlit":         {"streamlit"},
		"mcp-sse":           {"mcp"},
		"mcp-inspector":     {"mcp", "inspector"},
		"mcpjam-inspector":  {"mcp", "inspector"},
		"openai-compatible": {"openai-compatible", "llmjacking"},
		"open-webui":        {"open-webui"},
		"a2a":               {"a2a", "agent"},
		"postgresql":        {},
		"redis":             {},
	}

	if tags, ok := mapping[service]; ok {
		normalized := append([]string(nil), tags...)
		sort.Strings(normalized)
		return normalized
	}
	return []string{service}
}

func summarizeObservations(observations []fingerprint.PortObservation, summary *networkScanSummary) {
	if summary == nil {
		return
	}
	for _, observation := range observations {
		if observation.TimedOut {
			summary.TimedOutPorts++
		}
		switch observation.FingerprintStatus {
		case fingerprint.MatchKindConfirmed:
			for _, result := range observation.Results {
				if result.MatchKind == fingerprint.MatchKindConfirmed {
					summary.ConfirmedIdentities++
				} else if result.MatchKind == fingerprint.MatchKindSuspected {
					summary.SuspectedIdentities++
				}
				summary.ServiceCounts[result.Service]++
				summary.ServicesDiscovered++
			}
		case fingerprint.MatchKindSuspected:
			for _, result := range observation.Results {
				if result.MatchKind == fingerprint.MatchKindSuspected {
					summary.SuspectedIdentities++
				}
				summary.ServiceCounts[result.Service]++
				summary.ServicesDiscovered++
			}
		case fingerprint.MatchKindAmbiguous:
			for _, result := range observation.Results {
				summary.ServiceCounts[result.Service]++
				summary.ServicesDiscovered++
			}
		case fingerprint.MatchKindBanner:
			for _, result := range observation.Results {
				summary.BannerIdentities++
				summary.ServiceCounts[result.Service]++
			}
		case fingerprint.MatchKindPortHeuristic:
			for _, result := range observation.Results {
				summary.SuspectedIdentities++
				summary.ServiceCounts[result.Service]++
				summary.ServicesDiscovered++
			}
		default:
			summary.UnclassifiedOpenPorts++
		}
	}
}

type selectedFingerprintResult struct {
	Result            fingerprint.Result
	FingerprintStatus string
	CandidateServices []string
	CoverageExpanded  bool
}

type fingerprintSelection struct {
	Results              []selectedFingerprintResult
	AmbiguousExpanded    int
	NonHTTPTemplateSkips int
	NonHTTPResults       []selectedFingerprintResult
}

func (s fingerprintSelection) ResultsOnly() []fingerprint.Result {
	out := make([]fingerprint.Result, 0, len(s.Results))
	for _, selected := range s.Results {
		out = append(out, selected.Result)
	}
	return out
}

func (s fingerprintSelection) AllResults() []fingerprint.Result {
	out := make([]fingerprint.Result, 0, len(s.Results)+len(s.NonHTTPResults))
	for _, selected := range s.Results {
		out = append(out, selected.Result)
	}
	for _, selected := range s.NonHTTPResults {
		out = append(out, selected.Result)
	}
	return dedupeFingerprintResults(out)
}

func selectableFingerprintResults(observations []fingerprint.PortObservation) fingerprintSelection {
	var selection fingerprintSelection
	for _, observation := range observations {
		candidates := candidateServicesForObservation(observation)
		coverageExpanded := observation.FingerprintStatus == fingerprint.MatchKindAmbiguous
		if coverageExpanded {
			selection.AmbiguousExpanded++
		}
		for _, result := range observation.Results {
			selectable := false
			switch result.MatchKind {
			case fingerprint.MatchKindConfirmed, fingerprint.MatchKindSuspected, fingerprint.MatchKindPortHeuristic, fingerprint.MatchKindAmbiguous:
				selectable = true
			}
			if !selectable {
				continue
			}
			selected := selectedFingerprintResult{
				Result:            result,
				FingerprintStatus: observation.FingerprintStatus,
				CandidateServices: candidates,
				CoverageExpanded:  coverageExpanded,
			}
			if !httpTemplateCompatibleResult(result) {
				selection.NonHTTPTemplateSkips++
				selection.NonHTTPResults = append(selection.NonHTTPResults, selected)
				continue
			}
			selection.Results = append(selection.Results, selected)
		}
	}
	selection.Results = dedupeSelectedFingerprintResults(selection.Results)
	selection.NonHTTPResults = dedupeSelectedFingerprintResults(selection.NonHTTPResults)
	return selection
}

func candidateServicesForObservation(observation fingerprint.PortObservation) []string {
	values := make([]string, 0, len(observation.Results)+len(observation.CandidateServices))
	for _, result := range observation.Results {
		if strings.TrimSpace(result.Service) != "" {
			values = append(values, result.Service)
		}
	}
	values = append(values, observation.CandidateServices...)
	return uniqueSortedStrings(values)
}

func dedupeSelectedFingerprintResults(values []selectedFingerprintResult) []selectedFingerprintResult {
	seen := make(map[string]struct{}, len(values))
	out := make([]selectedFingerprintResult, 0, len(values))
	for _, value := range values {
		key := strings.Join([]string{
			canonicalServiceURL(value.Result.URL),
			strings.ToLower(value.Result.Service),
			string(value.Result.MatchKind),
			strings.Join(value.CandidateServices, ","),
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Result.URL != out[j].Result.URL {
			return out[i].Result.URL < out[j].Result.URL
		}
		if out[i].Result.Service != out[j].Result.Service {
			return out[i].Result.Service < out[j].Result.Service
		}
		return out[i].Result.MatchKind < out[j].Result.MatchKind
	})
	return out
}

func httpTemplateCompatibleResult(result fingerprint.Result) bool {
	service := strings.ToLower(strings.TrimSpace(result.Service))
	switch service {
	case "pgvector", "postgresql", "postgres", "mysql", "mariadb", "redis", "mongodb", "ldap", "ldaps", "smb", "nfs":
		return false
	}
	return result.Port != 5432
}

func annotateFindingsForSelectedFingerprint(findings []report.Finding, selected selectedFingerprintResult) {
	for i := range findings {
		if findings[i].Metadata == nil {
			findings[i].Metadata = map[string]interface{}{}
		}
		findings[i].Metadata["fingerprint_status"] = selected.FingerprintStatus
		findings[i].Metadata["identity_confidence"] = string(selected.Result.MatchKind)
		if selected.Result.MatchKind != "" {
			findings[i].Metadata["match_kind"] = string(selected.Result.MatchKind)
		}
		if selected.Result.ProxyLikely {
			findings[i].Metadata["proxy_likely"] = true
		}
		if selected.CoverageExpanded {
			findings[i].Metadata["coverage_expanded"] = true
			findings[i].Metadata["identity_confidence"] = "ambiguous"
			findings[i].Metadata["candidate_services"] = selected.CandidateServices
		}
	}
}

func nonHTTPTemplateSkipFinding(selected selectedFingerprintResult) report.Finding {
	target := selected.Result.URL
	metadata := map[string]interface{}{
		"module":              "fingerprint",
		"action":              "template-skip",
		"mutating":            false,
		"provider":            selected.Result.Service,
		"service":             selected.Result.Service,
		"port":                selected.Result.Port,
		"fingerprint_status":  selected.FingerprintStatus,
		"identity_confidence": string(selected.Result.MatchKind),
		"non_http":            true,
		"skip_reason":         "http-template-incompatible",
	}
	if selected.CoverageExpanded {
		metadata["coverage_expanded"] = true
		metadata["identity_confidence"] = "ambiguous"
		metadata["candidate_services"] = selected.CandidateServices
	}
	return newExploitFinding(
		report.SourceFingerprint,
		target,
		fmt.Sprintf("HTTP template scan skipped for non-HTTP service: %s", selected.Result.Service),
		report.SeverityInfo,
		fmt.Sprintf("%s on %s was fingerprinted as non-HTTP, so HTTP vulnerability templates were not sent to this port.", selected.Result.Service, target),
		metadata,
	)
}

func buildObservationWorkflowPlans(observations []fingerprint.PortObservation) []workflowPlan {
	plans := make([]workflowPlan, 0, len(observations))
	for _, observation := range observations {
		switch observation.FingerprintStatus {
		case fingerprint.MatchKindAmbiguous:
			plans = append(plans, buildUncertainPortWorkflowPlan(observation, "[Ambiguous fingerprint / reverse proxy likely]"))
		case fingerprint.MatchKindBanner:
			svc := "unknown"
			if len(observation.Results) > 0 {
				svc = observation.Results[0].Service
			}
			plans = append(plans, buildUncertainPortWorkflowPlan(observation,
				fmt.Sprintf("[Non-AI service: %s]", svc)))
		case "candidate":
			plans = append(plans, buildUncertainPortWorkflowPlan(observation, "[Partial identity evidence]"))
		case "unidentified":
			plans = append(plans, buildUncertainPortWorkflowPlan(observation, "[Open port / no fingerprint]"))
		default:
			emitted := false
			for _, result := range observation.Results {
				switch result.MatchKind {
				case fingerprint.MatchKindConfirmed, fingerprint.MatchKindSuspected, fingerprint.MatchKindPortHeuristic:
					plans = append(plans, buildScanNetworkWorkflowPlan(result))
					emitted = true
				}
			}
			if !emitted {
				plans = append(plans, buildUncertainPortWorkflowPlan(observation, "[Partial identity evidence]"))
			}
		}
	}
	return plans
}

func buildUncertainPortWorkflowPlan(observation fingerprint.PortObservation, prefix string) workflowPlan {
	target := canonicalServiceURL(observation.URL)
	rationale := strings.TrimSpace(prefix + " Inventory the surface first before trusting any service-specific path.")
	return workflowPlan{
		Target:    target,
		Stage:     "discovery",
		Rationale: rationale,
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(
				formatCommandExample("scan targets --target "+target),
				"Run broad template coverage against the open port.",
				false,
				5,
			),
		},
	}
}

func portObservationToFinding(observation fingerprint.PortObservation) report.Finding {
	metadata := map[string]interface{}{
		"host":               observation.Host,
		"port":               observation.Port,
		"port_state":         observation.PortState,
		"fingerprint_status": observation.FingerprintStatus,
		"timed_out":          observation.TimedOut,
		"incomplete":         observation.Incomplete,
		"candidate_services": observation.CandidateServices,
		"matched_probes":     observation.MatchedProbes,
	}
	if observation.ServerHeader != "" {
		metadata["server_header"] = observation.ServerHeader
	}
	if len(observation.Results) > 0 {
		primary := observation.Results[0]
		metadata["service"] = primary.Service
		metadata["specificity"] = primary.Specificity
		metadata["confidence"] = primary.Confidence
		metadata["match_kind"] = primary.MatchKind
		metadata["proxy_likely"] = primary.ProxyLikely
		if primary.Version != "" {
			metadata["version"] = primary.Version
		}
		if primary.Ambiguity != "" {
			metadata["ambiguity_reason"] = primary.Ambiguity
		}
		identities := make([]map[string]interface{}, 0, len(observation.Results))
		for _, result := range observation.Results {
			entry := map[string]interface{}{
				"service":        result.Service,
				"specificity":    result.Specificity,
				"confidence":     result.Confidence,
				"match_kind":     result.MatchKind,
				"proxy_likely":   result.ProxyLikely,
				"matched_probes": result.Probes,
			}
			if result.Version != "" {
				entry["version"] = result.Version
			}
			if result.Ambiguity != "" {
				entry["ambiguity_reason"] = result.Ambiguity
			}
			identities = append(identities, entry)
		}
		metadata["identities"] = identities
	}

	title := fmt.Sprintf("Open network port discovered: %s:%d", observation.Host, observation.Port)
	desc := fmt.Sprintf("Discovered TCP-open port %s:%d with fingerprint status %s", observation.Host, observation.Port, observation.FingerprintStatus)
	if identity := discoveryIdentityLabel(observation); identity != "unidentified" {
		desc += fmt.Sprintf(" (identity: %s)", identity)
	}
	if observation.TimedOut {
		desc += " [fingerprint timed out]"
	}

	finding := report.Finding{
		ID:          fmt.Sprintf("fingerprint-port-%s-%d", observation.Host, observation.Port),
		Timestamp:   time.Now().UTC(),
		Source:      report.SourceFingerprint,
		Target:      observation.URL,
		Title:       title,
		Severity:    report.SeverityInfo,
		Description: desc,
		Metadata:    metadata,
	}
	var evidenceParts []string
	if observation.ServerHeader != "" {
		evidenceParts = append(evidenceParts, fmt.Sprintf("server_header=%s", observation.ServerHeader))
	}
	if len(observation.MatchedProbes) > 0 {
		evidenceParts = append(evidenceParts, fmt.Sprintf("matched_probes=%s", strings.Join(observation.MatchedProbes, ",")))
	}
	if len(observation.Results) > 0 {
		for _, r := range observation.Results {
			evidenceParts = append(evidenceParts, fmt.Sprintf("identity=%s version=%s match=%s confidence=%s",
				r.Service, r.Version, r.MatchKind, r.Confidence))
		}
	}
	if len(evidenceParts) > 0 {
		finding.Evidence = strings.Join(evidenceParts, "\n")
	}
	if len(observation.Results) > 0 {
		finding.Tags = serviceToTags(observation.Results[0].Service)
	}
	return finding
}

func fingerprintToFinding(result fingerprint.Result) report.Finding {
	return portObservationToFinding(fingerprint.PortObservation{
		Host:              result.Host,
		Port:              result.Port,
		URL:               result.URL,
		PortState:         "open",
		FingerprintStatus: result.MatchKind,
		ServerHeader:      result.ServerHeader,
		MatchedProbes:     result.Probes,
		Results:           []fingerprint.Result{result},
	})
}

func printGroupedVulnProgress(findings []report.Finding) {
	byHost := make(map[string][]report.Finding)
	var hostOrder []string
	for _, f := range findings {
		h := hostFromTarget(f.Target)
		if _, seen := byHost[h]; !seen {
			hostOrder = append(hostOrder, h)
		}
		byHost[h] = append(byHost[h], f)
	}
	sort.Strings(hostOrder)

	fmt.Fprintln(stderrWriter)
	for _, host := range hostOrder {
		group := byHost[host]
		sort.SliceStable(group, func(i, j int) bool {
			return vulnSevRank(group[i].Severity) < vulnSevRank(group[j].Severity)
		})
		fmt.Fprintf(stderrWriter, "  %s (%d findings)\n", host, len(group))
		for _, f := range group {
			port := portFromTarget(f.Target)
			fmt.Fprintf(stderrWriter, "    %s  %-50s :%s\n",
				output.FormatSeverity(report.NormalizeSeverity(f.Severity)),
				truncate(f.Title, 50), port)
		}
		fmt.Fprintln(stderrWriter)
	}
}

func hostFromTarget(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	host := parsed.Hostname()
	if host == "" {
		return target
	}
	return host
}

func portFromTarget(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return "?"
	}
	if p := parsed.Port(); p != "" {
		return p
	}
	switch parsed.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return "?"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func vulnSevRank(sev string) int {
	switch report.NormalizeSeverity(sev) {
	case report.SeverityCritical:
		return 0
	case report.SeverityHigh:
		return 1
	case report.SeverityMedium:
		return 2
	case report.SeverityLow:
		return 3
	case report.SeverityInfo:
		return 4
	default:
		return 5
	}
}

func buildWorkflowPlanIndex(plans []workflowPlan) map[string]workflowPlan {
	idx := make(map[string]workflowPlan, len(plans))
	for _, plan := range plans {
		url := canonicalServiceURL(plan.Target)
		if existing, exists := idx[url]; exists {
			existing.Recommendations = append(existing.Recommendations, plan.Recommendations...)
			if existing.Rationale == "" {
				existing.Rationale = plan.Rationale
			}
			if existing.Landed == "" {
				existing.Landed = plan.Landed
			}
			if existing.ChainSource == "" {
				existing.ChainSource = plan.ChainSource
			}
			idx[url] = existing
		} else {
			idx[url] = plan
		}
	}
	return idx
}
