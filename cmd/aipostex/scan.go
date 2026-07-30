package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/vulncheck"
)

var (
	scanTargets    []string
	scanTags       []string
	scanSeverities []string
	scanTemplDir   string
	scanMode       string
)

var scanTargetsCmd = &cobra.Command{
	Use:   "targets [target...]",
	Short: "Run vulnerability templates against AI/MCP targets",
	Long: `Run YAML-defined vulnerability checks against AI infrastructure endpoints.
Similar to Nuclei, but purpose-built for AI/MCP attack surfaces.

Targets can be passed as positional arguments or via --target:
  aipostex scan targets http://10.0.0.50:11434
  aipostex scan targets --target http://10.0.0.50:11434 --tags ollama
  aipostex scan targets --target http://10.0.0.60:3000 --tags mcp --severity critical
  aipostex scan targets --target http://10.0.0.50:8000 --tags bizarre-bazaar`,
	Example: strings.Join([]string{
		formatCommandExample("scan targets --target http://127.0.0.1:11434"),
		formatCommandExample("scan targets --target http://127.0.0.1:3000 --tags mcp --severity critical"),
	}, "\n"),
	RunE: runScan,
}

func init() {
	scanTargetsCmd.Flags().StringSliceVarP(&scanTargets, "target", "t", nil, "Target URL(s) to scan (required)")
	scanTargetsCmd.Flags().StringSliceVar(&scanTags, "tags", nil, "Filter templates by tags (comma-separated)")
	scanTargetsCmd.Flags().StringSliceVar(&scanSeverities, "severity", nil, "Filter templates by severity (comma-separated)")
	scanTargetsCmd.Flags().StringVar(&scanTemplDir, "templates-dir", "", "Additional templates directory")
	scanTargetsCmd.Flags().StringVar(&scanMode, "mode", "detect", "Scan mode: detect (safe, default) or full (includes exploitation templates)")
}

func runScan(cmd *cobra.Command, args []string) error {
	if err := validateScanMode(scanMode); err != nil {
		return err
	}
	combined := append(append([]string{}, scanTargets...), args...)
	targets := uniqueSortedTargets(combined)
	if len(targets) == 0 {
		return missingFlagError("target", formatCommandExample("scan targets http://127.0.0.1:11434"))
	}

	writer, err := getWriter()
	if err != nil {
		return err
	}
	defer writer.Close()

	if err := writer.WriteHeader(); err != nil {
		return err
	}
	maybeWarnJSONLForLongRunning("scan targets")

	for _, target := range targets {
		if parsed, err := url.Parse(target); err == nil && parsed.Port() == "" {
			host := parsed.Hostname()
			if host == "" {
				host = target
			}
			scheme := strings.ToLower(parsed.Scheme)
			var portDesc string
			switch scheme {
			case "https":
				portDesc = "default HTTPS port 443"
			case "http":
				portDesc = "default HTTP port 80"
			default:
				portDesc = fmt.Sprintf("the default port for scheme %q", scheme)
			}
			warnf("No port specified in %s -- using %s.\n    Discover AI service ports: %s", target, portDesc, formatCommandExample("discover network "+host))
		}
	}

	// Build template engine
	concurrency := cfg.Concurrency
	if cfg.Stealth {
		concurrency = 1
	}
	engine := vulncheck.NewEngine(cfg.Timeout, concurrency)
	engine.Verbose = cfg.Verbose
	engine.Context = currentContext()
	engine.Mode = parseScanMode(scanMode)

	engine.OnProgress = func(ev vulncheck.ProgressEvent) {
		switch ev.Type {
		case "start":
			if cfg.Verbose {
				infof("Testing %s against %s", ev.TemplateID, ev.Target)
			}
		case "match":
			if cfg.Format != "console" {
				for _, f := range ev.Findings {
					fmt.Fprintf(stderrWriter, " %s [%s] %s\n",
						output.FormatSeverity(f.Severity), f.TemplateID, f.Title)
				}
			}
		}
	}

	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return err
	}
	engine.HTTPClient = httpClient

	if err := engine.LoadEmbeddedTemplates(); err != nil {
		warnf("loading embedded templates: %v", err)
	}

	// Load additional templates
	if scanTemplDir != "" {
		if err := engine.LoadTemplates(scanTemplDir); err != nil {
			return fmt.Errorf("loading templates from %s: %w", scanTemplDir, err)
		}
	}

	if engine.Mode == vulncheck.ModeFull {
		infof("Mode: Full Assessment (detection + exploitation)")
	} else {
		infof("Mode: Detection Only (no exploitation templates)")
	}

	filtered := engine.FilteredTemplates(scanTags, scanSeverities)
	if len(filtered) == 0 {
		return fmt.Errorf("no templates match the specified filters (loaded %d total)", len(engine.Templates))
	}

	if cfg.Verbose {
		infof("Loaded %d templates (%d after filtering)", len(engine.Templates), len(filtered))
	}

	// Scan each target
	summary := scanSummary{
		TargetsAttempted:    len(targets),
		TemplatesConsidered: len(engine.Templates),
		TemplatesMatched:    len(filtered),
	}
	allFindings := make([]report.Finding, 0)

	for _, target := range targets {
		if currentContext().Err() != nil {
			infof("Scan interrupted")
			break
		}
		if cfg.Verbose {
			infof("Scanning %s with %d templates", target, len(filtered))
		}

		findings, metrics, err := engine.ScanDetailed(target, scanTags, scanSeverities)
		if err != nil {
			warnf("scanning %s: %v", target, err)
			summary.TargetsWithTemplateErrors++
			summary.TargetsWithFailures++
			continue
		}
		hadFailure := false
		if metrics.RequestErrors > 0 {
			summary.TargetsWithRequestErrors++
			hadFailure = true
			if cfg.Verbose {
				infof("Request errors encountered while scanning %s: %d", target, metrics.RequestErrors)
			}
		}
		if metrics.TemplateErrors > 0 {
			summary.TargetsWithTemplateErrors++
			hadFailure = true
			if cfg.Verbose {
				infof("Template errors encountered while scanning %s: %d", target, metrics.TemplateErrors)
			}
		}
		if hadFailure {
			summary.TargetsWithFailures++
		}
		if len(findings) == 0 {
			summary.TargetsWithZeroFindings++
		}
		allFindings = append(allFindings, findings...)
		for _, tf := range metrics.FailedTemplates {
			allFindings = append(allFindings, report.Finding{
				Timestamp:   time.Now(),
				Source:      report.SourceVulnCheck,
				TemplateID:  tf.TemplateID,
				Target:      tf.Target,
				Title:       fmt.Sprintf("Check inconclusive: %s", tf.TemplateID),
				Severity:    report.SeverityInfo,
				Description: fmt.Sprintf("Template %s could not be executed against %s: %s", tf.TemplateID, tf.Target, tf.Error),
				Metadata: map[string]interface{}{
					"check_inconclusive": true,
					"template_id":        tf.TemplateID,
					"error":              tf.Error,
				},
			})
		}
	}

	deduped := dedupeAndSortFindings(annotateFindingsForOutput(allFindings))
	summary.FindingsEmitted = len(deduped)
	stats := findingStats(deduped)

	// Count actionable findings (excluding informational inconclusive markers)
	// for exit-code decisions.
	actionableCount := 0
	for _, f := range deduped {
		if _, ok := f.Metadata["check_inconclusive"]; !ok {
			actionableCount++
		}
	}

	for _, finding := range deduped {
		if err := writer.WriteFinding(finding); err != nil {
			warnf("writing finding: %v", err)
		}
	}

	if err := writer.WriteFooter(stats); err != nil {
		return err
	}
	printScanSummary(stderrWriter, summary, stats)

	// Infer services from finding tags and generate workflow plans
	workflowPlans := inferWorkflowPlansFromFindings(deduped, targets)
	currentCommands := currentScanWorkflowCommands(targets, scanTags)
	for i := range workflowPlans {
		workflowPlans[i] = suppressWorkflowCommands(workflowPlans[i], currentCommands...)
	}
	if len(workflowPlans) > 0 {
		printWorkflowPlans(stderrWriter, workflowPlans, cfg.Verbose)
	}

	if len(deduped) == 0 && cfg.Format == "console" {
		infof("No findings detected across %d target(s)", summary.TargetsAttempted)
		for _, target := range targets {
			if host := extractHostForScanNetwork(target); host != "" {
				infof("Broader discovery: %s", formatCommandExample("discover network "+host))
			}
		}
	}

	if actionableCount > 0 && summary.TargetsWithFailures > 0 {
		return &exitcode.FindingsPartialError{
			FindingsCount: actionableCount,
			Succeeded:     summary.TargetsAttempted - summary.TargetsWithFailures,
			Failed:        summary.TargetsWithFailures,
			Cause: fmt.Errorf(
				"assessment incomplete: %d target(s) had request errors and %d target(s) had template errors",
				summary.TargetsWithRequestErrors,
				summary.TargetsWithTemplateErrors,
			),
		}
	}
	if actionableCount > 0 {
		return &exitcode.FindingsError{Count: actionableCount}
	}
	if summary.TargetsWithFailures > 0 {
		return &exitcode.PartialError{
			Succeeded: summary.TargetsAttempted - summary.TargetsWithFailures,
			Failed:    summary.TargetsWithFailures,
			Cause: fmt.Errorf(
				"assessment incomplete: %d target(s) had request errors and %d target(s) had template errors",
				summary.TargetsWithRequestErrors,
				summary.TargetsWithTemplateErrors,
			),
		}
	}
	return nil
}

// inferWorkflowPlansFromFindings generates workflow plans from scan findings
// by reverse-mapping template tags to services. Services are canonicalized
// to their workflow family so that e.g. vllm and openai-compatible don't
// produce duplicate plans.
// workflowTagInferenceRank scores template tags when inferring follow-on workflows.
// More specific vendors (e.g. litellm) must win over umbrella tags like openai-compatible
// when both appear on the same finding.
func workflowTagInferenceRank(tag string) int {
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "litellm":
		return 1000
	case "inspector":
		return 900
	case "openai-compatible":
		return 100
	case "mcp":
		return 50
	case "llmjacking":
		return 0
	default:
		return 500
	}
}

// findingService returns the canonical aipostex service a finding pertains to,
// inferred from its template tags (highest-ranked tag wins). Empty if no tag maps to a
// known service.
func findingService(f report.Finding) string {
	svc := ""
	bestRank := -1
	for _, tag := range f.Tags {
		candidate := tagsToService(tag)
		if candidate == "" {
			continue
		}
		rank := workflowTagInferenceRank(tag)
		if rank < bestRank {
			continue
		}
		bestRank = rank
		svc = workflowCanonicalService(candidate)
	}
	return svc
}

func inferWorkflowPlansFromFindings(findings []report.Finding, targets []string) []workflowPlan {
	serviceURLs := make(map[string]map[string]bool)
	var plans []workflowPlan
	for _, f := range findings {
		if serverURL := inspectorServerURLFromFinding(f); serverURL != "" {
			plans = append(plans, buildMCPInspectorPivotWorkflowPlan(
				f.Target,
				serverURL,
				metadataExtractedString(f, "server_name"),
				metadataExtractedString(f, "transport_type"),
			))
		}
		svc := findingService(f)
		if svc == "" {
			continue
		}
		if serviceURLs[svc] == nil {
			serviceURLs[svc] = make(map[string]bool)
		}
		serviceURLs[svc][f.Target] = true
	}
	if len(serviceURLs) == 0 {
		return plans
	}

	for svc, urlMap := range serviceURLs {
		for target := range urlMap {
			r := fingerprint.Result{
				Service: svc,
				URL:     target,
			}
			plans = append(plans, buildScanNetworkWorkflowPlan(r))
		}
	}
	return plans
}

func inspectorServerURLFromFinding(f report.Finding) string {
	if f.TemplateID != "mcp-auth-005-inspector-api-exposed" {
		return ""
	}
	serverURL := metadataExtractedString(f, "server_url")
	if serverURL == "" {
		return ""
	}
	parsed, err := url.Parse(serverURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return serverURL
}

func metadataExtractedString(f report.Finding, key string) string {
	if f.Metadata == nil {
		return ""
	}
	if value, ok := f.Metadata[key]; ok {
		return strings.TrimSpace(fmt.Sprint(value))
	}
	extracted, ok := f.Metadata["extracted"].(map[string]interface{})
	if !ok {
		return ""
	}
	if value, ok := extracted[key]; ok {
		return strings.TrimSpace(fmt.Sprint(value))
	}
	return ""
}

// extractHostForScanNetwork returns the bare host from a target URL
// suitable for passing to discover network. Returns "" if the target has
// no scheme or can't be parsed.
func extractHostForScanNetwork(target string) string {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Hostname()
}

// workflowCanonicalService maps services that share the same workflow plan
// case to a single canonical name, preventing duplicate workflow output.
func workflowCanonicalService(svc string) string {
	switch svc {
	case "vllm", "localai", "lmstudio", "openai-compatible":
		return "openai-compatible"
	case "mcp":
		return "mcp-sse"
	case "inspector":
		return "mcp-inspector"
	default:
		return svc
	}
}

func currentScanWorkflowCommands(targets, tags []string) []string {
	tags = normalizeFlagList(tags)
	var commands []string
	for _, target := range uniqueSortedTargets(targets) {
		target = canonicalServiceURL(target)
		if len(tags) == 0 {
			commands = append(commands, formatCommandExample("scan targets --target "+target))
			continue
		}
		commands = append(commands, formatCommandExample("scan targets --target "+target+" --tags "+strings.Join(tags, ",")))
		sortedTags := uniqueSortedStrings(tags)
		sortedCommand := formatCommandExample("scan targets --target " + target + " --tags " + strings.Join(sortedTags, ","))
		commands = append(commands, sortedCommand)
	}
	return uniqueStringsOrdered(commands)
}

func normalizeFlagList(values []string) []string {
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func networkFingerprintConcurrency(cmd *cobra.Command, checks, configured int) int {
	if configured < 1 {
		return 1
	}
	if cfg.Stealth || commandFlagChanged(cmd, "concurrency") {
		return configured
	}
	switch {
	case checks >= 5000 && configured < 128:
		return 128
	case checks >= 1000 && configured < 64:
		return 64
	case checks >= 500 && configured < 32:
		return 32
	default:
		return configured
	}
}

func commandFlagChanged(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	if flag := cmd.Flags().Lookup(name); flag != nil {
		return flag.Changed
	}
	if flag := cmd.InheritedFlags().Lookup(name); flag != nil {
		return flag.Changed
	}
	return false
}

func parseScanMode(mode string) vulncheck.ScanMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "full":
		return vulncheck.ModeFull
	default:
		return vulncheck.ModeDetect
	}
}

func validateScanMode(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "detect", "full":
		return nil
	default:
		return fmt.Errorf("invalid --mode %q (valid: detect, full)", mode)
	}
}

func templateTypeCounts(templates []*vulncheck.Template) (detection, exploit int) {
	for _, t := range templates {
		if t.IsExploit() {
			exploit++
		} else {
			detection++
		}
	}
	return
}

func getWriter() (output.Writer, error) {
	return getWriterMode(false)
}

func getGroupedWriter() (output.Writer, error) {
	return getWriterMode(true)
}

func getWriterMode(grouped bool) (output.Writer, error) {
	// Active-session auto-dossier: when a session is active and the user did not
	// set -o/-f, accumulate findings into the session's engagement dossier so a
	// chain of commands builds one dossier with no per-command flags. Explicit
	// -o/-f always win. (Only finding-emitting commands reach getWriterMode, so
	// report view / sessions / version are unaffected.)
	// Only bare commands (no -o AND no -f) auto-accumulate into the session dossier.
	// An explicit --format must write to stdout as asked — redirecting it to the
	// engagement DIRECTORY while keeping e.g. json would hand NewJSONWriter a dir path
	// and fail. Explicit -o/-f always win.
	if !outputFlagChanged && !formatFlagChanged && cfg.OutputFile == "" {
		if dir := activeEngagementDir(); dir != "" {
			cfg.OutputFile = dir
			cfg.Format = "dossier"
		}
	}

	newConsole := func() output.Writer {
		if grouped {
			return output.NewGroupedConsoleWriterTo(stderrWriter, cfg.Verbose)
		}
		return output.NewConsoleWriterTo(stderrWriter, cfg.Verbose)
	}

	var w output.Writer
	var err error
	switch cfg.Format {
	case "json":
		w, err = output.NewJSONWriter(cfg.OutputFile)
	case "jsonl":
		w, err = output.NewJSONLWriter(cfg.OutputFile)
	case "csv":
		w, err = output.NewCSVWriter(cfg.OutputFile)
	case "html":
		if cfg.OutputFile == "" || cfg.OutputFile == "-" {
			warnf("HTML output is best written to a file; use --output report.html")
		}
		w, err = output.NewHTMLWriter(cfg.OutputFile)
	case "sarif":
		w, err = output.NewSARIFWriter(cfg.OutputFile)
	case "markdown", "md":
		w, err = output.NewMarkdownWriter(cfg.OutputFile)
	case "pdf":
		if cfg.OutputFile == "" || cfg.OutputFile == "-" {
			return nil, fmt.Errorf("PDF output requires --output <file.pdf>")
		}
		w, err = output.NewPDFWriter(cfg.OutputFile)
	case "dossier":
		// Writes an operator FOLDER (not a file) to -o <dir>; error like pdf when absent.
		if cfg.OutputFile == "" || cfg.OutputFile == "-" {
			return nil, fmt.Errorf("dossier output requires --output <dir>")
		}
		w, err = newDossierWriter(cfg.OutputFile)
	case "console":
		return newConsole(), nil
	default:
		return nil, fmt.Errorf("unknown output format: %s (valid: console, json, jsonl, csv, html, sarif, markdown, pdf, dossier)", cfg.Format)
	}
	if err != nil {
		return nil, err
	}
	// See + save: when a structured format is written to a FILE (`-o <file>`), ALSO render
	// the human console view to stderr so the operator sees the findings, not just a summary.
	// Piping (no `-o`, or `-o -`) stays structured-only on stdout so `--format jsonl | jq`
	// remains clean.
	if cfg.OutputFile != "" && cfg.OutputFile != "-" {
		return output.NewMultiWriter(w, newConsole()), nil
	}
	return w, nil
}
