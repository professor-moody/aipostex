package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/professor-moody/aipostex/internal/assessment"
	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

type scanSummary struct {
	TargetsAttempted          int
	TemplatesConsidered       int
	TemplatesMatched          int
	FindingsEmitted           int
	TargetsWithRequestErrors  int
	TargetsWithTemplateErrors int
	TargetsWithFailures       int
	TargetsWithZeroFindings   int
}

type networkScanSummary struct {
	HostsExpanded              int
	PortsScanned               int
	OpenPorts                  int
	ServicesDiscovered         int
	ConfirmedIdentities        int
	SuspectedIdentities        int
	BannerIdentities           int
	TimedOutPorts              int
	UnclassifiedOpenPorts      int
	AmbiguousServicesExpanded  int
	NonHTTPTemplateSkips       int
	UniqueServiceURLsScanned   int
	ServicesSkippedNoTemplates int
	TemplateScanErrors         int
	TemplateRequestErrors      int
	TemplateErrors             int
	FindingsEmitted            int
	ServiceCounts              map[string]int
	ServicesWithFailures       int
	WorkflowTargets            int
	GatedSuggestions           int
	WorkflowFailures           int
	WorkflowPlans              []workflowPlan
	HoneypotWarnings           int
}

type scanAllSummary struct {
	ServicesDiscovered         int
	AmbiguousServicesExpanded  int
	NonHTTPTemplateSkips       int
	TemplateScanAttempts       int
	ServicesWithScanFailures   int
	TemplateRequestErrors      int
	TemplateErrors             int
	EnumerationAttempts        int
	EnumerationFailures        int
	EnumerationPartialFailures int
	EnumerationSkipped         int
	EnumerationNotApplicable   int
	FindingsEmitted            int
}

func uniqueSortedTargets(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	normalized := make([]string, 0, len(targets))
	for _, target := range targets {
		target = normalizeAndWarnTarget(target)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		normalized = append(normalized, target)
	}
	sort.Strings(normalized)
	return normalized
}

func uniqueSortedHosts(hosts []string) []string {
	return assessment.UniqueSort(hosts)
}

func uniqueSortedPorts(ports []int) []int {
	return assessment.UniqueSortPorts(ports)
}

func uniqueSortedStrings(values []string) []string {
	return assessment.UniqueSort(values)
}

func normalizeServiceTags(service string, userTags []string) []string {
	if len(userTags) > 0 {
		return uniqueSortedStrings(userTags)
	}
	return uniqueSortedStrings(serviceToTags(service))
}

func dedupeFingerprintResults(results []fingerprint.Result) []fingerprint.Result {
	return assessment.DedupeFingerprints(results)
}

func dedupePortObservations(observations []fingerprint.PortObservation) []fingerprint.PortObservation {
	return assessment.DedupePortObservations(observations)
}

func canonicalServiceURL(raw string) string {
	return assessment.CanonicalServiceURL(raw)
}

func dedupeAndSortFindings(findings []report.Finding) []report.Finding {
	return assessment.DedupeAndSortFindings(findings)
}

func findingStats(findings []report.Finding) map[string]int {
	return assessment.FindingStats(findings)
}

func printScanSummary(w io.Writer, summary scanSummary, stats map[string]int) {
	printSummaryHeader(w, stats)
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d target(s) attempted", summary.TargetsAttempted),
		fmt.Sprintf("%d template(s) considered", summary.TemplatesConsidered),
		fmt.Sprintf("%d template(s) matched", summary.TemplatesMatched),
		fmt.Sprintf("%d finding(s)", summary.FindingsEmitted),
	}, "  |  ")
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d target(s) with request errors", summary.TargetsWithRequestErrors),
		fmt.Sprintf("%d target(s) with template errors", summary.TargetsWithTemplateErrors),
		fmt.Sprintf("%d target(s) with zero findings", summary.TargetsWithZeroFindings),
	}, "  |  ")
	if summary.TargetsWithFailures > 0 {
		printWrapped(w, 2, "", fmt.Sprintf("incomplete coverage: %d target(s) encountered scan errors", summary.TargetsWithFailures))
	}
}

func logFingerprintProgress(ev fingerprint.ScanProgressEvent, verbose bool) {
	switch ev.Type {
	case "tcp_open":
		infof("TCP open %s:%d", ev.Host, ev.Port)
	case "fingerprinting":
		if ev.Probe != "" {
			if verbose {
				infof("Trying %s:%d via %s", ev.Host, ev.Port, ev.Probe)
			}
			return
		}
		infof("Fingerprinting %s:%d", ev.Host, ev.Port)
	case "matched":
		if verbose && ev.Probe != "" {
			infof("Candidate %s on %s:%d via %s", ev.Service, ev.Host, ev.Port, ev.Probe)
			return
		}
		infof("Candidate %s on %s:%d", ev.Service, ev.Host, ev.Port)
	case "timed_out":
		warnf("Fingerprint timeout on %s:%d after %s", ev.Host, ev.Port, formatFingerprintBudget(ev.Budget))
	case "done":
		if verbose && ev.Total > 0 && (ev.Current == ev.Total || ev.Current%50 == 0) {
			infof("Port checks completed %d/%d", ev.Current, ev.Total)
		}
	}
}

func formatFingerprintBudget(budget time.Duration) string {
	if budget <= 0 {
		return "budget exhausted"
	}
	return budget.String()
}

func printDiscoveryTable(w io.Writer, observations []fingerprint.PortObservation) {
	if len(observations) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s\n", consoleSectionHeader("Discovery"))

	multiHost := hasMultipleHosts(observations)

	var cols []output.Column
	if multiHost {
		cols = append(cols, output.Column{Header: "HOST"})
	}
	cols = append(cols,
		output.Column{Header: "PORT"},
		output.Column{Header: "STATE"},
		output.Column{Header: "IDENTITY"},
		output.Column{Header: "CONFIDENCE"},
		output.Column{Header: "NOTES", Flex: true},
		output.Column{Header: "VERSION", Flex: true},
	)
	tbl := output.NewTable(cols...)

	sorted := append([]fingerprint.PortObservation(nil), observations...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Host != sorted[j].Host {
			return sorted[i].Host < sorted[j].Host
		}
		return sorted[i].Port < sorted[j].Port
	})

	for _, observation := range sorted {
		var row []string
		if multiHost {
			row = append(row, output.NormalizeCell(observation.Host))
		}
		row = append(row,
			fmt.Sprintf("%d/tcp", observation.Port),
			output.NormalizeCell(observation.PortState),
			output.NormalizeCell(discoveryIdentityLabel(observation)),
			output.NormalizeCell(discoveryConfidenceLabel(observation)),
			output.NormalizeCell(discoveryNotesLabel(observation)),
			output.NormalizeCell(discoveryVersionLabel(observation)),
		)
		tbl.AddRow(row...)
	}
	fmt.Fprintln(w)
	_ = tbl.Fprint(w, output.TableWidth())
	fmt.Fprintln(w)
}

func hasMultipleHosts(observations []fingerprint.PortObservation) bool {
	if len(observations) <= 1 {
		return false
	}
	first := observations[0].Host
	for _, observation := range observations[1:] {
		if observation.Host != first {
			return true
		}
	}
	return false
}

func discoveryIdentityLabel(observation fingerprint.PortObservation) string {
	switch observation.FingerprintStatus {
	case fingerprint.MatchKindConfirmed, fingerprint.MatchKindSuspected, fingerprint.MatchKindAmbiguous:
		services := make([]string, 0, len(observation.Results))
		for _, result := range observation.Results {
			services = append(services, result.Service)
		}
		return compactDiscoveryList(services)
	case fingerprint.MatchKindBanner, fingerprint.MatchKindPortHeuristic:
		if len(observation.Results) > 0 {
			return observation.Results[0].Service
		}
		return "unidentified"
	case "candidate":
		return "candidate:" + compactDiscoveryList(observation.CandidateServices)
	default:
		return "unidentified"
	}
}

func discoveryConfidenceLabel(observation fingerprint.PortObservation) string {
	if len(observation.Results) == 0 {
		return "-"
	}
	if observation.FingerprintStatus == fingerprint.MatchKindAmbiguous {
		return "mixed"
	}
	best := observation.Results[0].Confidence
	if strings.TrimSpace(best) == "" {
		return "-"
	}
	if best == fingerprint.MatchKindPortHeuristic {
		return "port-hint"
	}
	return best
}

func discoveryNotesLabel(observation fingerprint.PortObservation) string {
	notes := make([]string, 0, 3)
	switch observation.FingerprintStatus {
	case fingerprint.MatchKindConfirmed:
		// confirmed identity — no notes needed
	case fingerprint.MatchKindBanner:
		notes = append(notes, "server header only")
	case fingerprint.MatchKindPortHeuristic:
		notes = append(notes, "well-known port")
	case fingerprint.MatchKindSuspected:
		if len(observation.Results) > 0 && observation.Results[0].Ambiguity != "" {
			notes = append(notes, humanizeDiscoveryNote(observation.Results[0].Ambiguity))
		}
	case fingerprint.MatchKindAmbiguous:
		if len(observation.Results) > 0 && observation.Results[0].Ambiguity != "" {
			notes = append(notes, humanizeDiscoveryNote(observation.Results[0].Ambiguity))
		} else {
			notes = append(notes, "multiple candidates")
		}
	case "candidate":
		notes = append(notes, "partial identity evidence")
	default:
		if !observation.TimedOut {
			notes = append(notes, "no fingerprint match")
		}
	}
	if observation.TimedOut {
		notes = append(notes, "fingerprint timed out")
	}
	if len(notes) == 0 {
		return "-"
	}
	return strings.Join(notes, "; ")
}

func discoveryVersionLabel(observation fingerprint.PortObservation) string {
	if len(observation.Results) > 0 {
		primary := observation.Results[0]
		if strings.TrimSpace(primary.Version) != "" {
			label := strings.TrimSpace(primary.Service + " " + primary.Version)
			server := primary.ServerHeader
			if strings.TrimSpace(server) == "" {
				server = observation.ServerHeader
			}
			if strings.TrimSpace(server) != "" {
				label = fmt.Sprintf("%s (%s)", label, normalizeServerVersion(server))
			}
			return label
		}
		if strings.TrimSpace(primary.ServerHeader) != "" {
			return normalizeServerVersion(primary.ServerHeader)
		}
	}
	if strings.TrimSpace(observation.ServerHeader) != "" {
		return normalizeServerVersion(observation.ServerHeader)
	}
	return "-"
}

func normalizeServerVersion(header string) string {
	header = strings.Join(strings.Fields(strings.TrimSpace(header)), " ")
	if header == "" {
		return "-"
	}
	parts := strings.Fields(header)
	if len(parts) == 0 {
		return header
	}

	productTokens := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.Contains(part, "/") && !strings.HasPrefix(part, "(") {
			productTokens = append(productTokens, strings.TrimRight(part, ";"))
		}
	}
	if len(productTokens) > 0 {
		return strings.Join(productTokens, " ")
	}
	return header
}

func humanizeDiscoveryNote(note string) string {
	note = strings.TrimSpace(note)
	if note == "" {
		return ""
	}
	note = strings.ReplaceAll(note, "_", " ")
	note = strings.ReplaceAll(note, "-", " ")
	return note
}

func compactDiscoveryList(values []string) string {
	values = uniqueSortedStrings(values)
	if len(values) == 0 {
		return "-"
	}
	if len(values) == 1 {
		return values[0]
	}
	return fmt.Sprintf("%s +%d", values[0], len(values)-1)
}

// consoleSectionHeader renders a "── <title> ─────" divider that spans the current
// frame, so every section header lines up with the finding-block footer regardless of
// terminal width. The fill is computed from output.FrameWidth() rather than hardcoded.
func consoleSectionHeader(title string) string {
	prefix := "── " + title + " "
	fill := output.FrameWidth() - stringutil.VisibleWidth(prefix)
	if fill < 1 {
		fill = 1
	}
	return color.CyanString("%s%s", prefix, strings.Repeat("─", fill))
}

// printSummaryHeader opens the framed Summary block and leads with the colored severity
// tally + total, so the finding counts live inside the Summary block rather than on a
// separate footer line above it (which the console writer no longer prints).
func printSummaryHeader(w io.Writer, stats map[string]int) {
	total := 0
	for _, v := range stats {
		total += v
	}
	fmt.Fprintf(w, "\n%s\n", consoleSectionHeader("Summary"))
	printPacked(w, 2, "", []string{
		color.RedString("%d critical", stats[report.SeverityCritical]),
		color.HiRedString("%d high", stats[report.SeverityHigh]),
		color.YellowString("%d medium", stats[report.SeverityMedium]),
		color.BlueString("%d low", stats[report.SeverityLow]),
		color.HiBlackString("%d info", stats[report.SeverityInfo]),
		color.HiBlackString("(total: %d)", total),
	}, "  |  ")
}

func printDiscoverySummary(w io.Writer, summary networkScanSummary, stats map[string]int) {
	printSummaryHeader(w, stats)
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d host(s)", summary.HostsExpanded),
		fmt.Sprintf("%d port(s) scanned", summary.PortsScanned),
		fmt.Sprintf("%d open port(s)", summary.OpenPorts),
	}, "  |  ")
	printPacked(w, 2, "", []string{
		fmt.Sprintf("confirmed identities: %d", summary.ConfirmedIdentities),
		fmt.Sprintf("suspected identities: %d", summary.SuspectedIdentities),
		fmt.Sprintf("timed-out open ports: %d", summary.TimedOutPorts),
		fmt.Sprintf("unclassified open ports: %d", summary.UnclassifiedOpenPorts),
	}, "  |  ")
	if summary.HoneypotWarnings > 0 {
		fmt.Fprintf(w, "  %s\n", color.RedString("honeypot warnings: %d", summary.HoneypotWarnings))
	}
	if len(summary.ServiceCounts) > 0 {
		printPacked(w, 2, "services:", serviceCountParts(summary.ServiceCounts), ", ")
	}
}

// serviceCountParts returns the sorted "service=count" parts for a summary's service
// tally, ready to pack onto the framed services: line.
func serviceCountParts(counts map[string]int) []string {
	names := make([]string, 0, len(counts))
	for service := range counts {
		names = append(names, service)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, service := range names {
		parts = append(parts, service+"="+strconv.Itoa(counts[service]))
	}
	return parts
}

// printPacked writes parts packed onto frame-width lines under an optional label,
// hang-indented, so a summary line never breaks a part mid-word past the edge.
func printPacked(w io.Writer, indent int, label string, parts []string, sep string) {
	for _, ln := range output.PackUnder(indent, label, parts, sep) {
		fmt.Fprintln(w, ln)
	}
}

// printWrapped writes value word-wrapped onto frame-width lines under an optional
// label, hang-indented under the value column.
func printWrapped(w io.Writer, indent int, label, value string) {
	for _, ln := range output.WrapUnder(indent, label, value) {
		fmt.Fprintln(w, ln)
	}
}

func printNetworkScanSummary(w io.Writer, summary networkScanSummary, stats map[string]int, verbose bool) {
	printSummaryHeader(w, stats)
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d hosts", summary.HostsExpanded),
		fmt.Sprintf("%d open ports", summary.OpenPorts),
		fmt.Sprintf("%d vuln findings", summary.FindingsEmitted),
	}, "  |  ")

	if verbose {
		printPacked(w, 2, "", []string{
			fmt.Sprintf("ports scanned: %d", summary.PortsScanned),
			fmt.Sprintf("urls scanned: %d", summary.UniqueServiceURLsScanned),
			fmt.Sprintf("skipped: %d", summary.ServicesSkippedNoTemplates),
			fmt.Sprintf("scan-errors: %d", summary.TemplateScanErrors),
			fmt.Sprintf("request-errors: %d", summary.TemplateRequestErrors),
		}, "  |  ")
		printPacked(w, 2, "", []string{
			fmt.Sprintf("confirmed identities: %d", summary.ConfirmedIdentities),
			fmt.Sprintf("suspected identities: %d", summary.SuspectedIdentities),
			fmt.Sprintf("banner identities: %d", summary.BannerIdentities),
			fmt.Sprintf("timed-out open ports: %d", summary.TimedOutPorts),
			fmt.Sprintf("unclassified open ports: %d", summary.UnclassifiedOpenPorts),
		}, "  |  ")
		if summary.HoneypotWarnings > 0 {
			fmt.Fprintf(w, "  %s\n", color.RedString("honeypot warnings: %d", summary.HoneypotWarnings))
		}
		if len(summary.ServiceCounts) > 0 {
			printPacked(w, 2, "services:", serviceCountParts(summary.ServiceCounts), ", ")
		}
	}
	if summary.AmbiguousServicesExpanded > 0 {
		fmt.Fprintf(w, "  %d ambiguous service(s) expanded across plausible identities\n",
			summary.AmbiguousServicesExpanded)
	}
	if summary.NonHTTPTemplateSkips > 0 {
		fmt.Fprintf(w, "  %d non-HTTP service identity(s) skipped for HTTP template scanning\n",
			summary.NonHTTPTemplateSkips)
	}
	if summary.TemplateScanErrors > 0 || summary.TemplateRequestErrors > 0 || summary.TemplateErrors > 0 {
		fmt.Fprintf(w, "  incomplete coverage: %d scan error(s)  %d request error(s)  %d template error(s)\n",
			summary.TemplateScanErrors, summary.TemplateRequestErrors, summary.TemplateErrors)
	}
}

func printScanAllSummary(w io.Writer, summary scanAllSummary, stats map[string]int) {
	printSummaryHeader(w, stats)
	printPacked(w, 2, "", []string{
		fmt.Sprintf("%d service(s) discovered", summary.ServicesDiscovered),
		fmt.Sprintf("%d finding(s)", summary.FindingsEmitted),
	}, "  |  ")
	if summary.AmbiguousServicesExpanded > 0 {
		printWrapped(w, 2, "", fmt.Sprintf("%d ambiguous service(s) expanded across plausible identities", summary.AmbiguousServicesExpanded))
	}
	if summary.NonHTTPTemplateSkips > 0 {
		printWrapped(w, 2, "", fmt.Sprintf("%d non-HTTP service identity(s) skipped for HTTP template scanning", summary.NonHTTPTemplateSkips))
	}
	if summary.EnumerationSkipped > 0 {
		printWrapped(w, 2, "", fmt.Sprintf("%d service(s) had no enumerator (template scan only, no Phase 3 enumeration)", summary.EnumerationSkipped))
	}
	if summary.EnumerationNotApplicable > 0 {
		printWrapped(w, 2, "", fmt.Sprintf("%d probe(s) reached a service that was not the fingerprinted identity (ambiguous port — not a failure)", summary.EnumerationNotApplicable))
	}
	if summary.ServicesWithScanFailures > 0 || summary.TemplateRequestErrors > 0 || summary.TemplateErrors > 0 || summary.EnumerationFailures > 0 || summary.EnumerationPartialFailures > 0 {
		printPacked(w, 2, "incomplete coverage:", []string{
			fmt.Sprintf("%d scan failure(s)", summary.ServicesWithScanFailures),
			fmt.Sprintf("%d request error(s)", summary.TemplateRequestErrors),
			fmt.Sprintf("%d template error(s)", summary.TemplateErrors),
			fmt.Sprintf("%d enumeration failure(s)", summary.EnumerationFailures),
			fmt.Sprintf("%d partial enumeration(s)", summary.EnumerationPartialFailures),
		}, "  ")
	}
}

func printHoneypotWarnings(signals []fingerprint.HoneypotSignal) {
	if len(signals) == 0 {
		return
	}
	byHost := make(map[string][]fingerprint.HoneypotSignal)
	var hostOrder []string
	for _, s := range signals {
		if _, seen := byHost[s.Host]; !seen {
			hostOrder = append(hostOrder, s.Host)
		}
		byHost[s.Host] = append(byHost[s.Host], s)
	}
	for _, host := range hostOrder {
		warnf("%s", color.RedString("target %s may be a honeypot", host))
		for _, s := range byHost[host] {
			warnf("  %s", s.Reason)
		}
	}
}
