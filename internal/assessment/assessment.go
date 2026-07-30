package assessment

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

// CanonicalServiceURL normalizes a URL for deduplication and indexing. Only the
// scheme and host are case-insensitive per RFC 3986 and get lowercased; the path,
// query, and userinfo are case-sensitive and preserved verbatim — lowercasing them
// would both over-merge distinct resources ("/API" vs "/api") and corrupt case-
// sensitive tokens when the canonical form is reused in generated follow-up commands.
func CanonicalServiceURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		// Bare host:port — no path/query/userinfo to protect; host is case-insensitive.
		return strings.TrimRight(strings.ToLower(raw), "/")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimRight(raw, "/") // unparseable — trim only, never corrupt
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return strings.TrimRight(u.String(), "/")
}

// UniqueSort deduplicates, trims, and sorts a string slice.
// Delegates to stringutil.DedupeStrings to avoid duplication.
func UniqueSort(values []string) []string {
	return stringutil.DedupeStrings(values)
}

// UniqueSortPorts deduplicates and sorts an int slice.
func UniqueSortPorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	normalized := make([]int, 0, len(ports))
	for _, port := range ports {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		normalized = append(normalized, port)
	}
	sort.Ints(normalized)
	return normalized
}

// DedupeFingerprints deduplicates and sorts fingerprint results.
func DedupeFingerprints(results []fingerprint.Result) []fingerprint.Result {
	best := make(map[string]fingerprint.Result, len(results))
	for _, result := range results {
		key := CanonicalServiceURL(result.URL) + "|" + result.Service
		existing, ok := best[key]
		if !ok || result.Specificity > existing.Specificity || (result.Specificity == existing.Specificity && fingerprintResultLess(result, existing)) {
			best[key] = result
		}
	}

	normalized := make([]fingerprint.Result, 0, len(best))
	for _, result := range best {
		normalized = append(normalized, result)
	}

	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Service != normalized[j].Service {
			return normalized[i].Service < normalized[j].Service
		}
		if CanonicalServiceURL(normalized[i].URL) != CanonicalServiceURL(normalized[j].URL) {
			return CanonicalServiceURL(normalized[i].URL) < CanonicalServiceURL(normalized[j].URL)
		}
		if normalized[i].Specificity != normalized[j].Specificity {
			return normalized[i].Specificity > normalized[j].Specificity
		}
		return fingerprintResultLess(normalized[i], normalized[j])
	})

	return normalized
}

// DedupePortObservations normalizes and sorts discovery observations by host:port.
func DedupePortObservations(observations []fingerprint.PortObservation) []fingerprint.PortObservation {
	best := make(map[string]fingerprint.PortObservation, len(observations))
	for _, observation := range observations {
		key := fmt.Sprintf("%s:%d", observation.Host, observation.Port)
		existing, ok := best[key]
		if !ok || portObservationLess(existing, observation) {
			best[key] = observation
		}
	}

	normalized := make([]fingerprint.PortObservation, 0, len(best))
	for _, observation := range best {
		normalized = append(normalized, observation)
	}

	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Host != normalized[j].Host {
			return normalized[i].Host < normalized[j].Host
		}
		return normalized[i].Port < normalized[j].Port
	})

	return normalized
}

func portObservationLess(a, b fingerprint.PortObservation) bool {
	if a.TimedOut != b.TimedOut {
		return !a.TimedOut && b.TimedOut
	}
	if len(a.Results) != len(b.Results) {
		return len(a.Results) < len(b.Results)
	}
	if len(a.CandidateServices) != len(b.CandidateServices) {
		return len(a.CandidateServices) < len(b.CandidateServices)
	}
	return a.URL < b.URL
}

func fingerprintResultLess(a, b fingerprint.Result) bool {
	if a.Host != b.Host {
		return a.Host < b.Host
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	if a.URL != b.URL {
		return a.URL < b.URL
	}
	return a.Details < b.Details
}

// DedupeAndSortFindings deduplicates findings by content and sorts them.
func DedupeAndSortFindings(findings []report.Finding) []report.Finding {
	type keyedFinding struct {
		finding   report.Finding
		dedupeKey string
	}

	keyed := make([]keyedFinding, len(findings))
	for i, f := range findings {
		keyed[i] = keyedFinding{finding: f, dedupeKey: findingDedupeKey(f)}
	}

	sort.Slice(keyed, func(i, j int) bool {
		// Primary: severity descending (critical first) so the worst findings surface at the
		// top of every output. Severity is part of the dedupe key, so equal-key duplicates share
		// a severity and stay adjacent within their bucket — the dedup pass below still works.
		if ri, rj := severityRankForFindings(keyed[i].finding.Severity), severityRankForFindings(keyed[j].finding.Severity); ri != rj {
			return ri < rj
		}
		if keyed[i].dedupeKey != keyed[j].dedupeKey {
			return keyed[i].dedupeKey < keyed[j].dedupeKey
		}
		a, b := keyed[i].finding, keyed[j].finding
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Evidence != b.Evidence {
			return a.Evidence < b.Evidence
		}
		return MetadataString(a.Metadata) < MetadataString(b.Metadata)
	})

	deduped := make([]report.Finding, 0, len(keyed))
	for i := 0; i < len(keyed); {
		current := keyed[i].finding
		count := 1
		j := i + 1
		for j < len(keyed) && keyed[j].dedupeKey == keyed[i].dedupeKey {
			count++
			j++
		}
		if count > 1 {
			if current.Metadata == nil {
				current.Metadata = make(map[string]interface{})
			}
			current.Metadata["dedupe_count"] = count - 1
		}
		deduped = append(deduped, current)
		i = j
	}

	return deduped
}

// severityRankForFindings orders severities for display (critical first, info last).
func severityRankForFindings(sev string) int {
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

func findingDedupeKey(f report.Finding) string {
	var ps, action string
	if f.Metadata != nil {
		ps, _ = f.Metadata["landed"].(string)
		action, _ = f.Metadata["action"].(string)
	}
	return strings.Join([]string{
		f.Source,
		f.TemplateID,
		f.Target,
		f.Title,
		f.Severity,
		f.Description,
		f.Evidence,
		ps,
		action,
	}, "\x00")
}

// MetadataString produces a stable string representation of finding metadata.
func MetadataString(metadata map[string]interface{}) string {
	if len(metadata) == 0 {
		return ""
	}

	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+fmt.Sprint(metadata[key]))
	}
	return strings.Join(parts, ",")
}

// FindingStats computes severity counts for a set of findings.
func FindingStats(findings []report.Finding) map[string]int {
	stats := map[string]int{
		report.SeverityCritical: 0,
		report.SeverityHigh:     0,
		report.SeverityMedium:   0,
		report.SeverityLow:      0,
		report.SeverityInfo:     0,
	}
	for _, finding := range findings {
		stats[report.NormalizeSeverity(finding.Severity)]++
	}
	return stats
}

// TargetGroupKey returns the stable grouping key for host-oriented summaries.
// File-discovery findings are grouped under a synthetic bucket so local paths
// do not distort host counts in merged reports.
func TargetGroupKey(source, target string) string {
	if source == report.SourceFileDiscovery {
		return "local-files"
	}
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
