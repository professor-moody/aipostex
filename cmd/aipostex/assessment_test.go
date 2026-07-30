package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

// At a narrow frame, the discovery Summary's services: line wraps at part boundaries —
// a "svc=N" pair is never split mid-word (the "…wan\ndb=1" bug the round-2 pass fixed).
func TestDiscoverySummaryServicesLineNeverSplitsAPart(t *testing.T) {
	output.SetConsoleWidth(48)
	defer output.SetConsoleWidth(400)
	summary := networkScanSummary{
		HostsExpanded: 3, PortsScanned: 30, OpenPorts: 9,
		ServiceCounts: map[string]int{
			"ollama": 2, "litellm": 1, "chromadb": 1, "weaviate": 4, "qdrant": 2, "mlflow": 1,
		},
	}
	var out strings.Builder
	printDiscoverySummary(&out, summary, map[string]int{})
	rendered := out.String()
	for _, ln := range strings.Split(rendered, "\n") {
		// The "── Summary ──" divider is a fixed-width decorative separator, not framed
		// content; the invariant here is that the content lines wrap within the frame.
		if strings.Contains(ln, "─") {
			continue
		}
		if stringutil.VisibleWidth(ln) > 48 {
			t.Fatalf("summary content line exceeds width 48 (%d): %q", stringutil.VisibleWidth(ln), ln)
		}
	}
	for _, part := range []string{"ollama=2", "litellm=1", "chromadb=1", "weaviate=4", "qdrant=2", "mlflow=1"} {
		if !strings.Contains(rendered, part) {
			t.Fatalf("service part %q was split or dropped:\n%s", part, rendered)
		}
	}
}

func TestPrintHoneypotWarningsGroupsByHost(t *testing.T) {
	prevErr := stderrWriter
	defer func() { stderrWriter = prevErr }()
	var buf strings.Builder
	stderrWriter = &buf

	signals := []fingerprint.HoneypotSignal{
		{Host: "10.0.0.1", Reason: "too many open ports"},
		{Host: "10.0.0.1", Reason: "identical banners"},
		{Host: "10.0.0.2", Reason: "suspicious response time"},
	}
	printHoneypotWarnings(signals)
	rendered := buf.String()

	if !strings.Contains(rendered, "10.0.0.1") {
		t.Fatalf("expected host 10.0.0.1 in output, got %q", rendered)
	}
	if !strings.Contains(rendered, "10.0.0.2") {
		t.Fatalf("expected host 10.0.0.2 in output, got %q", rendered)
	}
	if !strings.Contains(rendered, "too many open ports") {
		t.Fatalf("expected reason in output, got %q", rendered)
	}
	if !strings.Contains(rendered, "honeypot") {
		t.Fatalf("expected honeypot warning in output, got %q", rendered)
	}
}

func TestPrintHoneypotWarningsEmpty(t *testing.T) {
	prevErr := stderrWriter
	defer func() { stderrWriter = prevErr }()
	var buf strings.Builder
	stderrWriter = &buf

	printHoneypotWarnings(nil)
	if buf.Len() != 0 {
		t.Fatalf("expected no output for empty signals, got %q", buf.String())
	}
}

func TestFormatFingerprintBudget(t *testing.T) {
	if formatFingerprintBudget(0) != "budget exhausted" {
		t.Fatalf("zero duration")
	}
	if formatFingerprintBudget(-time.Second) != "budget exhausted" {
		t.Fatalf("negative duration")
	}
	if got := formatFingerprintBudget(3 * time.Second); got != (3 * time.Second).String() {
		t.Fatalf("got %q", got)
	}
}

func TestDedupeAndSortFindingsCollapsesDuplicatesDeterministically(t *testing.T) {
	findings := []report.Finding{
		{ID: "b", Source: report.SourceVulnCheck, TemplateID: "tmpl", Target: "http://b", Title: "B", Severity: report.SeverityHigh, Description: "desc"},
		{ID: "dup2", Source: report.SourceVulnCheck, TemplateID: "tmpl", Target: "http://a", Title: "A", Severity: report.SeverityCritical, Description: "same", Evidence: "same"},
		{ID: "dup1", Source: report.SourceVulnCheck, TemplateID: "tmpl", Target: "http://a", Title: "A", Severity: report.SeverityCritical, Description: "same", Evidence: "same"},
	}

	deduped := dedupeAndSortFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 findings after dedupe, got %d", len(deduped))
	}
	if deduped[0].Target != "http://a" {
		t.Fatalf("expected findings to be sorted deterministically, got first target %q", deduped[0].Target)
	}
	if deduped[0].Metadata["dedupe_count"] != 1 {
		t.Fatalf("expected dedupe_count=1, got %#v", deduped[0].Metadata["dedupe_count"])
	}
}

func TestDedupePreservesDistinctEvidence(t *testing.T) {
	findings := []report.Finding{
		{Source: report.SourceVulnCheck, TemplateID: "tmpl", Target: "http://a", Title: "A", Severity: report.SeverityHigh, Description: "same", Evidence: "secret-1"},
		{Source: report.SourceVulnCheck, TemplateID: "tmpl", Target: "http://a", Title: "A", Severity: report.SeverityHigh, Description: "same", Evidence: "secret-2"},
	}

	deduped := dedupeAndSortFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("expected findings with different evidence to be preserved, got %d", len(deduped))
	}
}

func TestDedupeFingerprintResultsKeepsHighestSpecificity(t *testing.T) {
	results := []fingerprint.Result{
		{Host: "1.1.1.1", Port: 8000, Service: "openai-compatible", URL: "http://1.1.1.1:8000", Specificity: 20},
		{Host: "1.1.1.1", Port: 8000, Service: "openai-compatible", URL: "http://1.1.1.1:8000/", Specificity: 40},
		{Host: "1.1.1.2", Port: 11434, Service: "ollama", URL: "http://1.1.1.2:11434", Specificity: 100},
	}

	deduped := dedupeFingerprintResults(results)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 results after dedupe, got %d", len(deduped))
	}
	if deduped[0].Service != "ollama" || deduped[1].Specificity != 40 {
		t.Fatalf("unexpected deduped results: %#v", deduped)
	}
}

func TestNormalizeServiceTagsUsesUserTagsExclusivelyWhenProvided(t *testing.T) {
	tags := normalizeServiceTags("vllm", []string{"openai-compatible", "custom", "custom"})
	expected := []string{"custom", "openai-compatible"}
	if strings.Join(tags, ",") != strings.Join(expected, ",") {
		t.Fatalf("expected user tags only %v, got %v", expected, tags)
	}
}

func TestNormalizeServiceTagsFallsBackToServiceTagsWhenNoUserTags(t *testing.T) {
	tags := normalizeServiceTags("ollama", nil)
	if len(tags) == 0 {
		t.Fatal("expected service-derived tags, got none")
	}
	found := false
	for _, tag := range tags {
		if tag == "ollama" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'ollama' in service tags, got %v", tags)
	}
}

func TestPrintNetworkScanSummaryCompactFormat(t *testing.T) {
	summary := networkScanSummary{
		HostsExpanded:              4,
		PortsScanned:               3,
		OpenPorts:                  3,
		ServicesDiscovered:         2,
		ConfirmedIdentities:        1,
		SuspectedIdentities:        1,
		UniqueServiceURLsScanned:   1,
		ServicesSkippedNoTemplates: 1,
		FindingsEmitted:            3,
		ServiceCounts: map[string]int{
			"ollama": 1,
			"ray":    1,
		},
	}
	stats := map[string]int{
		"critical": 1,
		"high":     1,
		"medium":   0,
		"low":      0,
		"info":     1,
	}

	var out strings.Builder
	printNetworkScanSummary(&out, summary, stats, false)
	rendered := out.String()
	for _, expected := range []string{
		"Summary",
		"4 hosts",
		"3 open ports",
		"3 vuln findings",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected summary to contain %q, got %q", expected, rendered)
		}
	}
}

func TestPrintNetworkScanSummaryVerboseIncludesDetails(t *testing.T) {
	summary := networkScanSummary{
		HostsExpanded:              4,
		PortsScanned:               3,
		OpenPorts:                  3,
		ServicesDiscovered:         2,
		ConfirmedIdentities:        1,
		SuspectedIdentities:        1,
		UniqueServiceURLsScanned:   1,
		ServicesSkippedNoTemplates: 1,
		FindingsEmitted:            3,
		ServiceCounts: map[string]int{
			"ollama": 1,
			"ray":    1,
		},
	}
	stats := map[string]int{
		"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1,
	}

	var out strings.Builder
	printNetworkScanSummary(&out, summary, stats, true)
	rendered := out.String()
	for _, expected := range []string{
		"skipped: 1",
		"confirmed identities: 1  |  suspected identities: 1",
		"services: ollama=1, ray=1",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected verbose summary to contain %q, got %q", expected, rendered)
		}
	}
}

func TestServiceToTagsIncludesBroaderServiceFamilies(t *testing.T) {
	tests := map[string][]string{
		"ray":       {"ray"},
		"mlflow":    {"mlflow"},
		"gradio":    {"gradio"},
		"triton":    {"triton"},
		"bentoml":   {"bentoml"},
		"wandb":     {"wandb"},
		"hf-tgi":    {"huggingface", "tgi"},
		"hf-tei":    {"huggingface", "tei"},
		"langserve": {"langchain", "langserve"},
	}

	for service, expected := range tests {
		got := serviceToTags(service)
		if strings.Join(got, ",") != strings.Join(expected, ",") {
			t.Fatalf("expected tags %v for %s, got %v", expected, service, got)
		}
	}
}

func TestStripURLTargetsExtractsHostAndPort(t *testing.T) {
	targets := []string{
		"http://10.0.0.1:8000",
		"https://10.0.0.2:11434/path",
		"10.0.0.3",
		"192.168.1.0/24",
	}
	cleaned, ports := stripURLTargets(targets)

	expectedHosts := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "192.168.1.0/24"}
	if len(cleaned) != len(expectedHosts) {
		t.Fatalf("expected %d cleaned targets, got %d: %v", len(expectedHosts), len(cleaned), cleaned)
	}
	for i, h := range expectedHosts {
		if cleaned[i] != h {
			t.Fatalf("expected cleaned[%d]=%q, got %q", i, h, cleaned[i])
		}
	}
	if len(ports) == 0 || ports[0] != 8000 {
		t.Fatalf("expected extracted port 8000 in first position, got %v", ports)
	}
	portFound := false
	for _, p := range ports {
		if p == 11434 {
			portFound = true
		}
	}
	if !portFound {
		t.Fatalf("expected port 11434 in extracted ports, got %v", ports)
	}
}

func TestTagsToServiceReverseMapping(t *testing.T) {
	tests := map[string]string{
		"ollama":    "ollama",
		"chromadb":  "chromadb",
		"weaviate":  "weaviate",
		"qdrant":    "qdrant",
		"jupyter":   "jupyter",
		"wandb":     "wandb",
		"bentoml":   "bentoml",
		"triton":    "triton",
		"tgi":       "hf-tgi",
		"tei":       "hf-tei",
		"langserve": "langserve",
		"mcp":       "mcp-sse",
		"unknown":   "",
	}
	for tag, want := range tests {
		got := tagsToService(tag)
		if got != want {
			t.Fatalf("tagsToService(%q) = %q, want %q", tag, got, want)
		}
	}
}

func TestTagsToServiceGenericTagsReturnEmpty(t *testing.T) {
	for _, generic := range []string{"vectordb", "llmjacking"} {
		got := tagsToService(generic)
		if got != "" {
			t.Fatalf("tagsToService(%q) = %q, want empty (generic tags should not map to a specific vendor)", generic, got)
		}
	}
}

func TestInferWorkflowPlansFromFindings(t *testing.T) {
	findings := []report.Finding{
		{
			Target: "http://10.0.0.1:11434",
			Tags:   []string{"ollama", "recon"},
		},
		{
			Target: "http://10.0.0.2:8265",
			Tags:   []string{"ray"},
		},
	}
	plans := inferWorkflowPlansFromFindings(findings, []string{
		"http://10.0.0.1:11434",
		"http://10.0.0.2:8265",
	})
	if len(plans) < 2 {
		t.Fatalf("expected at least 2 workflow plans, got %d", len(plans))
	}
	servicesSeen := make(map[string]bool)
	for _, p := range plans {
		for _, r := range p.Recommendations {
			if strings.Contains(r.Command, "ollama") {
				servicesSeen["ollama"] = true
			}
			if strings.Contains(r.Command, "ray") {
				servicesSeen["ray"] = true
			}
		}
	}
	if !servicesSeen["ollama"] || !servicesSeen["ray"] {
		t.Fatalf("expected workflow plans for both ollama and ray, got %v", servicesSeen)
	}
}

func TestInferWorkflowPlansUsesVendorTagNotGeneric(t *testing.T) {
	findings := []report.Finding{
		{
			Target: "http://10.0.0.30:8080",
			Tags:   []string{"vectordb", "weaviate", "auth", "misconfiguration"},
		},
	}
	plans := inferWorkflowPlansFromFindings(findings, []string{"http://10.0.0.30:8080"})
	if len(plans) == 0 {
		t.Fatal("expected at least 1 workflow plan for weaviate finding")
	}
	for _, p := range plans {
		for _, r := range p.Recommendations {
			if strings.Contains(r.Command, "chromadb") {
				t.Fatalf("weaviate finding should not produce chromadb commands, got: %s", r.Command)
			}
		}
	}
	found := false
	for _, p := range plans {
		for _, r := range p.Recommendations {
			if strings.Contains(r.Command, "weaviate") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected workflow plan to contain weaviate commands")
	}
}

func TestInferWorkflowPlansDeduplicatesOverlappingTags(t *testing.T) {
	findings := []report.Finding{
		{
			Target: "http://10.0.0.1:80",
			Tags:   []string{"vllm", "auth", "misconfiguration", "llmjacking", "openai-compatible"},
		},
	}
	plans := inferWorkflowPlansFromFindings(findings, []string{"http://10.0.0.1:80"})

	cmdCount := make(map[string]int)
	for _, p := range plans {
		for _, r := range p.Recommendations {
			cmdCount[r.Command]++
		}
	}
	for cmd, count := range cmdCount {
		if count > 1 {
			t.Fatalf("duplicate workflow command produced: %q appeared %d times", cmd, count)
		}
	}
}

func TestInferWorkflowPlansFromFindings_PrefersLiteLLMOverOpenAICompat(t *testing.T) {
	findings := []report.Finding{{
		Tags:   []string{"openai-compatible", "litellm", "llmjacking"},
		Target: "http://127.0.0.1:4000",
	}}
	plans := inferWorkflowPlansFromFindings(findings, nil)
	if len(plans) == 0 {
		t.Fatal("expected workflow plans")
	}
	var sawLiteLLMProbe bool
	for _, p := range plans {
		for _, rec := range p.Recommendations {
			if strings.Contains(rec.Command, "litellm-probe") {
				sawLiteLLMProbe = true
			}
		}
	}
	if !sawLiteLLMProbe {
		t.Fatalf("expected LiteLLM-specific litellm-probe recommendation, got %#v", plans)
	}
}

func TestWorkflowCanonicalServiceCoalesces(t *testing.T) {
	tests := map[string]string{
		"vllm":              "openai-compatible",
		"localai":           "openai-compatible",
		"lmstudio":          "openai-compatible",
		"openai-compatible": "openai-compatible",
		"litellm":           "litellm",
		"ollama":            "ollama",
		"mcp-inspector":     "mcp-inspector",
		"mcpjam-inspector":  "mcpjam-inspector",
		"chromadb":          "chromadb",
	}
	for input, want := range tests {
		got := workflowCanonicalService(input)
		if got != want {
			t.Fatalf("workflowCanonicalService(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPrintNetworkScanSummarySplitCounts(t *testing.T) {
	summary := networkScanSummary{
		HostsExpanded:      1,
		OpenPorts:          2,
		ServicesDiscovered: 5,
		FindingsEmitted:    10,
		ServiceCounts:      map[string]int{},
	}
	stats := map[string]int{
		"critical": 2, "high": 3, "medium": 5, "low": 0, "info": 0,
	}

	var out strings.Builder
	printNetworkScanSummary(&out, summary, stats, false)
	rendered := out.String()
	if !strings.Contains(rendered, "10 vuln findings") {
		t.Fatalf("expected '10 vuln findings' in summary, got %q", rendered)
	}
}

func TestPrintDiscoverySummaryShowsServiceCounts(t *testing.T) {
	summary := networkScanSummary{
		HostsExpanded:         2,
		PortsScanned:          5,
		OpenPorts:             4,
		ServicesDiscovered:    3,
		ConfirmedIdentities:   2,
		SuspectedIdentities:   1,
		TimedOutPorts:         1,
		UnclassifiedOpenPorts: 1,
		ServiceCounts: map[string]int{
			"ollama": 2,
			"qdrant": 1,
		},
	}

	var out strings.Builder
	printDiscoverySummary(&out, summary, map[string]int{})
	rendered := out.String()
	for _, expected := range []string{
		"Summary",
		"2 host(s)",
		"5 port(s) scanned",
		"4 open port(s)",
		"confirmed identities: 2",
		"ollama=2",
		"qdrant=1",
		// The severity tally now leads the Summary block (folded in from the old footer).
		"(total:",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected discovery summary to contain %q, got %q", expected, rendered)
		}
	}
	// Discovery counts hosts/ports, not vuln findings.
	if strings.Contains(rendered, "vuln") {
		t.Fatalf("discovery summary should not contain vuln-finding info, got %q", rendered)
	}
}

func TestPrintDiscoveryTableFormatsResults(t *testing.T) {
	observations := []fingerprint.PortObservation{
		{Host: "10.0.0.1", Port: 8000, URL: "http://10.0.0.1:8000", PortState: "open", FingerprintStatus: fingerprint.MatchKindConfirmed, ServerHeader: "uvicorn", Results: []fingerprint.Result{{Service: "chromadb", Confidence: "high", Version: "0.5.23"}}},
		{Host: "10.0.0.1", Port: 11434, URL: "http://10.0.0.1:11434", PortState: "open", FingerprintStatus: fingerprint.MatchKindConfirmed, Results: []fingerprint.Result{{Service: "ollama", Confidence: "high", Version: "0.4.7"}}},
		{Host: "10.0.0.1", Port: 6333, URL: "http://10.0.0.1:6333", PortState: "open", FingerprintStatus: "unidentified"},
		{Host: "10.0.0.1", Port: 80, URL: "http://10.0.0.1:80", PortState: "open", FingerprintStatus: fingerprint.MatchKindBanner, ServerHeader: "nginx/1.18.0", Results: []fingerprint.Result{{Service: "nginx", Confidence: "banner", MatchKind: fingerprint.MatchKindBanner}}},
		{Host: "10.0.0.1", Port: 5432, URL: "http://10.0.0.1:5432", PortState: "open", FingerprintStatus: fingerprint.MatchKindPortHeuristic, Results: []fingerprint.Result{{Service: "postgresql", Confidence: "port-heuristic", MatchKind: fingerprint.MatchKindPortHeuristic}}},
	}

	var out strings.Builder
	printDiscoveryTable(&out, observations)
	rendered := out.String()

	for _, expected := range []string{
		"Discovery",
		"PORT",
		"IDENTITY",
		"CONFIDENCE",
		"NOTES",
		"VERSION",
		"8000/tcp",
		"chromadb",
		"chromadb 0.5.23",
		"high",
		"uvicorn",
		"11434/tcp",
		"ollama",
		"ollama 0.4.7",
		"6333/tcp",
		"unidentified",
		"80/tcp",
		"nginx",
		"nginx/1.18.0",
		"banner",
		"server header only",
		"5432/tcp",
		"postgresql",
		"port-hint",
		"well-known port",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected discovery table to contain %q, got %q", expected, rendered)
		}
	}
	if strings.Contains(rendered, "HOST") {
		t.Fatalf("single-host scan should not show HOST column, got %q", rendered)
	}
}

func TestPrintDiscoveryTableMultiHostShowsHostColumn(t *testing.T) {
	observations := []fingerprint.PortObservation{
		{Host: "10.0.0.1", Port: 11434, URL: "http://10.0.0.1:11434", PortState: "open", FingerprintStatus: fingerprint.MatchKindConfirmed, Results: []fingerprint.Result{{Service: "ollama"}}},
		{Host: "10.0.0.2", Port: 8000, URL: "http://10.0.0.2:8000", PortState: "open", FingerprintStatus: fingerprint.MatchKindConfirmed, Results: []fingerprint.Result{{Service: "chromadb"}}},
		{Host: "10.0.0.1", Port: 6333, URL: "http://10.0.0.1:6333", PortState: "open", FingerprintStatus: "unidentified"},
	}

	var out strings.Builder
	printDiscoveryTable(&out, observations)
	rendered := out.String()

	if !strings.Contains(rendered, "HOST") {
		t.Fatalf("multi-host scan should show HOST column, got %q", rendered)
	}
	if !strings.Contains(rendered, "10.0.0.1") || !strings.Contains(rendered, "10.0.0.2") {
		t.Fatalf("multi-host table should contain both hosts, got %q", rendered)
	}
}

func TestPrintDiscoveryTableEmptyResults(t *testing.T) {
	var out strings.Builder
	printDiscoveryTable(&out, nil)
	if out.Len() != 0 {
		t.Fatalf("expected no output for empty results, got %q", out.String())
	}
}

func TestPrintWorkflowPlansIncludesNewModules(t *testing.T) {
	var out strings.Builder
	printWorkflowPlans(&out, []workflowPlan{
		buildScanNetworkWorkflowPlan(fingerprint.Result{Service: "ray", URL: "http://10.0.0.7:8265"}),
		buildScanNetworkWorkflowPlan(fingerprint.Result{Service: "mlflow", URL: "http://10.0.0.8:5000"}),
		buildScanNetworkWorkflowPlan(fingerprint.Result{Service: "gradio", URL: "http://10.0.0.9:7860"}),
	}, false)

	rendered := out.String()
	for _, expected := range []string{
		"Next Actions",
		"ray --target http://10.0.0.7:8265 enum",
		"ray --target http://10.0.0.7:8265 jobs",
		"mlflow --target http://10.0.0.8:5000 enum",
		"gradio --target http://10.0.0.9:7860 enum",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected workflow plans to contain %q, got %q", expected, rendered)
		}
	}
}

func TestFingerprintToFindingProducesValidFinding(t *testing.T) {
	r := fingerprint.Result{
		Host:       "10.0.0.5",
		Port:       11434,
		Service:    "ollama",
		URL:        "http://10.0.0.5:11434",
		Version:    "0.6.2",
		MatchKind:  fingerprint.MatchKindConfirmed,
		Confidence: "high",
	}
	f := fingerprintToFinding(r)
	if f.ID != "fingerprint-port-10.0.0.5-11434" {
		t.Fatalf("id = %q, want fingerprint-port-10.0.0.5-11434", f.ID)
	}
	if f.Source != report.SourceFingerprint {
		t.Fatalf("source = %q, want %q", f.Source, report.SourceFingerprint)
	}
	if f.Severity != report.SeverityInfo {
		t.Fatalf("severity = %q, want info", f.Severity)
	}
	if f.Target != r.URL {
		t.Fatalf("target = %q, want %q", f.Target, r.URL)
	}
	if !strings.Contains(strings.ToLower(f.Title), "open network port") {
		t.Fatalf("title should mention service, got %q", f.Title)
	}
	if f.Metadata["version"] != "0.6.2" {
		t.Fatalf("metadata version = %v, want 0.6.2", f.Metadata["version"])
	}
	if f.Metadata["host"] != "10.0.0.5" {
		t.Fatalf("metadata host = %v, want 10.0.0.5", f.Metadata["host"])
	}
	if f.Metadata["port"] != 11434 {
		t.Fatalf("metadata port = %v, want 11434", f.Metadata["port"])
	}
	if f.Metadata["match_kind"] != fingerprint.MatchKindConfirmed {
		t.Fatalf("metadata match_kind = %v, want confirmed", f.Metadata["match_kind"])
	}
	if f.Metadata["confidence"] != "high" {
		t.Fatalf("metadata confidence = %v, want high", f.Metadata["confidence"])
	}
}

func TestFingerprintToFindingOmitsVersionWhenEmpty(t *testing.T) {
	r := fingerprint.Result{
		Host:    "10.0.0.5",
		Port:    8000,
		Service: "chromadb",
		URL:     "http://10.0.0.5:8000",
	}
	f := fingerprintToFinding(r)
	if _, ok := f.Metadata["version"]; ok {
		t.Fatalf("metadata version should be omitted when empty, got %#v", f.Metadata["version"])
	}
}

func TestFingerprintToFindingMarksSuspectedMatches(t *testing.T) {
	r := fingerprint.Result{
		Host:       "10.0.0.9",
		Port:       8000,
		Service:    "langserve",
		URL:        "http://10.0.0.9:8000",
		MatchKind:  fingerprint.MatchKindSuspected,
		Confidence: "low",
		Ambiguity:  "generic_match_only",
	}
	f := fingerprintToFinding(r)
	if f.Metadata["fingerprint_status"] != fingerprint.MatchKindSuspected {
		t.Fatalf("expected suspected fingerprint status, got %#v", f.Metadata["fingerprint_status"])
	}
	if f.Metadata["ambiguity_reason"] != "generic_match_only" {
		t.Fatalf("metadata ambiguity_reason = %v, want generic_match_only", f.Metadata["ambiguity_reason"])
	}
}

func TestUniqueSortedHosts(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"nil input", nil, nil},
		{"empty input", []string{}, nil},
		{"single host", []string{"10.0.0.1"}, []string{"10.0.0.1"}},
		{"already sorted and unique", []string{"10.0.0.1", "10.0.0.2"}, []string{"10.0.0.1", "10.0.0.2"}},
		{"duplicates removed", []string{"10.0.0.1", "10.0.0.2", "10.0.0.1"}, []string{"10.0.0.1", "10.0.0.2"}},
		{"unsorted input", []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"whitespace trimmed", []string{" 10.0.0.1 ", "10.0.0.2"}, []string{"10.0.0.1", "10.0.0.2"}},
		{"empty strings filtered", []string{"10.0.0.1", "", "  ", "10.0.0.2"}, []string{"10.0.0.1", "10.0.0.2"}},
		{"all duplicates", []string{"a", "a", "a"}, []string{"a"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := uniqueSortedHosts(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("index %d: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestDedupePortObservations(t *testing.T) {
	tests := []struct {
		name    string
		input   []fingerprint.PortObservation
		wantLen int
		check   func([]fingerprint.PortObservation) error
	}{
		{
			name:    "nil input",
			input:   nil,
			wantLen: 0,
		},
		{
			name:    "empty input",
			input:   []fingerprint.PortObservation{},
			wantLen: 0,
		},
		{
			name: "no duplicates preserved",
			input: []fingerprint.PortObservation{
				{Host: "10.0.0.1", Port: 8000, PortState: "open"},
				{Host: "10.0.0.1", Port: 11434, PortState: "open"},
			},
			wantLen: 2,
		},
		{
			name: "duplicate host:port deduped",
			input: []fingerprint.PortObservation{
				{Host: "10.0.0.1", Port: 8000, PortState: "open"},
				{Host: "10.0.0.1", Port: 8000, PortState: "open"},
			},
			wantLen: 1,
		},
		{
			name: "keeps observation with more results",
			input: []fingerprint.PortObservation{
				{Host: "10.0.0.1", Port: 8000, PortState: "open", Results: nil},
				{Host: "10.0.0.1", Port: 8000, PortState: "open", Results: []fingerprint.Result{{Service: "ollama"}}},
			},
			wantLen: 1,
			check: func(obs []fingerprint.PortObservation) error {
				if len(obs[0].Results) != 1 {
					return fmt.Errorf("expected result with 1 identity, got %d", len(obs[0].Results))
				}
				return nil
			},
		},
		{
			name: "sorted by host then port",
			input: []fingerprint.PortObservation{
				{Host: "10.0.0.2", Port: 80, PortState: "open"},
				{Host: "10.0.0.1", Port: 11434, PortState: "open"},
				{Host: "10.0.0.1", Port: 8000, PortState: "open"},
			},
			wantLen: 3,
			check: func(obs []fingerprint.PortObservation) error {
				if obs[0].Host != "10.0.0.1" || obs[0].Port != 8000 {
					return fmt.Errorf("expected first observation 10.0.0.1:8000, got %s:%d", obs[0].Host, obs[0].Port)
				}
				if obs[2].Host != "10.0.0.2" {
					return fmt.Errorf("expected last observation host 10.0.0.2, got %s", obs[2].Host)
				}
				return nil
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dedupePortObservations(tc.input)
			if len(got) != tc.wantLen {
				t.Fatalf("len = %d, want %d; got %v", len(got), tc.wantLen, got)
			}
			if tc.check != nil {
				if err := tc.check(got); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPrintDiscoveryTableShowsSuspectedAndAmbiguousServices(t *testing.T) {
	observations := []fingerprint.PortObservation{
		{Host: "10.0.0.1", Port: 8000, URL: "http://10.0.0.1:8000", PortState: "open", FingerprintStatus: fingerprint.MatchKindSuspected, Results: []fingerprint.Result{{Service: "langserve", MatchKind: fingerprint.MatchKindSuspected, Confidence: "low", Ambiguity: "generic_match_only"}}},
		{Host: "10.0.0.1", Port: 8501, URL: "http://10.0.0.1:8501", PortState: "open", FingerprintStatus: fingerprint.MatchKindAmbiguous, Results: []fingerprint.Result{{Service: "hf-tgi", MatchKind: fingerprint.MatchKindAmbiguous, Ambiguity: "no_strong_winner"}}},
	}

	var out strings.Builder
	printDiscoveryTable(&out, observations)
	rendered := out.String()
	for _, expected := range []string{"langserve", "hf-tgi", "generic match only", "no strong winner"} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected discovery table to contain %q, got %q", expected, rendered)
		}
	}
}

func TestPrintDiscoveryTableCompactsAmbiguousServices(t *testing.T) {
	observations := []fingerprint.PortObservation{
		{
			Host:              "172.16.50.10",
			Port:              6274,
			URL:               "http://172.16.50.10:6274",
			PortState:         "open",
			FingerprintStatus: fingerprint.MatchKindAmbiguous,
			ServerHeader:      "BaseHTTP/0.6 Python/3.12.3",
			Results: []fingerprint.Result{
				{Service: "mcp-inspector", MatchKind: fingerprint.MatchKindConfirmed, Confidence: "high", Ambiguity: "multiple_confirmed_matches"},
				{Service: "mcpjam-inspector", MatchKind: fingerprint.MatchKindConfirmed, Confidence: "high", Ambiguity: "multiple_confirmed_matches"},
			},
		},
	}

	var out strings.Builder
	printDiscoveryTable(&out, observations)
	rendered := out.String()
	if !strings.Contains(rendered, "mcp-inspector +1") {
		t.Fatalf("expected compact identity, got %q", rendered)
	}
	if strings.Contains(rendered, "mcp-inspector, mcpjam-inspector") {
		t.Fatalf("expected long identity list to be compacted, got %q", rendered)
	}
	if !strings.Contains(rendered, "multiple confirmed matches") {
		t.Fatalf("expected ambiguity reason to remain visible, got %q", rendered)
	}
	if !strings.Contains(rendered, "BaseHTTP/0.6 Python/3.12.3") {
		t.Fatalf("expected full server version to remain visible, got %q", rendered)
	}
}
