package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	exploitgradio "github.com/professor-moody/aipostex/pkg/exploit/gradio"
	"github.com/professor-moody/aipostex/pkg/exploit/jupyter"
	openaicompat "github.com/professor-moody/aipostex/pkg/exploit/openaicompat"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/vulncheck"
)

// ---------------------------------------------------------------------------
// openai_compat.go helpers
// ---------------------------------------------------------------------------

func TestPromptProbeSeverity(t *testing.T) {
	tests := []struct {
		probe string
		want  string
	}{
		{"instruction-override", report.SeverityHigh},
		{"jailbreak", report.SeverityHigh},
		{"refusal-bypass", report.SeverityHigh},
		{"role-confusion", report.SeverityMedium},
		{"delimiter-escape", report.SeverityMedium},
		{"unknown-probe", report.SeverityMedium},
		{"", report.SeverityMedium},
	}
	for _, tc := range tests {
		t.Run(tc.probe, func(t *testing.T) {
			if got := promptProbeSeverity(tc.probe); got != tc.want {
				t.Errorf("promptProbeSeverity(%q) = %q, want %q", tc.probe, got, tc.want)
			}
		})
	}
}

func TestPromptProbeFindingTitle(t *testing.T) {
	tests := []struct {
		probe string
		model string
		want  string
	}{
		{"instruction-override", "llama3", "Instruction override succeeded on llama3"},
		{"role-confusion", "gpt-4", "Role confusion prompt hijack succeeded on gpt-4"},
		{"delimiter-escape", "m", "Delimiter escape prompt injection succeeded on m"},
		{"jailbreak", "x", "Jailbreak prompt succeeded on x"},
		{"refusal-bypass", "y", "Refusal bypass succeeded on y"},
		{"unknown", "z", "Prompt probe succeeded on z"},
	}
	for _, tc := range tests {
		t.Run(tc.probe, func(t *testing.T) {
			if got := promptProbeFindingTitle(tc.probe, tc.model); got != tc.want {
				t.Errorf("promptProbeFindingTitle(%q, %q) = %q, want %q", tc.probe, tc.model, got, tc.want)
			}
		})
	}
}

func TestPromptProbeFindingDescription(t *testing.T) {
	tests := []struct {
		probe    string
		contains string
	}{
		{"instruction-override", "overridden by a direct user request"},
		{"role-confusion", "fake system-style instruction"},
		{"delimiter-escape", "Delimiter-style prompt boundaries"},
		{"jailbreak", "jailbreak prompt overrode a system-level output prohibition"},
		{"refusal-bypass", "translation-style prompt bypassed"},
		{"something-else", "bounded prompt injection probe"},
	}
	for _, tc := range tests {
		t.Run(tc.probe, func(t *testing.T) {
			got := promptProbeFindingDescription(tc.probe)
			if got == "" {
				t.Fatalf("promptProbeFindingDescription(%q) returned empty string", tc.probe)
			}
			if !containsSubstring(got, tc.contains) {
				t.Errorf("promptProbeFindingDescription(%q) = %q, expected to contain %q", tc.probe, got, tc.contains)
			}
		})
	}
}

func TestHighValueSlice(t *testing.T) {
	lowValue := openaicompat.ModelInfo{ID: "tiny-model", ValueScore: 10}
	got := highValueSlice(lowValue)
	if got != nil {
		t.Errorf("expected nil for low-value model, got %v", got)
	}

	highValue := openaicompat.ModelInfo{ID: "gpt-4o", ValueScore: 90}
	got = highValueSlice(highValue)
	if openaicompat.HighValueModel(highValue) && (len(got) != 1 || got[0] != "gpt-4o") {
		t.Errorf("expected [gpt-4o] for high-value model, got %v", got)
	}
}

func TestAcceptedAuthLabels(t *testing.T) {
	tests := []struct {
		name     string
		patterns []openaicompat.AuthSweepPattern
		want     int
	}{
		{
			"no accepted",
			[]openaicompat.AuthSweepPattern{
				{Label: "empty", AcceptedInventory: false, AcceptedInference: false},
			},
			0,
		},
		{
			"inventory only",
			[]openaicompat.AuthSweepPattern{
				{Label: "test-key", AcceptedInventory: true, AcceptedInference: false},
			},
			1,
		},
		{
			"inference only",
			[]openaicompat.AuthSweepPattern{
				{Label: "bearer", AcceptedInventory: false, AcceptedInference: true},
			},
			1,
		},
		{
			"deduped",
			[]openaicompat.AuthSweepPattern{
				{Label: "same", AcceptedInventory: true, AcceptedInference: false},
				{Label: "same", AcceptedInventory: false, AcceptedInference: true},
			},
			1,
		},
		{
			"empty patterns",
			nil,
			0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := acceptedAuthLabels(tc.patterns)
			if len(got) != tc.want {
				t.Errorf("acceptedAuthLabels() returned %d labels, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}

func TestCloneMap(t *testing.T) {
	original := map[string]interface{}{"a": 1, "b": "two"}
	cloned := cloneMap(original)
	if len(cloned) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(cloned))
	}
	cloned["c"] = 3
	if _, ok := original["c"]; ok {
		t.Fatal("mutation of clone affected original")
	}

	empty := cloneMap(nil)
	if empty == nil || len(empty) != 0 {
		t.Fatalf("cloneMap(nil) should return empty non-nil map, got %v", empty)
	}

	empty2 := cloneMap(map[string]interface{}{})
	if empty2 == nil || len(empty2) != 0 {
		t.Fatalf("cloneMap({}) should return empty non-nil map, got %v", empty2)
	}
}

// ---------------------------------------------------------------------------
// mcp.go helpers
// ---------------------------------------------------------------------------

func TestMapKeysBool(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]bool
		want   []string
	}{
		{"all true", map[string]bool{"fetch": true, "exec": true}, []string{"exec", "fetch"}},
		{"mixed", map[string]bool{"fetch": true, "exec": false, "file": true}, []string{"fetch", "file"}},
		{"all false", map[string]bool{"exec": false}, nil},
		{"empty", map[string]bool{}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapKeysBool(tc.values)
			if tc.want == nil {
				if len(got) != 0 {
					t.Errorf("expected empty, got %v", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len mismatch: got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// mcp_poison.go helpers
// ---------------------------------------------------------------------------

func TestBuildMCPToolArguments(t *testing.T) {
	args := buildMCPToolArguments("http://example.com")
	expectedKeys := []string{"url", "uri", "target", "endpoint", "path", "input", "prompt", "query"}
	for _, key := range expectedKeys {
		val, ok := args[key]
		if !ok {
			t.Errorf("missing key %q", key)
			continue
		}
		if val != "http://example.com" {
			t.Errorf("key %q = %v, want http://example.com", key, val)
		}
	}
}

func TestBuildMCPCloudArguments(t *testing.T) {
	tests := []struct {
		name       string
		target     mcpCloudTarget
		wantHeader bool
	}{
		{
			"gcp adds metadata-flavor",
			mcpCloudTarget{Alias: "gcp-metadata", URL: "http://metadata.google.internal/"},
			true,
		},
		{
			"azure adds metadata header",
			mcpCloudTarget{Alias: "azure-imds", URL: "http://169.254.169.254/metadata"},
			true,
		},
		{
			"aws has no extra headers",
			mcpCloudTarget{Alias: "aws-imds", URL: "http://169.254.169.254/latest"},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := buildMCPCloudArguments(tc.target)
			if args["url"] != tc.target.URL {
				t.Errorf("url = %v, want %v", args["url"], tc.target.URL)
			}
			_, hasHeaders := args["headers"]
			if hasHeaders != tc.wantHeader {
				t.Errorf("headers present = %v, want %v", hasHeaders, tc.wantHeader)
			}
		})
	}
}

func TestCommandVariants(t *testing.T) {
	variants := commandVariants("id")
	if len(variants) == 0 {
		t.Fatal("expected non-empty variants")
	}
	found := false
	for _, v := range variants {
		if v == "id" {
			found = true
		}
	}
	if !found {
		t.Error("expected bare command in variants")
	}
	// Variants are intentionally in insertion order (plain payload first), NOT sorted:
	// the plain command must be tried first so a low --attempts budget can't cut off the
	// only variant that runs cleanly on a direct-exec tool. See commandVariants.
	if variants[0] != "id" {
		t.Fatalf("expected plain command first, got %q (full: %v)", variants[0], variants)
	}
}

func TestTraversalCandidates(t *testing.T) {
	candidates := traversalCandidates("../../etc/passwd")
	if len(candidates) == 0 {
		t.Fatal("expected non-empty candidates")
	}
	found := false
	for _, c := range candidates {
		if c == "../../etc/passwd" {
			found = true
		}
	}
	if !found {
		t.Error("expected original path in candidates")
	}
}

func TestCloudProviderLabel(t *testing.T) {
	tests := []struct {
		alias string
		want  string
	}{
		{"aws-imds", "AWS"},
		{"gcp-metadata", "GCP"},
		{"azure-imds", "Azure"},
		{"something-else", "cloud metadata"},
		{"", "cloud metadata"},
	}
	for _, tc := range tests {
		t.Run(tc.alias, func(t *testing.T) {
			got := cloudProviderLabel(mcpCloudTarget{Alias: tc.alias})
			if got != tc.want {
				t.Errorf("cloudProviderLabel(%q) = %q, want %q", tc.alias, got, tc.want)
			}
		})
	}
}

func TestSortedMCPCloudAliases(t *testing.T) {
	aliases := sortedMCPCloudAliases()
	if len(aliases) != len(mcpCloudTargets) {
		t.Fatalf("expected %d aliases, got %d", len(mcpCloudTargets), len(aliases))
	}
	if !sort.StringsAreSorted(aliases) {
		t.Fatalf("aliases not sorted: %v", aliases)
	}
}

// ---------------------------------------------------------------------------
// mcp_schema.go helpers
// ---------------------------------------------------------------------------

func TestResolveChainCloudTargets(t *testing.T) {
	tests := []struct {
		cloud     string
		wantLen   int
		wantAlias string
	}{
		{"aws", 1, "aws-imds"},
		{"gcp", 1, "gcp-metadata"},
		{"azure", 1, "azure-imds"},
		{"all", 3, ""},
		{"ALL", 3, ""},
		{"", 3, ""},
	}
	for _, tc := range tests {
		t.Run(tc.cloud, func(t *testing.T) {
			targets := resolveChainCloudTargets(tc.cloud)
			if len(targets) != tc.wantLen {
				t.Fatalf("resolveChainCloudTargets(%q) returned %d targets, want %d", tc.cloud, len(targets), tc.wantLen)
			}
			if tc.wantAlias != "" && targets[0].Alias != tc.wantAlias {
				t.Errorf("first target alias = %q, want %q", targets[0].Alias, tc.wantAlias)
			}
		})
	}
}

func TestClassifyChainSeverity(t *testing.T) {
	tests := []struct {
		name     string
		findings []report.Finding
		want     string
	}{
		{"critical wins", []report.Finding{{Severity: report.SeverityCritical}, {Severity: report.SeverityHigh}}, report.SeverityCritical},
		{"high wins over medium", []report.Finding{{Severity: report.SeverityHigh}, {Severity: report.SeverityMedium}}, report.SeverityHigh},
		{"medium default", []report.Finding{{Severity: report.SeverityMedium}}, report.SeverityMedium},
		{"empty is medium", nil, report.SeverityMedium},
		{"info only is medium", []report.Finding{{Severity: report.SeverityInfo}}, report.SeverityMedium},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyChainSeverity(tc.findings); got != tc.want {
				t.Errorf("classifyChainSeverity() = %q, want %q", got, tc.want)
			}
		})
	}
}

type stringWriter struct{ data []byte }

func (w *stringWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

func (w *stringWriter) String() string { return string(w.data) }

// ---------------------------------------------------------------------------
// scan.go helpers
// ---------------------------------------------------------------------------

func TestExtractHostForScanNetwork(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"http://10.0.0.1:8080/api", "10.0.0.1"},
		{"https://example.com/path", "example.com"},
		{"http://[::1]:3000/", "::1"},
		{"not-a-url", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			if got := extractHostForScanNetwork(tc.target); got != tc.want {
				t.Errorf("extractHostForScanNetwork(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}
}

func TestTemplateTypeCounts(t *testing.T) {
	templates := []*vulncheck.Template{
		{Info: vulncheck.TemplateInfo{Tags: []string{"ollama"}}},
		{Info: vulncheck.TemplateInfo{Tags: []string{"exploit"}}},
		{Info: vulncheck.TemplateInfo{Tags: []string{"mcp"}}},
	}
	detection, exploit := templateTypeCounts(templates)
	total := detection + exploit
	if total != len(templates) {
		t.Errorf("detection(%d) + exploit(%d) != len(templates)(%d)", detection, exploit, total)
	}
}

// ---------------------------------------------------------------------------
// scan_network.go helpers
// ---------------------------------------------------------------------------

func TestSummarizeObservations(t *testing.T) {
	summary := &networkScanSummary{ServiceCounts: make(map[string]int)}
	observations := []fingerprint.PortObservation{
		{
			FingerprintStatus: fingerprint.MatchKindConfirmed,
			Results: []fingerprint.Result{
				{Service: "ollama", MatchKind: fingerprint.MatchKindConfirmed},
			},
		},
		{
			FingerprintStatus: fingerprint.MatchKindSuspected,
			Results: []fingerprint.Result{
				{Service: "jupyter", MatchKind: fingerprint.MatchKindSuspected},
			},
		},
		{
			FingerprintStatus: fingerprint.MatchKindBanner,
			Results: []fingerprint.Result{
				{Service: "nginx"},
			},
		},
		{
			FingerprintStatus: "unidentified",
			TimedOut:          true,
		},
	}

	summarizeObservations(observations, summary)

	if summary.ConfirmedIdentities != 1 {
		t.Errorf("confirmed = %d, want 1", summary.ConfirmedIdentities)
	}
	if summary.SuspectedIdentities != 1 {
		t.Errorf("suspected = %d, want 1", summary.SuspectedIdentities)
	}
	if summary.BannerIdentities != 1 {
		t.Errorf("banner = %d, want 1", summary.BannerIdentities)
	}
	if summary.UnclassifiedOpenPorts != 1 {
		t.Errorf("unclassified = %d, want 1", summary.UnclassifiedOpenPorts)
	}
	if summary.TimedOutPorts != 1 {
		t.Errorf("timed out = %d, want 1", summary.TimedOutPorts)
	}
	if summary.ServiceCounts["ollama"] != 1 {
		t.Errorf("ollama count = %d, want 1", summary.ServiceCounts["ollama"])
	}
}

func TestSummarizeObservationsNilSummary(t *testing.T) {
	summarizeObservations([]fingerprint.PortObservation{{FingerprintStatus: "confirmed"}}, nil)
}

func TestSelectableFingerprintResults(t *testing.T) {
	observations := []fingerprint.PortObservation{
		{
			FingerprintStatus: fingerprint.MatchKindConfirmed,
			Results: []fingerprint.Result{
				{Service: "ollama", MatchKind: fingerprint.MatchKindConfirmed, URL: "http://10.0.0.1:11434"},
			},
		},
		{
			FingerprintStatus: fingerprint.MatchKindAmbiguous,
			Results: []fingerprint.Result{
				{Service: "vllm", MatchKind: fingerprint.MatchKindConfirmed, URL: "http://10.0.0.1:8000"},
			},
		},
		{
			FingerprintStatus: fingerprint.MatchKindSuspected,
			Results: []fingerprint.Result{
				{Service: "jupyter", MatchKind: fingerprint.MatchKindSuspected, URL: "http://10.0.0.2:8888"},
			},
		},
		{
			FingerprintStatus: fingerprint.MatchKindBanner,
			Results: []fingerprint.Result{
				{Service: "nginx", MatchKind: fingerprint.MatchKindBanner, URL: "http://10.0.0.3:80"},
			},
		},
		{
			FingerprintStatus: fingerprint.MatchKindPortHeuristic,
			Results: []fingerprint.Result{
				{Service: "pgvector", MatchKind: fingerprint.MatchKindPortHeuristic, URL: "http://10.0.0.4:5432"},
			},
		},
	}

	selection := selectableFingerprintResults(observations)
	selected := selection.ResultsOnly()
	if len(selected) != 3 {
		t.Fatalf("expected 3 HTTP selectable results, got %d: %+v", len(selected), selected)
	}
	if selection.AmbiguousExpanded != 1 {
		t.Fatalf("expected 1 ambiguous observation expanded, got %d", selection.AmbiguousExpanded)
	}
	if selection.NonHTTPTemplateSkips != 1 {
		t.Fatalf("expected 1 non-HTTP template skip, got %d", selection.NonHTTPTemplateSkips)
	}
	services := make(map[string]bool)
	for _, r := range selected {
		services[r.Service] = true
	}
	if !services["ollama"] || !services["jupyter"] || !services["vllm"] {
		t.Errorf("expected ollama, jupyter and vllm in HTTP results, got %v", services)
	}
	allServices := make(map[string]bool)
	for _, r := range selection.AllResults() {
		allServices[r.Service] = true
	}
	if !allServices["pgvector"] {
		t.Errorf("expected pgvector preserved for non-HTTP enumeration, got %v", allServices)
	}
}

// ---------------------------------------------------------------------------
// scan_all.go helpers
// ---------------------------------------------------------------------------

func TestTopNPorts(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		wantErr bool
		minLen  int
	}{
		{"top 10", 10, false, 10},
		{"top 1", 1, false, 1},
		{"zero errors", 0, true, 0},
		{"negative errors", -1, true, 0},
		{"very large clamped", 100000, false, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ports, err := topNPorts(tc.n)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for n=%d", tc.n)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(ports) < tc.minLen {
				t.Errorf("expected at least %d ports, got %d", tc.minLen, len(ports))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// templates.go helpers
// ---------------------------------------------------------------------------

func TestTemplateCategoryForTags(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		want string
	}{
		{"mcp tag", []string{"mcp", "inspector"}, "mcp"},
		{"ollama tag", []string{"ollama", "llmjacking"}, "ollama"},
		{"vectordb chromadb", []string{"chromadb", "vectordb"}, "vectordb"},
		{"vectordb weaviate", []string{"weaviate"}, "vectordb"},
		{"vectordb qdrant", []string{"qdrant"}, "vectordb"},
		{"jupyter", []string{"jupyter"}, "jupyter"},
		{"openai-compat vllm", []string{"vllm"}, "openai-compat"},
		{"openai-compat litellm", []string{"litellm"}, "openai-compat"},
		{"openai-compat lmstudio", []string{"lmstudio"}, "openai-compat"},
		{"openai-compat localai", []string{"localai"}, "openai-compat"},
		{"openai-compat direct", []string{"openai-compatible"}, "openai-compat"},
		{"campaign adversary", []string{"adversary-emulation"}, "campaign"},
		{"campaign bizarre-bazaar", []string{"bizarre-bazaar-001"}, "campaign"},
		{"other", []string{"ray"}, "other"},
		{"empty tags", nil, "other"},
		{"case insensitive", []string{"MCP"}, "mcp"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := templateCategoryForTags(tc.tags); got != tc.want {
				t.Errorf("templateCategoryForTags(%v) = %q, want %q", tc.tags, got, tc.want)
			}
		})
	}
}

func TestFormatTemplateSeverity(t *testing.T) {
	tests := []struct {
		sev      string
		contains string
	}{
		{"critical", "crit"},
		{"high", "high"},
		{"medium", "med"},
		{"low", "low"},
		{"info", "info"},
		{"CRITICAL", "crit"},
		{"unknown", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.sev, func(t *testing.T) {
			got := formatTemplateSeverity(tc.sev)
			if got == "" {
				t.Fatalf("formatTemplateSeverity(%q) returned empty string", tc.sev)
			}
			if !containsSubstring(got, tc.contains) {
				t.Errorf("formatTemplateSeverity(%q) = %q, expected to contain %q", tc.sev, got, tc.contains)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// model_scan.go helpers
// ---------------------------------------------------------------------------

func TestValidateHash(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		wantType string
	}{
		{"bad format no colon", "abcdef", "hash-format-error"},
		{"bad format wrong algo", "md5:abcdef", "hash-format-error"},
		{"valid sha256 format", "sha256:0000000000000000000000000000000000000000000000000000000000000000", "hash-mismatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			risks := validateHash("/dev/null", tc.expected)
			if len(risks) == 0 {
				t.Fatal("expected at least one risk")
			}
			if risks[0].RiskType != tc.wantType {
				t.Errorf("risk type = %q, want %q", risks[0].RiskType, tc.wantType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// gradio.go helpers
// ---------------------------------------------------------------------------

func TestExtractGradioHandles(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{"empty", "", 0},
		{"event_id match", `{"event_id": "abc123"}`, 1},
		{"hash match", `"hash":"def456"`, 1},
		{"session_hash match", `session_hash: "xyz789"`, 1},
		{"multiple matches", `{"event_id":"a1","hash":"b2","queue_id":"c3"}`, 3},
		{"no matches", `{"status":"ok"}`, 0},
		{"duplicate values deduped", `{"event_id":"same","hash":"same"}`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractGradioHandles(tc.raw)
			if len(got) != tc.want {
				t.Errorf("extractGradioHandles(%q) returned %d handles, want %d: %v", tc.raw, len(got), tc.want, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// jupyter.go helpers
// ---------------------------------------------------------------------------

func TestKernelIDsFromKernels(t *testing.T) {
	tests := []struct {
		name    string
		kernels []jupyter.Kernel
		want    []string
	}{
		{"empty", nil, []string{}},
		{"single", []jupyter.Kernel{{ID: "k1", Name: "python3"}}, []string{"k1"}},
		{"multiple", []jupyter.Kernel{{ID: "k1"}, {ID: "k2"}, {ID: "k3"}}, []string{"k1", "k2", "k3"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := kernelIDsFromKernels(tc.kernels)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d IDs, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// litellm.go helpers
// ---------------------------------------------------------------------------

func TestModelIDs(t *testing.T) {
	models := []openaicompat.ModelInfo{
		{ID: "gpt-4"},
		{ID: "claude-3"},
		{ID: "llama3"},
	}
	got := modelIDs(models)
	if len(got) != 3 {
		t.Fatalf("expected 3 model IDs, got %d", len(got))
	}
	if got[0] != "gpt-4" || got[1] != "claude-3" || got[2] != "llama3" {
		t.Errorf("unexpected model IDs: %v", got)
	}
}

func TestModelIDsEmpty(t *testing.T) {
	got := modelIDs(nil)
	if len(got) != 0 {
		t.Errorf("expected 0 model IDs for nil, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// ray.go helpers
// ---------------------------------------------------------------------------

func TestExtractRayEnvVarFindings(t *testing.T) {
	tests := []struct {
		name       string
		runtimeEnv map[string]interface{}
		wantLen    int
	}{
		{"nil runtime env", nil, 0},
		{"no env_vars key", map[string]interface{}{"pip": []string{"requests"}}, 0},
		{"env_vars wrong type", map[string]interface{}{"env_vars": "not-a-map"}, 0},
		{"empty env_vars", map[string]interface{}{"env_vars": map[string]interface{}{}}, 0},
		{
			"one env var",
			map[string]interface{}{
				"env_vars": map[string]interface{}{
					"API_KEY": "sk-secret-123",
				},
			},
			1,
		},
		{
			"multiple env vars",
			map[string]interface{}{
				"env_vars": map[string]interface{}{
					"API_KEY":  "sk-secret-123",
					"DB_PASS":  "hunter2",
					"SAFE_VAR": "true",
				},
			},
			1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := extractRayEnvVarFindings("http://target", "job-1", tc.runtimeEnv)
			if len(findings) != tc.wantLen {
				t.Errorf("got %d findings, want %d", len(findings), tc.wantLen)
			}
			for _, f := range findings {
				if f.Severity != report.SeverityCritical {
					t.Errorf("expected critical severity, got %q", f.Severity)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// vectordb.go helpers
// ---------------------------------------------------------------------------

func TestRenderCount(t *testing.T) {
	tests := []struct {
		count int
		want  string
	}{
		{0, "0"},
		{42, "42"},
		{-1, "unknown"},
		{-100, "unknown"},
		{1000, "1000"},
	}
	for _, tc := range tests {
		if got := renderCount(tc.count); got != tc.want {
			t.Errorf("renderCount(%d) = %q, want %q", tc.count, got, tc.want)
		}
	}
}

func TestHeaderNames(t *testing.T) {
	headers := http.Header{
		"Authorization": []string{"Bearer xxx"},
		"Content-Type":  []string{"application/json"},
	}
	names := headerNames(headers)
	if len(names) != 2 {
		t.Fatalf("expected 2 header names, got %d", len(names))
	}
	sort.Strings(names)
	if names[0] != "Authorization" || names[1] != "Content-Type" {
		t.Errorf("unexpected names: %v", names)
	}

	empty := headerNames(nil)
	if len(empty) != 0 {
		t.Errorf("expected empty for nil headers, got %v", empty)
	}
}

func TestResolveVDBLimit(t *testing.T) {
	// resolveVDBLimit checks the Cobra flag state, but we can test the negative case
	prevLimit := vdbLimit
	defer func() { vdbLimit = prevLimit }()

	vdbLimit = -1
	err := resolveVDBLimit(vdbExtractCmd)
	if err == nil {
		t.Fatal("expected error for negative limit")
	}

	vdbLimit = 0
	err = resolveVDBLimit(vdbExtractCmd)
	if err != nil {
		t.Fatalf("unexpected error for zero limit: %v", err)
	}

	vdbLimit = 100
	err = resolveVDBLimit(vdbExtractCmd)
	if err != nil {
		t.Fatalf("unexpected error for positive limit: %v", err)
	}
}

// ---------------------------------------------------------------------------
// scan.go helpers — getGroupedWriter / getWriter
// ---------------------------------------------------------------------------

func TestGetGroupedWriterConsole(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "console"
		w, err := getGroupedWriter()
		if err != nil {
			t.Fatalf("getGroupedWriter(console) error: %v", err)
		}
		defer w.Close()
	})
}

func TestGetGroupedWriterJSON(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "test-grouped.json")
		w, err := getGroupedWriter()
		if err != nil {
			t.Fatalf("getGroupedWriter(json) error: %v", err)
		}
		defer w.Close()
	})
}

func TestGetGroupedWriterUnknownFormat(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "invalid-format-xyz"
		_, err := getGroupedWriter()
		if err == nil {
			t.Fatal("expected error for unknown format")
		}
	})
}

func TestGetWriterModeFormats(t *testing.T) {
	formats := []string{"json", "jsonl", "csv", "sarif", "markdown", "console"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			withTestConfig(t, func() {
				cfg.Format = format
				cfg.OutputFile = filepath.Join(t.TempDir(), "test."+format)
				w, err := getWriterMode(false)
				if err != nil {
					t.Fatalf("getWriterMode(%q) error: %v", format, err)
				}
				defer w.Close()
			})
		})
	}
}

func TestGetWriterModePDFRequiresOutputFile(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "pdf"
		cfg.OutputFile = ""
		_, err := getWriterMode(false)
		if err == nil {
			t.Fatal("expected error for PDF without output file")
		}
	})
}

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// scan.go — parseScanMode / validateScanMode / runScan error paths
// ---------------------------------------------------------------------------

func TestParseScanMode(t *testing.T) {
	tests := []struct {
		mode string
		want vulncheck.ScanMode
	}{
		{"detect", vulncheck.ModeDetect},
		{"full", vulncheck.ModeFull},
		{"FULL", vulncheck.ModeFull},
		{"  full  ", vulncheck.ModeFull},
		{"", vulncheck.ModeDetect},
		{"invalid", vulncheck.ModeDetect},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := parseScanMode(tc.mode); got != tc.want {
				t.Errorf("parseScanMode(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

func TestValidateScanMode(t *testing.T) {
	tests := []struct {
		mode    string
		wantErr bool
	}{
		{"detect", false},
		{"full", false},
		{"DETECT", false},
		{"FULL", false},
		{"  full  ", false},
		{"", true},
		{"invalid", true},
		{"partial", true},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			err := validateScanMode(tc.mode)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateScanMode(%q) error = %v, wantErr %v", tc.mode, err, tc.wantErr)
			}
		})
	}
}

func TestRunScanMissingTarget(t *testing.T) {
	prevTargets := scanTargets
	prevMode := scanMode
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
	}()

	scanTargets = nil
	scanMode = "detect"

	withTestConfig(t, func() {
		err := runScan(scanTargetsCmd, nil)
		if err == nil {
			t.Fatal("expected error for missing target")
		}
		if !strings.Contains(err.Error(), "target") {
			t.Errorf("expected error about missing target, got: %v", err)
		}
	})
}

func TestRunScanInvalidMode(t *testing.T) {
	prevTargets := scanTargets
	prevMode := scanMode
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
	}()

	scanTargets = []string{"http://127.0.0.1:11434"}
	scanMode = "badmode"

	withTestConfig(t, func() {
		err := runScan(scanTargetsCmd, nil)
		if err == nil {
			t.Fatal("expected error for invalid mode")
		}
		if !strings.Contains(err.Error(), "invalid --mode") {
			t.Errorf("expected invalid mode error, got: %v", err)
		}
	})
}

func TestWorkflowCanonicalService(t *testing.T) {
	tests := []struct {
		svc  string
		want string
	}{
		{"vllm", "openai-compatible"},
		{"localai", "openai-compatible"},
		{"lmstudio", "openai-compatible"},
		{"openai-compatible", "openai-compatible"},
		{"mcp-inspector", "mcp-inspector"},
		{"mcpjam-inspector", "mcpjam-inspector"},
		{"ollama", "ollama"},
		{"jupyter", "jupyter"},
	}
	for _, tc := range tests {
		t.Run(tc.svc, func(t *testing.T) {
			if got := workflowCanonicalService(tc.svc); got != tc.want {
				t.Errorf("workflowCanonicalService(%q) = %q, want %q", tc.svc, got, tc.want)
			}
		})
	}
}

func TestWorkflowTagInferenceRank(t *testing.T) {
	tests := []struct {
		tag  string
		want int
	}{
		{"litellm", 1000},
		{"openai-compatible", 100},
		{"llmjacking", 0},
		{"ollama", 500},
		{"unknown-tag", 500},
	}
	for _, tc := range tests {
		t.Run(tc.tag, func(t *testing.T) {
			if got := workflowTagInferenceRank(tc.tag); got != tc.want {
				t.Errorf("workflowTagInferenceRank(%q) = %d, want %d", tc.tag, got, tc.want)
			}
		})
	}
}

func TestGetWriterModeHTMLWithOutput(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "html"
		cfg.OutputFile = filepath.Join(t.TempDir(), "test.html")
		w, err := getWriterMode(false)
		if err != nil {
			t.Fatalf("getWriterMode(html) error: %v", err)
		}
		defer w.Close()
	})
}

func TestGetWriterModePDFWithOutput(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "pdf"
		cfg.OutputFile = filepath.Join(t.TempDir(), "test.pdf")
		w, err := getWriterMode(false)
		if err != nil {
			t.Fatalf("getWriterMode(pdf) error: %v", err)
		}
		defer w.Close()
	})
}

func TestGetWriterModeMdAlias(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "md"
		cfg.OutputFile = filepath.Join(t.TempDir(), "test.md")
		w, err := getWriterMode(false)
		if err != nil {
			t.Fatalf("getWriterMode(md) error: %v", err)
		}
		defer w.Close()
	})
}

func TestInferWorkflowPlansFromFindingsBasicTag(t *testing.T) {
	findings := []report.Finding{
		{
			Target: "http://10.0.0.5:11434",
			Tags:   []string{"ollama", "llmjacking"},
		},
	}
	plans := inferWorkflowPlansFromFindings(findings, []string{"http://10.0.0.5:11434"})
	if len(plans) == 0 {
		t.Fatal("expected at least one workflow plan")
	}
}

func TestInferWorkflowPlansFromFindingsEmptyInput(t *testing.T) {
	plans := inferWorkflowPlansFromFindings(nil, nil)
	if len(plans) != 0 {
		t.Fatalf("expected no plans for empty findings, got %d", len(plans))
	}
}

// ---------------------------------------------------------------------------
// scan_files.go — runScanFiles error paths
// ---------------------------------------------------------------------------

func TestRunScanFilesMissingPath(t *testing.T) {
	prevPaths := scanFilePaths
	defer func() { scanFilePaths = prevPaths }()

	scanFilePaths = nil

	withTestConfig(t, func() {
		err := runScanFiles(discoverFilesCmd, nil)
		if err == nil {
			t.Fatal("expected error for missing path")
		}
		if !strings.Contains(err.Error(), "path") {
			t.Errorf("expected error about missing path, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// report.go — runReport
// ---------------------------------------------------------------------------

func TestRunReportWithTempInput(t *testing.T) {
	collection := report.FindingCollection{
		EngagementID: "test-eng",
		Findings: []report.Finding{
			{ID: "f1", Source: report.SourceVulnCheck, Target: "http://10.0.0.5:11434",
				Title: "Test Vuln", Severity: report.SeverityHigh},
		},
	}
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.json")
	data, err := json.Marshal(collection)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(inputPath, data, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	prevFormat := reportRenderFormat
	defer func() { reportRenderFormat = prevFormat }()

	for _, format := range []string{"html", "markdown", "md", "json"} {
		t.Run(format, func(t *testing.T) {
			reportRenderFormat = format
			withTestConfig(t, func() {
				outputPath := filepath.Join(tmpDir, "report-"+format+".out")
				cfg.OutputFile = outputPath

				if err := runReport(nil, []string{inputPath}); err != nil {
					t.Fatalf("runReport(%s) error: %v", format, err)
				}
				stat, err := os.Stat(outputPath)
				if err != nil {
					t.Fatalf("output file not created: %v", err)
				}
				if stat.Size() == 0 {
					t.Fatal("output file is empty")
				}
			})
		})
	}
}

// ---------------------------------------------------------------------------
// scan.go — runScan deeper paths (port warnings, full scan loop)
// ---------------------------------------------------------------------------

func TestRunScanPortWarningHTTP(t *testing.T) {
	prevTargets := scanTargets
	prevMode := scanMode
	prevTags := scanTags
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
		scanTags = prevTags
	}()

	scanTargets = []string{"http://10.0.0.50"}
	scanMode = "detect"
	scanTags = []string{"nonexistent-tag-xyz"}

	var stderr stringWriter
	origWriter := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = origWriter }()

	withTestConfig(t, func() {
		cfg.Format = "console"
		err := runScan(scanTargetsCmd, nil)
		_ = err
		got := stderr.String()
		if !containsSubstring(got, "default HTTP port 80") {
			t.Errorf("expected HTTP port 80 warning, got: %q", got)
		}
	})
}

func TestRunScanPortWarningHTTPS(t *testing.T) {
	prevTargets := scanTargets
	prevMode := scanMode
	prevTags := scanTags
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
		scanTags = prevTags
	}()

	scanTargets = []string{"https://10.0.0.50"}
	scanMode = "detect"
	scanTags = []string{"nonexistent-tag-xyz"}

	var stderr stringWriter
	origWriter := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = origWriter }()

	withTestConfig(t, func() {
		cfg.Format = "console"
		err := runScan(scanTargetsCmd, nil)
		_ = err
		got := stderr.String()
		if !containsSubstring(got, "default HTTPS port 443") {
			t.Errorf("expected HTTPS port 443 warning, got: %q", got)
		}
	})
}

func TestRunScanPortWarningUnknownScheme(t *testing.T) {
	prevTargets := scanTargets
	prevMode := scanMode
	prevTags := scanTags
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
		scanTags = prevTags
	}()

	scanTargets = []string{"ftp://10.0.0.50"}
	scanMode = "detect"
	scanTags = []string{"nonexistent-tag-xyz"}

	var stderr stringWriter
	origWriter := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = origWriter }()

	withTestConfig(t, func() {
		cfg.Format = "console"
		err := runScan(scanTargetsCmd, nil)
		_ = err
		got := stderr.String()
		if !containsSubstring(got, "default port for scheme") {
			t.Errorf("expected unknown scheme port warning, got: %q", got)
		}
	})
}

func TestRunScanNoPortWarningExplicitPort(t *testing.T) {
	prevTargets := scanTargets
	prevMode := scanMode
	prevTags := scanTags
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
		scanTags = prevTags
	}()

	scanTargets = []string{"http://10.0.0.50:11434"}
	scanMode = "detect"
	scanTags = []string{"nonexistent-tag-xyz"}

	var stderr stringWriter
	origWriter := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = origWriter }()

	withTestConfig(t, func() {
		cfg.Format = "console"
		err := runScan(scanTargetsCmd, nil)
		_ = err
		got := stderr.String()
		if containsSubstring(got, "No port specified") {
			t.Errorf("should not warn about port for target with explicit port, got: %q", got)
		}
	})
}

func TestRunScanFullModeLabel(t *testing.T) {
	prevTargets := scanTargets
	prevMode := scanMode
	prevTags := scanTags
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
		scanTags = prevTags
	}()

	scanTargets = []string{"http://10.0.0.50:11434"}
	scanMode = "full"
	scanTags = []string{"nonexistent-tag-xyz"}

	var stderr stringWriter
	origWriter := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = origWriter }()

	withTestConfig(t, func() {
		cfg.Format = "console"
		err := runScan(scanTargetsCmd, nil)
		_ = err
		got := stderr.String()
		if !containsSubstring(got, "Full Assessment") {
			t.Errorf("expected Full Assessment mode banner, got: %q", got)
		}
	})
}

func TestRunScanVerboseLoaded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	prevTargets := scanTargets
	prevMode := scanMode
	prevTags := scanTags
	prevSev := scanSeverities
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
		scanTags = prevTags
		scanSeverities = prevSev
	}()

	scanTargets = []string{srv.URL}
	scanMode = "detect"
	scanTags = nil
	scanSeverities = nil

	var stderr stringWriter
	origWriter := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = origWriter }()

	withTestConfig(t, func() {
		cfg.Format = "console"
		cfg.Verbose = true
		cfg.Timeout = 2
		err := runScan(scanTargetsCmd, nil)
		_ = err
		got := stderr.String()
		if !containsSubstring(got, "Loaded") {
			t.Errorf("expected Loaded templates message in verbose, got: %q", got)
		}
	})
}

func TestRunScanNoTemplatesMatch(t *testing.T) {
	prevTargets := scanTargets
	prevMode := scanMode
	prevTags := scanTags
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
		scanTags = prevTags
	}()

	scanTargets = []string{"http://10.0.0.50:11434"}
	scanMode = "detect"
	scanTags = []string{"nonexistent-tag-xyz"}

	withTestConfig(t, func() {
		cfg.Format = "console"
		err := runScan(scanTargetsCmd, nil)
		if err == nil || !strings.Contains(err.Error(), "no templates match") {
			t.Errorf("expected no-templates-match error, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// scan_files.go — runScanFiles deeper paths
// ---------------------------------------------------------------------------

func TestRunScanFilesWithTempDir(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-config.env")
	if err := os.WriteFile(testFile, []byte("OPENAI_API_KEY=sk-test-key-1234567890"), 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	prevPaths := scanFilePaths
	prevRulesDir := scanRulesDir
	defer func() {
		scanFilePaths = prevPaths
		scanRulesDir = prevRulesDir
	}()

	scanFilePaths = []string{tmpDir}
	scanRulesDir = ""

	withTestConfig(t, func() {
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "scan-files.jsonl")

		err := runScanFiles(discoverFilesCmd, nil)
		if err != nil {
			t.Logf("runScanFiles returned (may be expected): %v", err)
		}
	})
}

func TestRunScanFilesVerbose(t *testing.T) {
	tmpDir := t.TempDir()
	prevPaths := scanFilePaths
	prevRulesDir := scanRulesDir
	defer func() {
		scanFilePaths = prevPaths
		scanRulesDir = prevRulesDir
	}()

	scanFilePaths = []string{tmpDir}
	scanRulesDir = ""

	var stderr stringWriter
	origWriter := stderrWriter
	stderrWriter = &stderr
	defer func() { stderrWriter = origWriter }()

	withTestConfig(t, func() {
		cfg.Format = "console"
		cfg.Verbose = true
		err := runScanFiles(discoverFilesCmd, nil)
		_ = err
		got := stderr.String()
		if !containsSubstring(got, "Loaded") {
			t.Errorf("expected verbose output about loaded rules, got: %q", got)
		}
	})
}

func TestRunReportUnknownFormat(t *testing.T) {
	collection := report.FindingCollection{
		EngagementID: "test-eng",
		Findings: []report.Finding{
			{ID: "f1", Source: report.SourceVulnCheck, Target: "http://10.0.0.5:11434",
				Title: "Test", Severity: report.SeverityInfo},
		},
	}
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.json")
	data, _ := json.Marshal(collection)
	_ = os.WriteFile(inputPath, data, 0o600)

	prevFormat := reportRenderFormat
	defer func() { reportRenderFormat = prevFormat }()
	reportRenderFormat = "bogus-format"

	withTestConfig(t, func() {
		err := runReport(nil, []string{inputPath})
		if err == nil {
			t.Fatal("expected error for unknown format")
		}
		if !strings.Contains(err.Error(), "unknown report format") {
			t.Errorf("expected unknown format error, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// capabilityFinding — all categories
// ---------------------------------------------------------------------------

func TestCapabilityFindingAllCategories(t *testing.T) {
	tests := []struct {
		category     string
		wantSeverity string
		wantContains string
	}{
		{"fetch", report.SeverityHigh, "fetch-capable"},
		{"file", report.SeverityHigh, "file-access"},
		{"exec", report.SeverityCritical, "exec-capable"},
		{"process", report.SeverityHigh, "process-launch"},
		{"inspector", report.SeverityMedium, "inspector-like"},
		{"unknown-category", report.SeverityInfo, "classified"},
		{"", report.SeverityInfo, "classified"},
	}
	for _, tc := range tests {
		t.Run(tc.category, func(t *testing.T) {
			title, description, severity := capabilityFinding("test-tool", tc.category)
			if severity != tc.wantSeverity {
				t.Errorf("capabilityFinding(%q) severity = %q, want %q", tc.category, severity, tc.wantSeverity)
			}
			if !strings.Contains(title, tc.wantContains) && !strings.Contains(title, "classified") {
				t.Errorf("capabilityFinding(%q) title = %q, expected to contain %q", tc.category, title, tc.wantContains)
			}
			if description == "" {
				t.Errorf("capabilityFinding(%q) returned empty description", tc.category)
			}
			if !strings.Contains(title, "test-tool") {
				t.Errorf("capabilityFinding(%q) title = %q, expected to contain tool name", tc.category, title)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// newMCPClient — validation paths
// ---------------------------------------------------------------------------

func TestNewMCPClientMissingTarget(t *testing.T) {
	prevTarget := mcpTarget
	prevTransport := mcpTransport
	defer func() {
		mcpTarget = prevTarget
		mcpTransport = prevTransport
	}()

	mcpTarget = ""
	mcpTransport = "http"

	_, err := newMCPClient()
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("expected missing target error, got %v", err)
	}
}

func TestNewMCPClientStdioMissingCommand(t *testing.T) {
	prevTarget := mcpTarget
	prevTransport := mcpTransport
	prevStdioCmd := mcpStdioCmd
	defer func() {
		mcpTarget = prevTarget
		mcpTransport = prevTransport
		mcpStdioCmd = prevStdioCmd
	}()

	mcpTransport = "stdio"
	mcpStdioCmd = ""

	_, err := newMCPClient()
	if err == nil || !strings.Contains(err.Error(), "stdio-command") {
		t.Fatalf("expected missing stdio-command error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// classifyModel — additional edge cases
// ---------------------------------------------------------------------------

func TestClassifyModelEdgeCases(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{"bedrock/claude-v3", "aws"},
		{"sagemaker/llama-2", "aws"},
		{"vertex_ai/gemini-pro", "google"},
		{"google/gemini-1.5", "google"},
		{"claude-3-sonnet", "anthropic"},
		{"o1-mini", "openai"},
		{"o3-large", "openai"},
		{"o4-preview", "openai"},
		{"gemini-pro-vision", "google"},
		{"llama-3-70b", "ollama/local"},
		{"mistral-7b", "ollama/local"},
		{"mixtral-8x7b", "ollama/local"},
		{"codellama-34b", "ollama/local"},
		{"ollama/phi3", "ollama/local"},
		{"command-r-plus", "cohere"},
		{"cohere/command-light", "cohere"},
		{"huggingface/bert-base", "huggingface"},
		{"totally-custom-model", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			if got := classifyModel(tc.model); got != tc.want {
				t.Errorf("classifyModel(%q) = %q, want %q", tc.model, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// newLiteLLMClient — validation paths
// ---------------------------------------------------------------------------

func TestNewLiteLLMClientMissingTarget(t *testing.T) {
	prevTarget := litellmTarget
	defer func() { litellmTarget = prevTarget }()

	litellmTarget = ""

	_, err := newLiteLLMClient()
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("expected missing target error, got %v", err)
	}
}

func TestNewLiteLLMClientWithAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	prevTarget := litellmTarget
	prevAPIKey := litellmAPIKey
	prevHeaders := litellmHeaders
	defer func() {
		litellmTarget = prevTarget
		litellmAPIKey = prevAPIKey
		litellmHeaders = prevHeaders
	}()

	withTestConfig(t, func() {
		litellmTarget = srv.URL
		litellmAPIKey = "sk-test-key"
		litellmHeaders = nil

		client, err := newLiteLLMClient()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}
	})
}

// ---------------------------------------------------------------------------
// gradio — missing flag validation
// ---------------------------------------------------------------------------

func TestRunGradioQueueProbeMissingSelectorAndInputJSON(t *testing.T) {
	prevTarget := gradioTarget
	prevAPIName := gradioAPIName
	prevFnIndex := gradioFnIndex
	prevInputJSON := gradioInputJSON
	defer func() {
		gradioTarget = prevTarget
		gradioAPIName = prevAPIName
		gradioFnIndex = prevFnIndex
		gradioInputJSON = prevInputJSON
	}()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		gradioTarget = "http://127.0.0.1:7860"

		gradioAPIName = ""
		gradioFnIndex = -1
		gradioInputJSON = `["hello"]`
		err := runGradioQueueProbe(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--api-name or --fn-index") {
			t.Fatalf("expected selector validation error, got %v", err)
		}

		gradioAPIName = "predict"
		gradioFnIndex = -1
		gradioInputJSON = ""
		err = runGradioQueueProbe(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--input-json") {
			t.Fatalf("expected input-json validation error, got %v", err)
		}
	})
}

func TestRunGradioDownloadFileMissingFile(t *testing.T) {
	prevFile := gradioFile
	defer func() { gradioFile = prevFile }()

	gradioFile = ""
	err := runGradioDownloadFile(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "file") {
		t.Fatalf("expected missing file error, got %v", err)
	}
}

func TestRunGradioFileChainMissingFile(t *testing.T) {
	prevFile := gradioFile
	defer func() { gradioFile = prevFile }()

	gradioFile = ""
	err := runGradioFileChain(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "file") {
		t.Fatalf("expected missing file error, got %v", err)
	}
}

func TestRunGradioServeProbeRequiresForceExploit(t *testing.T) {
	prevFile := gradioFile
	defer func() { gradioFile = prevFile }()

	withTestConfig(t, func() {
		cfg.ForceExploit = false
		gradioFile = "/tmp/gradio/file.txt"

		err := runGradioServeProbe(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

func TestRunGradioServeProbeMissingFile(t *testing.T) {
	prevFile := gradioFile
	defer func() { gradioFile = prevFile }()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		gradioFile = ""

		err := runGradioServeProbe(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "file") {
			t.Fatalf("expected missing file error, got %v", err)
		}
	})
}

func TestValidateGradioSelectorBothSet(t *testing.T) {
	prevAPIName := gradioAPIName
	prevFnIndex := gradioFnIndex
	defer func() {
		gradioAPIName = prevAPIName
		gradioFnIndex = prevFnIndex
	}()

	gradioAPIName = "predict"
	gradioFnIndex = 0
	err := validateGradioSelector("predict")
	if err == nil || !strings.Contains(err.Error(), "--api-name or --fn-index") {
		t.Fatalf("expected mutual exclusion error, got %v", err)
	}
}

func TestValidateGradioSelectorNeitherSet(t *testing.T) {
	prevAPIName := gradioAPIName
	prevFnIndex := gradioFnIndex
	defer func() {
		gradioAPIName = prevAPIName
		gradioFnIndex = prevFnIndex
	}()

	gradioAPIName = ""
	gradioFnIndex = -1
	err := validateGradioSelector("predict")
	if err == nil || !strings.Contains(err.Error(), "--api-name or --fn-index") {
		t.Fatalf("expected missing selector error, got %v", err)
	}
}

func TestValidateGradioSelectorValidAPIName(t *testing.T) {
	prevAPIName := gradioAPIName
	prevFnIndex := gradioFnIndex
	defer func() {
		gradioAPIName = prevAPIName
		gradioFnIndex = prevFnIndex
	}()

	gradioAPIName = "predict"
	gradioFnIndex = -1
	err := validateGradioSelector("predict")
	if err != nil {
		t.Fatalf("expected no error for valid api-name, got %v", err)
	}
}

func TestValidateGradioSelectorValidFnIndex(t *testing.T) {
	prevAPIName := gradioAPIName
	prevFnIndex := gradioFnIndex
	defer func() {
		gradioAPIName = prevAPIName
		gradioFnIndex = prevFnIndex
	}()

	gradioAPIName = ""
	gradioFnIndex = 0
	err := validateGradioSelector("predict")
	if err != nil {
		t.Fatalf("expected no error for valid fn-index, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// torchserve — missing flag validation
// ---------------------------------------------------------------------------

func TestRunTSPredictMissingModel(t *testing.T) {
	prevModel := tsModel
	defer func() { tsModel = prevModel }()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		tsModel = ""

		err := runTSPredict(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "model") {
			t.Fatalf("expected missing model error, got %v", err)
		}
	})
}

func TestRunTSPredictMissingPayload(t *testing.T) {
	prevModel := tsModel
	prevPayload := tsPayload
	defer func() {
		tsModel = prevModel
		tsPayload = prevPayload
	}()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		tsModel = "resnet"
		tsPayload = ""

		err := runTSPredict(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "payload") {
			t.Fatalf("expected missing payload error, got %v", err)
		}
	})
}

func TestRunTSPredictRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		cfg.ForceExploit = false
		err := runTSPredict(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

func TestRunTSRegisterMissingModelURL(t *testing.T) {
	prevModelURL := tsModelURL
	prevModel := tsModel
	prevPayload := tsPayload
	defer func() {
		tsModelURL = prevModelURL
		tsModel = prevModel
		tsPayload = prevPayload
	}()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		tsModelURL = ""
		tsModel = ""
		tsPayload = ""

		err := runTSRegister(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "model-url") {
			t.Fatalf("expected missing model-url error, got %v", err)
		}
	})
}

func TestRunTSScaleMissingModel(t *testing.T) {
	prevModel := tsModel
	defer func() { tsModel = prevModel }()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		tsModel = ""

		err := runTSScale(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "model") {
			t.Fatalf("expected missing model error, got %v", err)
		}
	})
}

func TestRunTSUnregisterMissingModel(t *testing.T) {
	prevModel := tsModel
	defer func() { tsModel = prevModel }()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		tsModel = ""

		err := runTSUnregister(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "model") {
			t.Fatalf("expected missing model error, got %v", err)
		}
	})
}

func TestNewTSClientMissingTarget(t *testing.T) {
	prevTarget := tsTarget
	defer func() { tsTarget = prevTarget }()

	tsTarget = ""
	_, _, err := newTSClient()
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("expected missing target error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// runScan — integration test with httptest server
// ---------------------------------------------------------------------------

func TestRunScanIntegrationWithServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	prevTargets := scanTargets
	prevMode := scanMode
	prevTags := scanTags
	prevSev := scanSeverities
	defer func() {
		scanTargets = prevTargets
		scanMode = prevMode
		scanTags = prevTags
		scanSeverities = prevSev
	}()

	scanTargets = []string{srv.URL}
	scanMode = "detect"
	scanTags = nil
	scanSeverities = nil

	withTestConfig(t, func() {
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "scan-integration.json")
		cfg.Timeout = 5

		var stderr stringWriter
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		err := runScan(scanTargetsCmd, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				if _, ok := err.(*exitcode.PartialError); !ok {
					if _, ok := err.(*exitcode.FindingsPartialError); !ok {
						t.Logf("runScan returned: %T: %v", err, err)
					}
				}
			}
		}

		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatalf("expected output file: %v", readErr)
		}
		if len(raw) == 0 {
			t.Fatal("expected non-empty output file")
		}
	})
}

// ---------------------------------------------------------------------------
// gradioEndpointLabels
// ---------------------------------------------------------------------------

func TestGradioEndpointLabelsVariants(t *testing.T) {
	tests := []struct {
		name     string
		endpoint exploitgradio.Endpoint
		wantLen  int
	}{
		{
			"all features",
			exploitgradio.Endpoint{Queue: true, FileInput: true, FileOutput: true, PreferredPath: "/predict"},
			4,
		},
		{
			"no features",
			exploitgradio.Endpoint{},
			0,
		},
		{
			"queue only",
			exploitgradio.Endpoint{Queue: true},
			1,
		},
		{
			"file input/output",
			exploitgradio.Endpoint{FileInput: true, FileOutput: true},
			2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			labels := gradioEndpointLabels(tc.endpoint)
			if len(labels) != tc.wantLen {
				t.Errorf("gradioEndpointLabels() returned %d labels, want %d: %v", len(labels), tc.wantLen, labels)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// joinPreview — additional edge cases
// ---------------------------------------------------------------------------

func TestJoinPreviewNegativeMax(t *testing.T) {
	got := joinPreview([]string{"a", "b", "c"}, -1)
	if got != "a, b, c" {
		t.Errorf("joinPreview with negative max = %q, want full join", got)
	}
}

func TestJoinPreviewSingleElement(t *testing.T) {
	got := joinPreview([]string{"only"}, 1)
	if got != "only" {
		t.Errorf("joinPreview single element = %q, want 'only'", got)
	}
}

// ---------------------------------------------------------------------------
// classifyProviders
// ---------------------------------------------------------------------------

func TestClassifyProvidersDeduplication(t *testing.T) {
	models := []string{"gpt-4o", "gpt-3.5-turbo", "anthropic/claude-3", "gpt-4"}
	providers := classifyProviders(models)
	openaiCount := 0
	for _, p := range providers {
		if p == "openai" {
			openaiCount++
		}
	}
	if openaiCount != 1 {
		t.Errorf("expected openai to appear once, got %d in %v", openaiCount, providers)
	}
}

// ---------------------------------------------------------------------------
// serviceToTags / tagsToService round-trip
// ---------------------------------------------------------------------------

func TestServiceToTagsKnownServices(t *testing.T) {
	services := []string{"ollama", "chromadb", "triton", "jupyter", "mlflow", "gradio", "ray", "bentoml"}
	for _, svc := range services {
		tags := serviceToTags(svc)
		if len(tags) == 0 {
			t.Errorf("serviceToTags(%q) returned empty", svc)
		}
	}
}

func TestServiceToTagsUnknownService(t *testing.T) {
	tags := serviceToTags("nonexistent-service-xyz")
	if len(tags) != 1 || tags[0] != "nonexistent-service-xyz" {
		t.Errorf("expected passthrough for unknown service, got %v", tags)
	}
}

// The kube-apiserver fingerprint must map to the k8s template tags so the
// k8s-* templates are selected for a discovered API server.
func TestServiceToTagsKubeAPIServer(t *testing.T) {
	tags := serviceToTags("kube-apiserver")
	want := map[string]bool{"k8s": false, "kubernetes": false}
	for _, tag := range tags {
		if _, ok := want[tag]; ok {
			want[tag] = true
		}
	}
	for tag, found := range want {
		if !found {
			t.Errorf("serviceToTags(kube-apiserver) missing %q tag (got %v)", tag, tags)
		}
	}
}

func TestTagsToServiceKnownTags(t *testing.T) {
	knownTags := []string{"ollama", "jupyter", "mlflow", "gradio", "ray", "chromadb"}
	for _, tag := range knownTags {
		svc := tagsToService(tag)
		if svc == "" {
			t.Errorf("tagsToService(%q) returned empty", tag)
		}
	}
}

func TestTagsToServiceUnknownTag(t *testing.T) {
	svc := tagsToService("nonexistent-tag-xyz")
	if svc != "" {
		t.Errorf("expected empty for unknown tag, got %q", svc)
	}
}

// ---------------------------------------------------------------------------
// TorchServe — runTSModels with specific model detail
// ---------------------------------------------------------------------------

func TestRunTSModelsDetailAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/models/resnet", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"modelName":  "resnet",
				"modelUrl":   "resnet.mar",
				"runtime":    "python",
				"handler":    "image_classifier",
				"minWorkers": 1,
				"maxWorkers": 4,
				"batchSize":  1,
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tsTarget
	prevModel := tsModel
	defer func() {
		tsTarget = prev
		tsModel = prevModel
	}()

	withTestConfig(t, func() {
		tsTarget = srv.URL
		tsModel = "resnet"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-model-detail.json")

		err := runTSModels(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError or nil, got %T: %v", err, err)
			}
		}
		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !strings.Contains(string(raw), "resnet") {
			t.Fatalf("expected model name in output, got %s", string(raw))
		}
	})
}

// ---------------------------------------------------------------------------
// LiteLLM — enum with no LiteLLM-specific responses
// ---------------------------------------------------------------------------

func TestRunLiteLLMEnumNoLiteLLM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := litellmTarget
	defer func() { litellmTarget = prev }()

	withTestConfig(t, func() {
		litellmTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "litellm-no-detect.json")

		err := runLiteLLMEnum(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError or nil, got %T: %v", err, err)
			}
		}
		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !strings.Contains(string(raw), "not detected") {
			t.Logf("output: %s", string(raw))
		}
	})
}

// ---------------------------------------------------------------------------
// LiteLLM — budget probe with no data
// ---------------------------------------------------------------------------

func TestRunLiteLLMBudgetProbeNoBudgetData(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/model/info", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"model_name": "gpt-4"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := litellmTarget
	defer func() { litellmTarget = prev }()

	withTestConfig(t, func() {
		litellmTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "litellm-no-budget.json")

		err := runLiteLLMBudgetProbe(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError or nil, got %T: %v", err, err)
			}
		}
		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !strings.Contains(string(raw), "budget") {
			t.Logf("output: %s", string(raw))
		}
	})
}

func TestSubcommandRequired(t *testing.T) {
	fn := subcommandRequired("aipostex scan", "aipostex scan targets http://127.0.0.1:11434")
	err := fn(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("expected subcommand error, got %v", err)
	}
}
