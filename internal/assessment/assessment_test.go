package assessment

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
)

func TestCanonicalServiceURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"scheme+host lowered, path preserved", "HTTP://Example.COM:8080/Path/", "http://example.com:8080/Path"},
		{"case-sensitive path kept", "http://host/API/v1", "http://host/API/v1"},
		{"case-sensitive query kept", "http://host/x?Token=AbC", "http://host/x?Token=AbC"},
		{"trailing slashes", "http://host:11434///", "http://host:11434"},
		{"whitespace", "  http://host  ", "http://host"},
		{"already canonical", "http://localhost:8080", "http://localhost:8080"},
		{"bare host:port lowered", "HOST:11434", "host:11434"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CanonicalServiceURL(tc.raw)
			if got != tc.want {
				t.Errorf("CanonicalServiceURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestUniqueSort(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"empty", nil, []string{}},
		{"already sorted unique", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"duplicates", []string{"b", "a", "b", "c", "a"}, []string{"a", "b", "c"}},
		{"whitespace trimmed", []string{" x ", "y", " x"}, []string{"x", "y"}},
		{"empty strings removed", []string{"", "a", " ", "b"}, []string{"a", "b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := UniqueSort(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("UniqueSort(%v) = %v, want %v", tc.input, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("UniqueSort(%v)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestUniqueSortPorts(t *testing.T) {
	tests := []struct {
		name  string
		input []int
		want  []int
	}{
		{"empty", nil, []int{}},
		{"already sorted", []int{80, 443, 8080}, []int{80, 443, 8080}},
		{"duplicates and unsorted", []int{8080, 80, 443, 80, 8080}, []int{80, 443, 8080}},
		{"single", []int{11434}, []int{11434}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := UniqueSortPorts(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("UniqueSortPorts(%v) = %v, want %v", tc.input, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("UniqueSortPorts(%v)[%d] = %d, want %d", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestDedupeFingerprints(t *testing.T) {
	results := []fingerprint.Result{
		{Service: "ollama", URL: "http://host:11434", Host: "host", Port: 11434, Specificity: 90},
		{Service: "ollama", URL: "http://host:11434", Host: "host", Port: 11434, Specificity: 80},
		{Service: "ray", URL: "http://host:8265", Host: "host", Port: 8265, Specificity: 70},
	}

	deduped := DedupeFingerprints(results)

	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped results, got %d", len(deduped))
	}

	for _, r := range deduped {
		if r.Service == "ollama" && r.Specificity != 90 {
			t.Errorf("expected ollama specificity 90, got %d", r.Specificity)
		}
	}
}

func TestDedupeAndSortFindings(t *testing.T) {
	findings := []report.Finding{
		{ID: "f1", Source: "fingerprint", Target: "http://host:11434", Title: "Ollama", Severity: "info"},
		{ID: "f1-dup", Source: "fingerprint", Target: "http://host:11434", Title: "Ollama", Severity: "info"},
		{ID: "f2", Source: "vulncheck", Target: "http://host:11434", Title: "Vuln", Severity: "high"},
	}

	deduped := DedupeAndSortFindings(findings)

	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped findings, got %d", len(deduped))
	}

	foundDedupe := false
	for _, f := range deduped {
		if count, ok := f.Metadata["dedupe_count"]; ok {
			if count != 1 {
				t.Errorf("expected dedupe_count=1, got %v", count)
			}
			foundDedupe = true
		}
	}
	if !foundDedupe {
		t.Error("expected at least one finding with dedupe_count metadata")
	}
}

func TestFindingStats(t *testing.T) {
	findings := []report.Finding{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
		{Severity: "info"},
		{Severity: "info"},
		{Severity: "info"},
	}

	stats := FindingStats(findings)

	if stats[report.SeverityCritical] != 1 {
		t.Errorf("critical = %d, want 1", stats[report.SeverityCritical])
	}
	if stats[report.SeverityHigh] != 2 {
		t.Errorf("high = %d, want 2", stats[report.SeverityHigh])
	}
	if stats[report.SeverityMedium] != 1 {
		t.Errorf("medium = %d, want 1", stats[report.SeverityMedium])
	}
	if stats[report.SeverityLow] != 1 {
		t.Errorf("low = %d, want 1", stats[report.SeverityLow])
	}
	if stats[report.SeverityInfo] != 3 {
		t.Errorf("info = %d, want 3", stats[report.SeverityInfo])
	}
}

func TestTargetGroupKey(t *testing.T) {
	tests := []struct {
		name   string
		source string
		target string
		want   string
	}{
		{"file discovery", report.SourceFileDiscovery, "/home/user/.env", "local-files"},
		{"network target", "fingerprint", "http://10.0.0.1:11434", "10.0.0.1"},
		{"with path", "vulncheck", "http://host:8080/api/tags", "host"},
		{"unparseable", "exploit", "not-a-url", "not-a-url"},
		{"empty host", "exploit", "file:///tmp/test", "file:///tmp/test"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TargetGroupKey(tc.source, tc.target)
			if got != tc.want {
				t.Errorf("TargetGroupKey(%q, %q) = %q, want %q", tc.source, tc.target, got, tc.want)
			}
		})
	}
}

func TestDedupePortObservations(t *testing.T) {
	observations := []fingerprint.PortObservation{
		{Host: "10.0.0.1", Port: 8080, URL: "http://10.0.0.1:8080"},
		{Host: "10.0.0.1", Port: 8080, URL: "http://10.0.0.1:8080", Results: []fingerprint.Result{{Service: "ollama"}}},
		{Host: "10.0.0.2", Port: 443, URL: "https://10.0.0.2:443"},
		{Host: "10.0.0.2", Port: 443, URL: "https://10.0.0.2:443", Results: []fingerprint.Result{{Service: "gradio"}}},
	}

	deduped := DedupePortObservations(observations)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped observations, got %d", len(deduped))
	}
	if deduped[0].Host != "10.0.0.1" || deduped[1].Host != "10.0.0.2" {
		t.Fatalf("unexpected host ordering: %v, %v", deduped[0].Host, deduped[1].Host)
	}
	if len(deduped[0].Results) != 1 {
		t.Errorf("expected host 10.0.0.1 to keep the observation with more results, got %d results", len(deduped[0].Results))
	}
	if len(deduped[1].Results) != 1 {
		t.Errorf("expected host 10.0.0.2 to keep the observation with more results, got %d results", len(deduped[1].Results))
	}
}

func TestDedupePortObservationsEmpty(t *testing.T) {
	deduped := DedupePortObservations(nil)
	if len(deduped) != 0 {
		t.Fatalf("expected 0 deduped observations, got %d", len(deduped))
	}
}

func TestPortObservationLess(t *testing.T) {
	tests := []struct {
		name string
		a, b fingerprint.PortObservation
		want bool
	}{
		{
			"non-timed-out preferred",
			fingerprint.PortObservation{TimedOut: false},
			fingerprint.PortObservation{TimedOut: true},
			true,
		},
		{
			"timed-out vs non-timed-out",
			fingerprint.PortObservation{TimedOut: true},
			fingerprint.PortObservation{TimedOut: false},
			false,
		},
		{
			"fewer results is less",
			fingerprint.PortObservation{Results: nil},
			fingerprint.PortObservation{Results: []fingerprint.Result{{Service: "a"}}},
			true,
		},
		{
			"fewer candidates is less",
			fingerprint.PortObservation{CandidateServices: nil},
			fingerprint.PortObservation{CandidateServices: []string{"ollama"}},
			true,
		},
		{
			"url fallback",
			fingerprint.PortObservation{URL: "http://a"},
			fingerprint.PortObservation{URL: "http://b"},
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := portObservationLess(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("portObservationLess() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFingerprintResultLess(t *testing.T) {
	tests := []struct {
		name string
		a, b fingerprint.Result
		want bool
	}{
		{"host comparison", fingerprint.Result{Host: "a"}, fingerprint.Result{Host: "b"}, true},
		{"same host, port comparison", fingerprint.Result{Host: "a", Port: 80}, fingerprint.Result{Host: "a", Port: 443}, true},
		{"same host+port, url comparison", fingerprint.Result{Host: "a", Port: 80, URL: "http://a"}, fingerprint.Result{Host: "a", Port: 80, URL: "http://b"}, true},
		{"same host+port+url, details comparison", fingerprint.Result{Host: "a", Port: 80, URL: "http://a", Details: "x"}, fingerprint.Result{Host: "a", Port: 80, URL: "http://a", Details: "y"}, true},
		{"equal", fingerprint.Result{Host: "a", Port: 80}, fingerprint.Result{Host: "a", Port: 80}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fingerprintResultLess(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("fingerprintResultLess() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDedupeFingerprintsEmpty(t *testing.T) {
	deduped := DedupeFingerprints(nil)
	if len(deduped) != 0 {
		t.Fatalf("expected 0 results, got %d", len(deduped))
	}
}

func TestDedupeFingerprintsSameSpecificity(t *testing.T) {
	results := []fingerprint.Result{
		{Service: "ollama", URL: "http://host:11434", Host: "host", Port: 11434, Specificity: 80, Details: "first"},
		{Service: "ollama", URL: "http://host:11434", Host: "host", Port: 11434, Specificity: 80, Details: "second"},
	}
	deduped := DedupeFingerprints(results)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduped result, got %d", len(deduped))
	}
}

func TestDedupeFingerprintsDifferentServices(t *testing.T) {
	results := []fingerprint.Result{
		{Service: "ollama", URL: "http://host:11434", Host: "host", Port: 11434, Specificity: 90},
		{Service: "vllm", URL: "http://host:11434", Host: "host", Port: 11434, Specificity: 80},
	}
	deduped := DedupeFingerprints(results)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 results for different services, got %d", len(deduped))
	}
}

func TestDedupeFingerprintsCaseNormalization(t *testing.T) {
	results := []fingerprint.Result{
		{Service: "ollama", URL: "HTTP://Host:11434/", Host: "host", Port: 11434, Specificity: 90},
		{Service: "ollama", URL: "http://host:11434", Host: "host", Port: 11434, Specificity: 80},
	}
	deduped := DedupeFingerprints(results)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 result after URL normalization, got %d", len(deduped))
	}
	if deduped[0].Specificity != 90 {
		t.Errorf("expected higher specificity to win, got %d", deduped[0].Specificity)
	}
}

func TestFindingDedupeKeyWithNilMetadata(t *testing.T) {
	f := report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://host:8080",
		Title:    "Test",
		Severity: report.SeverityHigh,
	}
	key := findingDedupeKey(f)
	if key == "" {
		t.Fatal("expected non-empty dedupe key")
	}
}

func TestFindingDedupeKeyWithMetadata(t *testing.T) {
	f := report.Finding{
		Source:   report.SourceVulnCheck,
		Target:   "http://host:8080",
		Title:    "Test",
		Severity: report.SeverityHigh,
		Metadata: map[string]interface{}{
			"landed": "execution-confirmed",
			"action": "exploit",
		},
	}
	key := findingDedupeKey(f)
	if key == "" {
		t.Fatal("expected non-empty dedupe key")
	}
	if !strings.Contains(key, "execution-confirmed") || !strings.Contains(key, "exploit") {
		t.Fatalf("expected landed and action in key, got %q", key)
	}
}

func TestDedupeAndSortFindingsNilMetadata(t *testing.T) {
	findings := []report.Finding{
		{Source: "a", Target: "http://h:1", Title: "T", Severity: "info"},
		{Source: "a", Target: "http://h:1", Title: "T", Severity: "info"},
		{Source: "a", Target: "http://h:1", Title: "T", Severity: "info"},
	}
	deduped := DedupeAndSortFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(deduped))
	}
	if deduped[0].Metadata["dedupe_count"] != 2 {
		t.Fatalf("expected dedupe_count=2, got %v", deduped[0].Metadata["dedupe_count"])
	}
}

func TestDedupeAndSortFindingsDifferentSources(t *testing.T) {
	findings := []report.Finding{
		{Source: "a", Target: "http://h:1", Title: "T", Severity: "info"},
		{Source: "b", Target: "http://h:1", Title: "T", Severity: "info"},
	}
	deduped := DedupeAndSortFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 findings (different sources), got %d", len(deduped))
	}
}

func TestDedupeAndSortFindingsWithEvidence(t *testing.T) {
	findings := []report.Finding{
		{Source: "a", Target: "http://h:1", Title: "T", Severity: "info", Evidence: "ev1"},
		{Source: "a", Target: "http://h:1", Title: "T", Severity: "info", Evidence: "ev2"},
	}
	deduped := DedupeAndSortFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 findings (different evidence), got %d", len(deduped))
	}
}

func TestMetadataString(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]interface{}
		want     string
	}{
		{"nil", nil, ""},
		{"empty", map[string]interface{}{}, ""},
		{"single", map[string]interface{}{"key": "val"}, "key=val"},
		{"sorted keys", map[string]interface{}{"b": 2, "a": 1}, "a=1,b=2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MetadataString(tc.metadata)
			if got != tc.want {
				t.Errorf("MetadataString(%v) = %q, want %q", tc.metadata, got, tc.want)
			}
		})
	}
}
