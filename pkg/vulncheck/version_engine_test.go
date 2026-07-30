package vulncheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAffectedVersionSuppressesNotAffectedFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"0.14.1"}`))
	}))
	defer srv.Close()

	engine := NewEngine(time.Second, 1)
	tmpl := versionAwareTemplate("< 0.14.1")
	findings, _, err := engine.ExecuteTemplateDetailed(tmpl, srv.URL)
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected not-affected version to suppress finding, got %#v", findings)
	}
}

func TestAffectedVersionAddsConfidenceMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"0.14.0"}`))
	}))
	defer srv.Close()

	engine := NewEngine(time.Second, 1)
	tmpl := versionAwareTemplate("< 0.14.1")
	findings, _, err := engine.ExecuteTemplateDetailed(tmpl, srv.URL)
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	if got := findings[0].Metadata["advisory_confidence"]; got != "affected-version-confirmed" {
		t.Fatalf("advisory_confidence = %v, want affected-version-confirmed", got)
	}
	if got := findings[0].Metadata["affected_version"]; got != "0.14.0" {
		t.Fatalf("affected_version = %v, want 0.14.0", got)
	}
}

// An unparseable target version (e.g. "1.2.3rc1") must NOT suppress the finding
// — that would conflate "couldn't determine the version" with "not affected".
// The finding is reported at service-exposed-risk and annotated.
func TestAffectedVersionUnparseableStillReports(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1.2.3rc1"}`))
	}))
	defer srv.Close()

	engine := NewEngine(time.Second, 1)
	tmpl := versionAwareTemplate("< 1.2.4")
	findings, metrics, err := engine.ExecuteTemplateDetailed(tmpl, srv.URL)
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the finding to be reported (not suppressed) on an unparseable version, got %#v", findings)
	}
	if got := findings[0].Metadata["advisory_confidence"]; got != "service-exposed-risk" {
		t.Fatalf("advisory_confidence = %v, want service-exposed-risk", got)
	}
	if got := findings[0].Metadata["version_unparseable"]; got != true {
		t.Fatalf("version_unparseable = %v, want true", got)
	}
	if got := findings[0].Metadata["affected_version"]; got != "1.2.3rc1" {
		t.Fatalf("affected_version = %v, want raw 1.2.3rc1", got)
	}
	if metrics.TemplateErrors != 0 {
		t.Fatalf("unparseable version should no longer count as a template error, got %d", metrics.TemplateErrors)
	}
}

func versionAwareTemplate(expr string) *Template {
	return &Template{
		ID: "cve-2025-unit",
		Info: TemplateInfo{
			Name:        "unit",
			Type:        TemplateTypeDetection,
			Severity:    "high",
			CVSS:        7.5,
			Author:      "unit",
			Description: "unit",
			References:  []string{"https://example.test/advisory"},
			Tags:        []string{"cve-2025"},
		},
		Checks: []Check{
			{
				Name:     "version",
				Method:   "GET",
				Path:     "/version",
				Matchers: []Matcher{{Type: MatchStatus, Value: "200"}},
				Extractors: []Extractor{{
					Type:  "regex",
					Name:  "server_version",
					Regex: `"version"\s*:\s*"([^"]+)"`,
				}},
				AffectedVersion: &AffectedVersion{Variable: "server_version", Range: expr},
				Finding: FindingTemplate{
					Title:       "affected",
					Description: "affected",
					Remediation: "upgrade",
				},
			},
		},
	}
}
