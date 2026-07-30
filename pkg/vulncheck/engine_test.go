package vulncheck

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/internal/httptestutil"
)

func TestExecuteTemplateRunsDetectCheckExtractionAndInterpolation(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Request:    req,
			}

			switch req.URL.Path {
			case "/":
				resp.Body = io.NopCloser(strings.NewReader("service online"))
			case "/api/check":
				resp.Header.Set("Content-Type", "application/json")
				resp.Body = io.NopCloser(strings.NewReader(`{"result":{"id":"alpha-1","items":["one","two"]}}`))
			default:
				resp.StatusCode = http.StatusNotFound
				resp.Body = io.NopCloser(strings.NewReader("not found"))
			}

			return resp, nil
		}),
		Timeout: 2 * time.Second,
	}

	tmpl := &Template{
		ID: "test-template",
		Info: TemplateInfo{
			Name:        "Test Template",
			Severity:    "high",
			CVSS:        8.1,
			Author:      "test",
			Description: "test description",
			Tags:        []string{"mcp", "demo"},
			References:  []string{"https://example.com/advisory"},
		},
		Detect: []HTTPStep{
			{
				Method: "GET",
				Path:   "/",
				Matchers: []Matcher{
					{Type: MatchBodyContains, Value: "service online"},
				},
			},
		},
		Checks: []Check{
			{
				Name:   "Enumerate resources",
				Method: "GET",
				Path:   "/api/check",
				Matchers: []Matcher{
					{Type: MatchStatus, Value: "200"},
					{Type: MatchJSONPath, Key: "result.id", Value: "alpha-1"},
				},
				Extractors: []Extractor{
					{Type: "json", Name: "resource_id", Path: "result.id"},
				},
				Severity: "critical",
				Finding: FindingTemplate{
					Title:       "Exposed resource {{resource_id}}",
					Description: "Resource {{resource_id}} was returned to an unauthenticated request",
					Evidence:    "{{resource_id}}",
				},
			},
		},
	}

	findings, err := engine.ExecuteTemplate(tmpl, "http://target.local")
	if err != nil {
		t.Fatalf("ExecuteTemplate returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Title != "Exposed resource alpha-1" {
		t.Fatalf("unexpected title: %q", finding.Title)
	}
	if finding.Description != "Resource alpha-1 was returned to an unauthenticated request" {
		t.Fatalf("unexpected description: %q", finding.Description)
	}
	if finding.Severity != "critical" {
		t.Fatalf("unexpected severity: %q", finding.Severity)
	}
	if finding.TemplateID != "test-template" {
		t.Fatalf("unexpected template id: %q", finding.TemplateID)
	}
	if finding.Evidence != "alpha-1" {
		t.Fatalf("unexpected evidence: %q", finding.Evidence)
	}
	extracted, ok := finding.Metadata["extracted"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected extracted metadata, got %#v", finding.Metadata["extracted"])
	}
	if extracted["resource_id"] != "alpha-1" {
		t.Fatalf("unexpected extracted resource_id metadata: %#v", extracted)
	}
	if finding.Metadata["resource_id"] != "alpha-1" {
		t.Fatalf("expected flattened extracted resource_id metadata, got %#v", finding.Metadata["resource_id"])
	}
	if len(finding.Tags) != 2 || finding.Tags[0] != "mcp" {
		t.Fatalf("unexpected tags: %#v", finding.Tags)
	}
	if len(finding.References) != 1 || finding.References[0] != "https://example.com/advisory" {
		t.Fatalf("unexpected references: %#v", finding.References)
	}
}

func TestExecuteTemplateUsesDetectExtractorsInChecks(t *testing.T) {
	var showBody string
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Request:    req,
			}

			switch req.URL.Path {
			case "/api/tags":
				resp.Header.Set("Content-Type", "application/json")
				resp.Body = io.NopCloser(strings.NewReader(`{"models":[{"name":"llama3:latest"}]}`))
			case "/api/show":
				body, _ := io.ReadAll(req.Body)
				showBody = string(body)
				resp.Header.Set("Content-Type", "application/json")
				resp.Body = io.NopCloser(strings.NewReader(`{"modelfile":"SYSTEM stay concise","details":{"family":"llama","parameter_size":"8B"}}`))
			default:
				resp.StatusCode = http.StatusNotFound
				resp.Body = io.NopCloser(strings.NewReader("not found"))
			}

			return resp, nil
		}),
		Timeout: 2 * time.Second,
	}

	tmpl := &Template{
		ID:   "detect-vars",
		Info: TemplateInfo{Name: "Detect Vars", Severity: "high", Author: "test", Description: "test"},
		Detect: []HTTPStep{{
			Method: "GET",
			Path:   "/api/tags",
			Matchers: []Matcher{
				{Type: MatchStatus, Value: "200"},
			},
			Extractors: []Extractor{
				{Type: "json", Name: "first_model", Path: "models.0.name"},
			},
		}},
		Checks: []Check{{
			Name:   "show model",
			Method: "POST",
			Path:   "/api/show",
			Body:   `{"model":"{{first_model}}"}`,
			Matchers: []Matcher{
				{Type: MatchStatus, Value: "200"},
				{Type: MatchBodyContains, Value: "modelfile"},
			},
			Extractors: []Extractor{
				{Type: "json", Name: "modelfile_content", Path: "modelfile"},
			},
			Finding: FindingTemplate{
				Title:       "Model {{first_model}} exposed",
				Description: "Retrieved {{modelfile_content}}",
			},
		}},
	}

	findings, _, err := engine.ExecuteTemplateDetailed(tmpl, "http://target.local")
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(showBody, `"model":"llama3:latest"`) {
		t.Fatalf("expected detect extractor to populate check body, got %q", showBody)
	}
	if !strings.Contains(findings[0].Title, "llama3:latest") {
		t.Fatalf("expected detect variable in finding title, got %q", findings[0].Title)
	}
}

func TestExecuteTemplateSeedsTemplateVars(t *testing.T) {
	var capturedPath string
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			capturedPath = req.URL.Path
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
				Request:    req,
			}, nil
		}),
		Timeout: 2 * time.Second,
	}

	tmpl := &Template{
		ID:   "template-vars",
		Info: TemplateInfo{Name: "Template Vars", Severity: "medium", Author: "test", Description: "test"},
		Vars: map[string]string{"callback_path": "callbacks"},
		Checks: []Check{{
			Name:     "default var path",
			Method:   "GET",
			Path:     "/{{callback_path}}",
			Matchers: []Matcher{{Type: MatchStatus, Value: "200"}},
			Finding:  FindingTemplate{Title: "matched", Description: "matched"},
		}},
	}

	findings, _, err := engine.ExecuteTemplateDetailed(tmpl, "http://target.local")
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if capturedPath != "/callbacks" {
		t.Fatalf("expected template var interpolation, got %q", capturedPath)
	}
}

func TestFilteredTemplatesAppliesTagAndSeverityFilters(t *testing.T) {
	engine := NewEngine(time.Second, 1)
	engine.Templates = []*Template{
		{
			ID: "mcp-high",
			Info: TemplateInfo{
				Name:     "MCP High",
				Severity: "high",
				Author:   "test",
				Tags:     []string{"mcp"},
			},
			Checks: []Check{{Name: "check", Method: "GET", Path: "/"}},
		},
		{
			ID: "ollama-medium",
			Info: TemplateInfo{
				Name:     "Ollama Medium",
				Severity: "medium",
				Author:   "test",
				Tags:     []string{"ollama"},
			},
			Checks: []Check{{Name: "check", Method: "GET", Path: "/"}},
		},
	}

	filtered := engine.FilteredTemplates([]string{"mcp"}, []string{"high"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered template, got %d", len(filtered))
	}
	if filtered[0].ID != "mcp-high" {
		t.Fatalf("unexpected template selected: %q", filtered[0].ID)
	}
}

func TestFilteredTemplatesIncludesCheckLevelSeverityOverrides(t *testing.T) {
	engine := NewEngine(time.Second, 1)
	engine.Templates = []*Template{
		{
			ID: "campaign-high-with-critical-checks",
			Info: TemplateInfo{
				Name:     "Campaign Template",
				Severity: "high",
				Author:   "test",
				Tags:     []string{"campaign"},
			},
			Checks: []Check{
				{Name: "info-check", Method: "GET", Path: "/", Severity: "high"},
				{Name: "critical-check", Method: "POST", Path: "/rce", Severity: "critical"},
			},
		},
		{
			ID: "plain-medium",
			Info: TemplateInfo{
				Name:     "Plain Medium",
				Severity: "medium",
				Author:   "test",
				Tags:     []string{"other"},
			},
			Checks: []Check{{Name: "check", Method: "GET", Path: "/"}},
		},
	}

	filtered := engine.FilteredTemplates(nil, []string{"critical"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 template with critical check override, got %d", len(filtered))
	}
	if filtered[0].ID != "campaign-high-with-critical-checks" {
		t.Fatalf("wrong template selected: %q", filtered[0].ID)
	}

	filtered = engine.FilteredTemplates(nil, []string{"high"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 template matching high, got %d", len(filtered))
	}

	filtered = engine.FilteredTemplates(nil, []string{"medium"})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 template matching medium, got %d", len(filtered))
	}
	if filtered[0].ID != "plain-medium" {
		t.Fatalf("wrong template selected for medium: %q", filtered[0].ID)
	}
}

func TestScanDetailedTracksRequestErrorsWithoutDroppingFindings(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/ok":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Request:    req,
					Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
				}, nil
			case "/error":
				return nil, errors.New("dial failed")
			default:
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Header:     make(http.Header),
					Request:    req,
					Body:       io.NopCloser(strings.NewReader("not found")),
				}, nil
			}
		}),
		Timeout: 2 * time.Second,
	}

	if err := engine.AddTemplate(&Template{
		ID: "request-error-template",
		Info: TemplateInfo{
			Name:        "Request Error Template",
			Severity:    "high",
			Author:      "test",
			Description: "test",
			Tags:        []string{"demo"},
		},
		Checks: []Check{
			{
				Name:   "successful",
				Method: "GET",
				Path:   "/ok",
				Matchers: []Matcher{
					{Type: MatchStatus, Value: "200"},
				},
				Finding: FindingTemplate{
					Title:       "Successful finding",
					Description: "successful finding",
				},
			},
			{
				Name:   "request-error",
				Method: "GET",
				Path:   "/error",
				Matchers: []Matcher{
					{Type: MatchStatus, Value: "200"},
				},
				Finding: FindingTemplate{
					Title:       "Should not match",
					Description: "should not match",
				},
			},
		},
	}); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, metrics, err := engine.ScanDetailed("http://target.local", []string{"demo"}, nil)
	if err != nil {
		t.Fatalf("ScanDetailed returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if metrics.RequestErrors != 1 {
		t.Fatalf("expected 1 request error, got %d", metrics.RequestErrors)
	}
}

func TestDefaultContentTypeForPOST(t *testing.T) {
	var capturedReq *http.Request
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			capturedReq = req
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Request:    req,
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
		Timeout: 2 * time.Second,
	}

	tmpl := &Template{
		ID:   "ct-json",
		Info: TemplateInfo{Name: "CT JSON", Severity: "info", Author: "test"},
		Checks: []Check{
			{
				Name:   "post-json",
				Method: "POST",
				Path:   "/api",
				Body:   `{"key":"value"}`,
				Matchers: []Matcher{
					{Type: MatchStatus, Value: "200"},
				},
				Finding: FindingTemplate{Title: "test"},
			},
		},
	}

	_, _, err := engine.ExecuteTemplateDetailed(tmpl, "http://target.local")
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed returned error: %v", err)
	}
	if capturedReq == nil {
		t.Fatal("request was not captured")
	}
	if ct := capturedReq.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json for JSON body, got %q", ct)
	}

	capturedReq = nil
	tmpl.ID = "ct-form"
	tmpl.Checks[0].Body = "username=admin&password=admin"

	_, _, err = engine.ExecuteTemplateDetailed(tmpl, "http://target.local")
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed returned error: %v", err)
	}
	if capturedReq == nil {
		t.Fatal("request was not captured")
	}
	if ct := capturedReq.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Fatalf("expected Content-Type application/x-www-form-urlencoded for form body, got %q", ct)
	}
}

func TestTemplateBugVsNetworkError(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}),
		Timeout: 2 * time.Second,
	}

	tmplBug := &Template{
		ID:   "template-bug",
		Info: TemplateInfo{Name: "Template Bug", Severity: "info", Author: "test"},
		Checks: []Check{
			{
				Name:   "bad-url",
				Method: "GET",
				Path:   "/path\x7f",
				Matchers: []Matcher{
					{Type: MatchStatus, Value: "200"},
				},
				Finding: FindingTemplate{Title: "test"},
			},
		},
	}

	_, metrics, err := engine.ExecuteTemplateDetailed(tmplBug, "http://target.local")
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed returned error: %v", err)
	}
	if metrics.TemplateErrors == 0 {
		t.Fatal("expected TemplateErrors > 0 for malformed URL")
	}
	if metrics.RequestErrors != 0 {
		t.Fatalf("expected RequestErrors == 0, got %d", metrics.RequestErrors)
	}

	tmplNet := &Template{
		ID:   "network-error",
		Info: TemplateInfo{Name: "Network Error", Severity: "info", Author: "test"},
		Checks: []Check{
			{
				Name:   "unreachable",
				Method: "GET",
				Path:   "/valid-path",
				Matchers: []Matcher{
					{Type: MatchStatus, Value: "200"},
				},
				Finding: FindingTemplate{Title: "test"},
			},
		},
	}

	_, metrics, err = engine.ExecuteTemplateDetailed(tmplNet, "http://target.local")
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed returned error: %v", err)
	}
	if metrics.RequestErrors == 0 {
		t.Fatal("expected RequestErrors > 0 for network failure")
	}
	if metrics.TemplateErrors != 0 {
		t.Fatalf("expected TemplateErrors == 0, got %d", metrics.TemplateErrors)
	}
}

func TestEngineProgressCallback(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("service online")),
			}, nil
		}),
	}

	tmpl := &Template{
		ID:   "progress-test",
		Info: TemplateInfo{Name: "Progress Test", Severity: "info", Author: "test", Description: "test"},
		Checks: []Check{
			{
				Name:   "check-1",
				Method: "GET",
				Path:   "/",
				Matchers: []Matcher{
					{Type: MatchStatus, Value: "200"},
					{Type: MatchBodyContains, Value: "service online"},
				},
				Finding: FindingTemplate{Title: "Service detected", Description: "test"},
			},
		},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	var events []ProgressEvent
	engine.OnProgress = func(ev ProgressEvent) {
		events = append(events, ev)
	}

	findings, _, err := engine.ScanDetailed("http://target.local", nil, nil)
	if err != nil {
		t.Fatalf("ScanDetailed returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}

	foundTypes := make(map[string]bool)
	for _, ev := range events {
		foundTypes[ev.Type] = true
	}
	if !foundTypes["start"] {
		t.Fatal("expected 'start' progress event")
	}
	if !foundTypes["match"] {
		t.Fatal("expected 'match' progress event")
	}
}

func TestEngineHandlesOversizedResponseWithoutCrash(t *testing.T) {
	oversized := strings.Repeat("A", 1<<20+1024)

	engine := NewEngine(2*time.Second, 1)
	engine.Verbose = true
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(oversized)),
				Request:    req,
			}, nil
		}),
	}

	tmpl := &Template{
		ID: "trunc-test",
		Info: TemplateInfo{
			Name:        "Truncation Test",
			Severity:    "info",
			Author:      "test",
			Description: "test",
		},
		Checks: []Check{
			{
				Name:   "big-response",
				Method: "GET",
				Path:   "/large",
				Matchers: []Matcher{
					{Type: "status", Value: "200"},
				},
				Finding: FindingTemplate{Title: "Large response", Description: "test"},
			},
		},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, metrics, err := engine.ScanDetailed("http://target.local", nil, nil)
	if err != nil {
		t.Fatalf("ScanDetailed should not error on oversized response: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding from incomplete oversized response, got %d", len(findings))
	}
	if metrics.RequestErrors == 0 {
		t.Fatal("expected request error metric for oversized response")
	}
	if len(metrics.FailedTemplates) == 0 {
		t.Fatal("expected failed template entry for oversized response")
	}
}

func TestBuildAutoEvidence(t *testing.T) {
	ev := buildAutoEvidence("POST", "http://10.0.0.1:3000/message", 200, `{"result":"ok"}`)
	if !strings.Contains(ev, "=== REQUEST ===") {
		t.Fatal("expected REQUEST header")
	}
	if !strings.Contains(ev, "POST http://10.0.0.1:3000/message") {
		t.Fatal("expected method and URL")
	}
	if !strings.Contains(ev, "=== RESPONSE (200) ===") {
		t.Fatal("expected RESPONSE header with status")
	}
	if !strings.Contains(ev, `{"result":"ok"}`) {
		t.Fatal("expected response body")
	}
}

func TestBuildAutoEvidenceTruncates(t *testing.T) {
	longBody := strings.Repeat("A", 3000)
	ev := buildAutoEvidence("GET", "http://10.0.0.1/big", 200, longBody)
	if !strings.Contains(ev, "... truncated (3000 bytes total)") {
		t.Fatal("expected truncation notice")
	}
	if strings.Contains(ev, strings.Repeat("A", 2500)) {
		t.Fatal("body should be truncated to ~2048 chars, not include full 3000")
	}
}

func TestAutoEvidencePopulatedForProofFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"content":[{"text":"CANARY_OUTPUT"}]}}`))
	}))
	defer ts.Close()

	engine := NewEngine(2*time.Second, 1)
	tmpl := &Template{
		ID: "proof-test",
		Info: TemplateInfo{
			Name:        "Proof Test",
			Severity:    "critical",
			Author:      "test",
			Description: "test",
		},
		Checks: []Check{
			{
				Name:   "canary-check",
				Method: "POST",
				Path:   "/message",
				Stage:  "impact",
				Landed: "execution-confirmed",
				Matchers: []Matcher{
					{Type: "status", Value: "200"},
					{Type: "body_contains", Value: "CANARY_OUTPUT"},
				},
				Finding: FindingTemplate{
					Title:       "RCE Confirmed",
					Description: "Canary echoed back",
				},
			},
		},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, _, err := engine.ScanDetailed(ts.URL, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Evidence == "" {
		t.Fatal("expected auto-captured evidence for proof finding, got empty")
	}
	if !strings.Contains(f.Evidence, "CANARY_OUTPUT") {
		t.Fatalf("expected evidence to contain response body, got: %s", f.Evidence)
	}
	if !strings.Contains(f.Evidence, "=== REQUEST ===") {
		t.Fatal("expected evidence to contain request header")
	}
}

func TestExplicitEvidenceNotOverridden(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"result":"data"}`))
	}))
	defer ts.Close()

	engine := NewEngine(2*time.Second, 1)
	tmpl := &Template{
		ID: "explicit-ev-test",
		Info: TemplateInfo{
			Name:        "Explicit Evidence Test",
			Severity:    "high",
			Author:      "test",
			Description: "test",
		},
		Checks: []Check{
			{
				Name:   "explicit-check",
				Method: "GET",
				Path:   "/api",
				Stage:  "impact",
				Landed: "confirmed",
				Matchers: []Matcher{
					{Type: "status", Value: "200"},
				},
				Finding: FindingTemplate{
					Title:       "API Exposed",
					Description: "API is accessible",
					Evidence:    "Custom explicit evidence text",
				},
			},
		},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, _, err := engine.ScanDetailed(ts.URL, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Evidence != "Custom explicit evidence text" {
		t.Fatalf("explicit evidence should not be overridden, got: %s", findings[0].Evidence)
	}
}

func TestDefaultModeIsDetect(t *testing.T) {
	engine := NewEngine(time.Second, 1)
	if engine.Mode != ModeDetect {
		t.Fatalf("expected default mode ModeDetect, got %q", engine.Mode)
	}
}

func TestFilteredTemplatesRespectsMode(t *testing.T) {
	engine := NewEngine(time.Second, 1)
	engine.Templates = []*Template{
		{
			ID: "detect-only",
			Info: TemplateInfo{
				Name:     "Detection Template",
				Severity: "high",
				Author:   "test",
				Tags:     []string{"mcp"},
			},
			Checks: []Check{{Name: "check", Method: "GET", Path: "/"}},
		},
		{
			ID: "exploit-template",
			Info: TemplateInfo{
				Name:     "Exploit Template",
				Type:     TemplateTypeExploit,
				Severity: "critical",
				Author:   "test",
				Tags:     []string{"mcp"},
			},
			Checks: []Check{{Name: "check", Method: "POST", Path: "/rce"}},
		},
	}

	engine.Mode = ModeDetect
	filtered := engine.FilteredTemplates(nil, nil)
	if len(filtered) != 1 {
		t.Fatalf("ModeDetect: expected 1 template, got %d", len(filtered))
	}
	if filtered[0].ID != "detect-only" {
		t.Fatalf("ModeDetect: expected detect-only, got %q", filtered[0].ID)
	}
}

func TestFilteredTemplatesFullMode(t *testing.T) {
	engine := NewEngine(time.Second, 1)
	engine.Templates = []*Template{
		{
			ID: "detect-only",
			Info: TemplateInfo{
				Name:     "Detection Template",
				Severity: "high",
				Author:   "test",
				Tags:     []string{"mcp"},
			},
			Checks: []Check{{Name: "check", Method: "GET", Path: "/"}},
		},
		{
			ID: "exploit-template",
			Info: TemplateInfo{
				Name:     "Exploit Template",
				Type:     TemplateTypeExploit,
				Severity: "critical",
				Author:   "test",
				Tags:     []string{"mcp"},
			},
			Checks: []Check{{Name: "check", Method: "POST", Path: "/rce"}},
		},
	}

	engine.Mode = ModeFull
	filtered := engine.FilteredTemplates(nil, nil)
	if len(filtered) != 2 {
		t.Fatalf("ModeFull: expected 2 templates, got %d", len(filtered))
	}
}

func TestScanModeIncludedInFindingMetadata(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.Mode = ModeFull
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}

	tmpl := &Template{
		ID:   "mode-meta-test",
		Info: TemplateInfo{Name: "Mode Meta", Severity: "info", Author: "test", Description: "test"},
		Checks: []Check{{
			Name:   "check",
			Method: "GET",
			Path:   "/",
			Matchers: []Matcher{
				{Type: MatchStatus, Value: "200"},
			},
			Finding: FindingTemplate{Title: "test", Description: "test"},
		}},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, _, err := engine.ScanDetailed("http://target.local", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	mode, ok := findings[0].Metadata["scan_mode"]
	if !ok {
		t.Fatal("expected scan_mode in finding metadata")
	}
	if mode != "full" {
		t.Fatalf("expected scan_mode 'full', got %q", mode)
	}
	ps, ok := findings[0].Metadata["landed"]
	if !ok {
		t.Fatal("expected landed auto-set in finding metadata")
	}
	if ps != "read-confirmed" {
		t.Fatalf("expected landed 'read-confirmed' for detection template, got %q", ps)
	}
}

func TestAutoProofBadgeDetection(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
				Request:    req,
			}, nil
		}),
	}

	tmpl := &Template{
		ID:   "detect-badge-test",
		Info: TemplateInfo{Name: "Detect Badge", Severity: "high", Author: "test", Description: "test", Type: TemplateTypeDetection},
		Checks: []Check{{
			Name:     "check",
			Method:   "GET",
			Path:     "/api/status",
			Matchers: []Matcher{{Type: MatchStatus, Value: "200"}},
			Finding:  FindingTemplate{Title: "Service Exposed", Description: "test"},
		}},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, _, err := engine.ScanDetailed("http://target.local", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Metadata["stage"] != "impact" {
		t.Fatalf("expected stage 'proof', got %q", findings[0].Metadata["stage"])
	}
	if findings[0].Metadata["landed"] != "read-confirmed" {
		t.Fatalf("expected landed 'read-confirmed', got %q", findings[0].Metadata["landed"])
	}
	if findings[0].Evidence == "" {
		t.Fatal("expected auto-generated evidence for auto-badged finding")
	}
	if !strings.Contains(findings[0].Evidence, "=== REQUEST ===") {
		t.Fatalf("expected auto-evidence to contain request/response, got %q", findings[0].Evidence)
	}
}

func TestAutoProofBadgeExploit(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.Mode = ModeFull
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"result":"pwned"}`)),
				Request:    req,
			}, nil
		}),
	}

	tmpl := &Template{
		ID:   "exploit-badge-test",
		Info: TemplateInfo{Name: "Exploit Badge", Severity: "critical", Author: "test", Description: "test", Type: TemplateTypeExploit},
		Checks: []Check{{
			Name:     "rce-check",
			Method:   "POST",
			Path:     "/exec",
			Matchers: []Matcher{{Type: MatchStatus, Value: "200"}},
			Finding:  FindingTemplate{Title: "RCE Confirmed", Description: "test"},
		}},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, _, err := engine.ScanDetailed("http://target.local", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Metadata["stage"] != "impact" {
		t.Fatalf("expected stage 'proof', got %q", findings[0].Metadata["stage"])
	}
	if findings[0].Metadata["landed"] != "takeover-capable" {
		t.Fatalf("expected landed 'takeover-capable', got %q", findings[0].Metadata["landed"])
	}
}

func TestExplicitProofMetadataHonored(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"tools":["fetch"]}`)),
				Request:    req,
			}, nil
		}),
	}

	tmpl := &Template{
		ID:   "explicit-proof-test",
		Info: TemplateInfo{Name: "Explicit Proof", Severity: "medium", Author: "test", Description: "test"},
		Checks: []Check{{
			Name:     "reachable-check",
			Method:   "GET",
			Path:     "/tools",
			Matchers: []Matcher{{Type: MatchStatus, Value: "200"}},
			Stage:    "access",
			Landed:   "reachable",
			Finding:  FindingTemplate{Title: "Tool Exposed", Description: "test"},
		}},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, _, err := engine.ScanDetailed("http://target.local", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Metadata["stage"] != "access" {
		t.Fatalf("explicit stage should be honored, got %q", findings[0].Metadata["stage"])
	}
	if findings[0].Metadata["landed"] != "reachable" {
		t.Fatalf("explicit landed should be honored, got %q", findings[0].Metadata["landed"])
	}
}

func resetCompiledRegexCache() {
	compiledRegexCache = sync.Map{}
	compiledRegexCacheCount.Store(0)
}

func TestCompileRegexCachedReturnsSameInstance(t *testing.T) {
	resetCompiledRegexCache()
	defer resetCompiledRegexCache()

	first, err := compileRegexCached("^hello$")
	if err != nil {
		t.Fatalf("first compileRegexCached returned error: %v", err)
	}
	second, err := compileRegexCached("^hello$")
	if err != nil {
		t.Fatalf("second compileRegexCached returned error: %v", err)
	}
	if first != second {
		t.Fatal("expected compileRegexCached to return the cached regexp instance")
	}
}

func TestLoadEmbeddedTemplates(t *testing.T) {
	engine := NewEngine(2*time.Second, 4)
	if err := engine.LoadEmbeddedTemplates(); err != nil {
		t.Fatalf("LoadEmbeddedTemplates returned error: %v", err)
	}

	if len(engine.Templates) == 0 {
		t.Fatal("expected templates to be loaded, got 0")
	}
	t.Logf("loaded %d embedded templates", len(engine.Templates))

	knownIDs := []string{
		"ollama-auth-001-unauthenticated-api",
		"mcp-auth-001-unauthenticated-sse",
	}
	loaded := make(map[string]bool, len(engine.Templates))
	for _, tmpl := range engine.Templates {
		loaded[tmpl.ID] = true
	}
	for _, id := range knownIDs {
		if !loaded[id] {
			t.Errorf("expected embedded template %q to be present", id)
		}
	}
}

func TestScanWithEmbeddedTemplatesAndMockTarget(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Ollama is running")
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"models":[{"name":"llama3:latest","size":4000000000}]}`)
		case "/api/version":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"version":"0.1.30"}`)
		case "/api/ps":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"models":[{"name":"llama3:latest","size":4000000000}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "not found")
		}
	}))
	defer ts.Close()

	engine := NewEngine(5*time.Second, 4)
	if err := engine.LoadEmbeddedTemplates(); err != nil {
		t.Fatalf("LoadEmbeddedTemplates: %v", err)
	}

	findings, err := engine.Scan(ts.URL, []string{"ollama"}, nil)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from Ollama templates against mock server, got 0")
	}

	foundIDs := make(map[string]bool)
	for _, f := range findings {
		foundIDs[f.TemplateID] = true
		t.Logf("finding: template=%s title=%q severity=%s", f.TemplateID, f.Title, f.Severity)
	}

	if !foundIDs["ollama-auth-001-unauthenticated-api"] {
		t.Error("expected finding from ollama-auth-001-unauthenticated-api template")
	}

	for _, f := range findings {
		if f.Target != ts.URL {
			t.Errorf("finding target %q does not match test server URL %q", f.Target, ts.URL)
		}
		if f.Severity == "" {
			t.Errorf("finding %q has empty severity", f.ID)
		}
		if f.Title == "" {
			t.Errorf("finding %q has empty title", f.ID)
		}
	}
}

func TestExecuteStepWithVariableInterpolation(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/api/models/llama3" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"model":"llama3","status":"loaded"}`)),
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("not found")),
				Request:    req,
			}, nil
		}),
	}

	step := HTTPStep{
		Method: "GET",
		Path:   "/api/models/{{model_name}}",
		Matchers: []Matcher{
			{Type: MatchStatus, Value: "200"},
			{Type: MatchBodyContains, Value: "loaded"},
		},
	}

	vars := map[string]string{"model_name": "llama3"}
	matched, _, metrics := engine.executeStep(step, "http://target.local", vars)
	if !matched {
		t.Fatal("expected step to match with interpolated variable")
	}
	if metrics.RequestErrors != 0 {
		t.Fatalf("expected 0 request errors, got %d", metrics.RequestErrors)
	}
}

func TestExecuteStepBodyRegexMatcher(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`version: 2.9.0-beta`)),
				Request:    req,
			}, nil
		}),
	}

	step := HTTPStep{
		Method: "GET",
		Path:   "/version",
		Matchers: []Matcher{
			{Type: MatchBodyRegex, Value: `version:\s+\d+\.\d+\.\d+`},
		},
	}
	matched, _, _ := engine.executeStep(step, "http://target.local", nil)
	if !matched {
		t.Fatal("expected body regex to match")
	}

	step.Matchers[0].Value = `version:\s+\d+\.\d+\.\d+\.\d+`
	matched, _, _ = engine.executeStep(step, "http://target.local", nil)
	if matched {
		t.Fatal("expected body regex to NOT match four-part version")
	}
}

func TestExecuteStepNegateMatcher(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"auth":"none"}`)),
				Request:    req,
			}, nil
		}),
	}

	step := HTTPStep{
		Method: "GET",
		Path:   "/",
		Matchers: []Matcher{
			{Type: MatchStatus, Value: "200"},
			{Type: MatchBodyContains, Value: "forbidden", Negate: true},
		},
	}
	matched, _, _ := engine.executeStep(step, "http://target.local", nil)
	if !matched {
		t.Fatal("expected negated matcher to pass when body does not contain 'forbidden'")
	}
}

func TestExecuteStepHeaderMatcher(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			h := make(http.Header)
			h.Set("X-Powered-By", "MLflow/2.0")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     h,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}

	step := HTTPStep{
		Method: "GET",
		Path:   "/",
		Matchers: []Matcher{
			{Type: MatchHeaderContains, Key: "X-Powered-By", Value: "mlflow"},
		},
	}
	matched, _, _ := engine.executeStep(step, "http://target.local", nil)
	if !matched {
		t.Fatal("expected header matcher to match (case-insensitive)")
	}
}

func TestExecuteStepBodyNotContains(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
				Request:    req,
			}, nil
		}),
	}

	step := HTTPStep{
		Method: "GET",
		Path:   "/",
		Matchers: []Matcher{
			{Type: MatchBodyNotContains, Value: "error"},
		},
	}
	matched, _, _ := engine.executeStep(step, "http://target.local", nil)
	if !matched {
		t.Fatal("expected body_not_contains to match when body does not contain 'error'")
	}

	step.Matchers[0].Value = "status"
	matched, _, _ = engine.executeStep(step, "http://target.local", nil)
	if matched {
		t.Fatal("expected body_not_contains to not match when body contains 'status'")
	}
}

func TestExecuteStepJSONPathMatcher(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"result":{"id":"abc","items":["x","y"]}}`)),
				Request:    req,
			}, nil
		}),
	}

	step := HTTPStep{
		Method: "GET",
		Path:   "/",
		Matchers: []Matcher{
			{Type: MatchJSONPath, Key: "result.id", Value: "abc"},
		},
	}
	matched, _, _ := engine.executeStep(step, "http://target.local", nil)
	if !matched {
		t.Fatal("expected JSON path matcher to match value 'abc'")
	}

	step.Matchers[0].Value = ""
	matched, _, _ = engine.executeStep(step, "http://target.local", nil)
	if !matched {
		t.Fatal("expected JSON path matcher with empty value to check existence only")
	}

	step.Matchers[0].Key = "result.nonexistent"
	matched, _, _ = engine.executeStep(step, "http://target.local", nil)
	if matched {
		t.Fatal("expected JSON path matcher to not match nonexistent path")
	}
}

func TestExtractorRegexAndJSON(t *testing.T) {
	body := `{"version":"2.9.0","model":"llama3"}`
	headers := make(http.Header)

	regexExt := Extractor{Type: "regex", Name: "ver", Regex: `"version":"([^"]+)"`}
	val := extract(regexExt, body, headers)
	if val != "2.9.0" {
		t.Fatalf("expected regex extraction '2.9.0', got %q", val)
	}

	jsonExt := Extractor{Type: "json", Name: "model", Path: "model"}
	val = extract(jsonExt, body, headers)
	if val != "llama3" {
		t.Fatalf("expected json extraction 'llama3', got %q", val)
	}

	headerExt := Extractor{Type: "header", Name: "server", Path: "Server"}
	headers.Set("Server", "uvicorn")
	val = extract(headerExt, body, headers)
	if val != "uvicorn" {
		t.Fatalf("expected header extraction 'uvicorn', got %q", val)
	}
}

func TestExecuteStepWithBodyAndHeaders(t *testing.T) {
	var capturedBody string
	var capturedHeaders http.Header
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			capturedBody = string(body)
			capturedHeaders = req.Header
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
				Request:    req,
			}, nil
		}),
	}

	step := HTTPStep{
		Method:  "POST",
		Path:    "/api/{{action}}",
		Headers: map[string]string{"X-Custom": "{{token}}"},
		Body:    `{"key":"{{value}}"}`,
		Matchers: []Matcher{
			{Type: MatchStatus, Value: "200"},
		},
	}
	vars := map[string]string{"action": "test", "token": "secret", "value": "data"}
	matched, _, metrics := engine.executeStep(step, "http://target.local", vars)
	if !matched {
		t.Fatal("expected step to match")
	}
	if metrics.RequestErrors != 0 {
		t.Fatalf("expected 0 errors, got %d", metrics.RequestErrors)
	}
	if capturedBody != `{"key":"data"}` {
		t.Fatalf("expected interpolated body, got %q", capturedBody)
	}
	if capturedHeaders.Get("X-Custom") != "secret" {
		t.Fatalf("expected interpolated header, got %q", capturedHeaders.Get("X-Custom"))
	}
}

func TestExecuteStepMatcherStatusInvalid(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}

	step := HTTPStep{
		Method: "GET",
		Path:   "/",
		Matchers: []Matcher{
			{Type: MatchStatus, Value: "not-a-number"},
		},
	}
	matched, _, _ := engine.executeStep(step, "http://target.local", nil)
	if matched {
		t.Fatal("expected invalid status value to not match")
	}
}

func TestExecuteStepBodyRegexInvalid(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}

	step := HTTPStep{
		Method: "GET",
		Path:   "/",
		Matchers: []Matcher{
			{Type: MatchBodyRegex, Value: "[invalid(regex"},
		},
	}
	matched, _, _ := engine.executeStep(step, "http://target.local", nil)
	if matched {
		t.Fatal("expected invalid regex to not match")
	}
}

func TestExtractorRegexWithGroup(t *testing.T) {
	body := `version: 2.9.0-beta`
	headers := make(http.Header)

	group0 := 0
	ext := Extractor{Type: "regex", Name: "full", Regex: `(version:\s+)(\d+\.\d+\.\d+)`, Group: &group0}
	val := extract(ext, body, headers)
	if val != "version: 2.9.0" {
		t.Fatalf("expected group 0 match, got %q", val)
	}

	group2 := 2
	ext2 := Extractor{Type: "regex", Name: "ver", Regex: `(version:\s+)(\d+\.\d+\.\d+)`, Group: &group2}
	val2 := extract(ext2, body, headers)
	if val2 != "2.9.0" {
		t.Fatalf("expected group 2 match, got %q", val2)
	}
}

func TestExtractorInvalidRegex(t *testing.T) {
	body := "test"
	headers := make(http.Header)
	ext := Extractor{Type: "regex", Name: "bad", Regex: "[invalid(regex"}
	val := extract(ext, body, headers)
	if val != "" {
		t.Fatalf("expected empty for invalid regex, got %q", val)
	}
}

func TestExtractorRegexNoMatch(t *testing.T) {
	body := "no match here"
	headers := make(http.Header)
	ext := Extractor{Type: "regex", Name: "ver", Regex: `version:\s+(\d+)`}
	val := extract(ext, body, headers)
	if val != "" {
		t.Fatalf("expected empty for no match, got %q", val)
	}
}

func TestExtractorJSONNoMatch(t *testing.T) {
	body := `{"other":"field"}`
	headers := make(http.Header)
	ext := Extractor{Type: "json", Name: "missing", Path: "nonexistent.path"}
	val := extract(ext, body, headers)
	if val != "" {
		t.Fatalf("expected empty for missing JSON path, got %q", val)
	}
}

func TestExtractorUnknownType(t *testing.T) {
	body := "test"
	headers := make(http.Header)
	ext := Extractor{Type: "unknown", Name: "x"}
	val := extract(ext, body, headers)
	if val != "" {
		t.Fatalf("expected empty for unknown type, got %q", val)
	}
}

func TestDetectPhaseErrorLogging(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/" {
				return nil, fmt.Errorf("connection refused")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}

	tmpl := &Template{
		ID:   "detect-error",
		Info: TemplateInfo{Name: "Detect Error", Severity: "high", Author: "test", Description: "test"},
		Detect: []HTTPStep{
			{Method: "GET", Path: "/", Matchers: []Matcher{{Type: MatchBodyContains, Value: "running"}}},
		},
		Checks: []Check{
			{Name: "check", Method: "GET", Path: "/api", Matchers: []Matcher{{Type: MatchStatus, Value: "200"}}, Finding: FindingTemplate{Title: "test", Description: "test"}},
		},
	}

	findings, metrics, err := engine.ExecuteTemplateDetailed(tmpl, "http://target.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when detect has errors, got %d", len(findings))
	}
	if metrics.DetectErrors == 0 {
		t.Fatal("expected DetectErrors > 0")
	}
}

func TestDetectPhaseSkipsChecksOnFailure(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("not found")),
				Request:    req,
			}, nil
		}),
	}

	tmpl := &Template{
		ID:   "detect-fail",
		Info: TemplateInfo{Name: "Detect Fail", Severity: "high", Author: "test", Description: "test"},
		Detect: []HTTPStep{
			{Method: "GET", Path: "/", Matchers: []Matcher{{Type: MatchBodyContains, Value: "Ollama is running"}}},
		},
		Checks: []Check{
			{Name: "check", Method: "GET", Path: "/api/tags", Matchers: []Matcher{{Type: MatchStatus, Value: "200"}}, Finding: FindingTemplate{Title: "test"}},
		},
	}

	findings, err := engine.ExecuteTemplate(tmpl, "http://target.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when detect fails, got %d", len(findings))
	}
}

func TestScanDetailedPopulatesFailedTemplates(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}),
	}

	tmpl := &Template{
		ID:   "net-fail",
		Info: TemplateInfo{Name: "Net Fail", Severity: "high", Author: "test", Description: "test"},
		// No detect steps — skip straight to checks
		Checks: []Check{
			{Name: "check1", Method: "GET", Path: "/api/v1", Matchers: []Matcher{{Type: MatchStatus, Value: "200"}}, Finding: FindingTemplate{Title: "found", Description: "test"}},
		},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, metrics, err := engine.ScanDetailed("http://target.local", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	if metrics.RequestErrors == 0 {
		t.Fatal("expected RequestErrors > 0")
	}
	if len(metrics.FailedTemplates) == 0 {
		t.Fatal("expected FailedTemplates to be populated")
	}
	ft := metrics.FailedTemplates[0]
	if ft.TemplateID != "net-fail" {
		t.Fatalf("expected TemplateID 'net-fail', got %q", ft.TemplateID)
	}
	if ft.Target != "http://target.local" {
		t.Fatalf("expected Target 'http://target.local', got %q", ft.Target)
	}
	if ft.Error == "" {
		t.Fatal("expected non-empty Error in TemplateFailure")
	}
}

func TestProgressEventErrorField(t *testing.T) {
	engine := NewEngine(2*time.Second, 1)
	engine.HTTPClient = &http.Client{
		Transport: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		}),
	}

	// Use a template with detect steps that will fail — triggering detect errors
	// Since ExecuteTemplateDetailed returns nil error but metrics with errors,
	// we need to test the templateMetrics path instead.
	// Actually, let's test via a template with no detect and failing checks.
	tmpl := &Template{
		ID:   "progress-fail",
		Info: TemplateInfo{Name: "Progress Fail", Severity: "medium", Author: "test", Description: "test"},
		Checks: []Check{
			{Name: "check1", Method: "GET", Path: "/x", Matchers: []Matcher{{Type: MatchStatus, Value: "200"}}, Finding: FindingTemplate{Title: "x", Description: "test"}},
		},
	}
	if err := engine.AddTemplate(tmpl); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	var events []ProgressEvent
	engine.OnProgress = func(e ProgressEvent) {
		events = append(events, e)
	}

	engine.ScanDetailed("http://target.local", nil, nil)

	// Should have at least a "start" event
	var startFound bool
	for _, ev := range events {
		if ev.Type == "start" && ev.TemplateID == "progress-fail" {
			startFound = true
		}
	}
	if !startFound {
		t.Fatal("expected a 'start' progress event for template 'progress-fail'")
	}
}

func TestCompileRegexCachedHandlesOverflow(t *testing.T) {
	resetCompiledRegexCache()
	defer resetCompiledRegexCache()

	var uncached *regexp.Regexp
	for i := 0; i < compiledRegexCacheLimit+1; i++ {
		pattern := fmt.Sprintf("^pattern-%d$", i)
		re, err := compileRegexCached(pattern)
		if err != nil {
			t.Fatalf("compileRegexCached(%q) returned error: %v", pattern, err)
		}
		if re == nil {
			t.Fatalf("compileRegexCached(%q) returned nil regexp", pattern)
		}
		if i == compiledRegexCacheLimit {
			uncached = re
		}
	}

	if got := compiledRegexCacheCount.Load(); got != compiledRegexCacheLimit {
		t.Fatalf("expected cache count to stop at %d, got %d", compiledRegexCacheLimit, got)
	}

	repeated, err := compileRegexCached(fmt.Sprintf("^pattern-%d$", compiledRegexCacheLimit))
	if err != nil {
		t.Fatalf("compileRegexCached overflow pattern returned error: %v", err)
	}
	if repeated == uncached {
		t.Fatal("expected overflow pattern to be recompiled instead of cached")
	}
}
