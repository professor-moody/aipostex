//go:build integration

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/vulncheck"
)

func TestScanNetworkPipelineIntegration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "Ollama is running")
	})
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"models":[]}`)
	})
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"0.0.0-test"}`)
	})
	mux.HandleFunc("/api/ps", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"models":[]}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}
	host := parsed.Hostname()
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parsing test server port: %v", err)
	}

	// --- Phase 1: fingerprint discovery ---
	scanner := fingerprint.NewScanner(2*time.Second, 1)
	observation := scanner.ScanHost(host, port)
	if len(observation.Results) == 0 {
		t.Fatalf("expected fingerprint result, got %#v", observation)
	}
	result := observation.Results[0]
	if result.Service != "ollama" {
		t.Fatalf("expected service ollama, got %q", result.Service)
	}

	// --- Phase 2: vulncheck template engine ---
	engine := vulncheck.NewEngine(2*time.Second, 1)
	if err := engine.LoadEmbeddedTemplates(); err != nil {
		t.Fatalf("loading embedded templates: %v", err)
	}

	tags := []string{result.Service}
	filtered := engine.FilteredTemplates(tags, nil)
	if len(filtered) == 0 {
		t.Log("no embedded templates matched tag", result.Service)
	}

	findings, _, err := engine.ScanDetailed(srv.URL, tags, nil)
	if err != nil {
		t.Logf("ScanDetailed returned error (acceptable for stub server): %v", err)
	}
	t.Logf("vulncheck findings against stub: %d", len(findings))

	// --- Phase 3: workflow plan generation ---
	plan := buildScanNetworkWorkflowPlan(result)
	if len(plan.Recommendations) == 0 {
		t.Fatal("expected workflow recommendations for ollama, got none")
	}
	if plan.Stage == "" {
		t.Fatal("expected non-empty workflow stage")
	}
	t.Logf("workflow plan stage=%s recommendations=%d", plan.Stage, len(plan.Recommendations))
}
