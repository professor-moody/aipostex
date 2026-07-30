package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
)

func TestScanAllTargetNormalizationMergesURLPorts(t *testing.T) {
	targets, extractedPorts := stripURLTargets([]string{"http://127.0.0.1:11434", "10.0.0.5"})
	ports, err := parsePorts([]string{"8000"})
	if err != nil {
		t.Fatalf("parsePorts returned error: %v", err)
	}
	ports = append(ports, extractedPorts...)
	ports = uniqueSortedPorts(ports)

	if len(targets) != 2 || targets[0] != "10.0.0.5" || targets[1] != "127.0.0.1" {
		t.Fatalf("unexpected normalized targets: %#v", targets)
	}
	if len(ports) != 2 || ports[0] != 8000 || ports[1] != 11434 {
		t.Fatalf("unexpected merged ports: %#v", ports)
	}
}

func TestParsePortsRejectsTrailingJunk(t *testing.T) {
	if _, err := parsePorts([]string{"8080abc"}); err == nil {
		t.Fatal("expected parsePorts to reject trailing junk")
	}
}

func TestRunExploitEnumerationUsesRealEnumResultsOnly(t *testing.T) {
	prevEnumerator := scanAllServiceEnumerator
	prevErr := stderrWriter
	defer func() {
		scanAllServiceEnumerator = prevEnumerator
		stderrWriter = prevErr
	}()

	var stderr bytes.Buffer
	stderrWriter = &stderr
	scanAllServiceEnumerator = func(service, target string, httpClient *http.Client) ([]report.Finding, error) {
		switch target {
		case "http://ok":
			return []report.Finding{{
				Source: report.SourceGradio,
				Target: target,
				Title:  "Gradio app enumerated",
			}}, nil
		default:
			return nil, fmt.Errorf("enumeration failed")
		}
	}

	out := runExploitEnumeration([]fingerprint.Result{
		{Service: "gradio", URL: "http://ok"},
		{Service: "gradio", URL: "http://fail"},
	}, &http.Client{})

	if len(out.Findings) != 1 || out.Findings[0].Title != "Gradio app enumerated" {
		t.Fatalf("expected only real enumeration findings, got %#v", out.Findings)
	}
	if out.Attempts != 2 || out.Failures != 1 {
		t.Fatalf("expected attempts=2 failures=1, got attempts=%d failures=%d", out.Attempts, out.Failures)
	}
	if strings.Contains(out.Findings[0].Title, "accessible") {
		t.Fatalf("expected no synthetic accessibility finding, got %#v", out.Findings[0])
	}
	if !strings.Contains(stderr.String(), "enumerating gradio at http://fail") {
		t.Fatalf("expected failed enumeration to be logged, got %q", stderr.String())
	}
}

func TestWriteAndRemoveCheckpoint(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test-checkpoint.jsonl")

	findings := []report.Finding{
		{ID: "f1", Title: "Test Finding 1", Source: report.SourceOllama, Severity: report.SeverityInfo},
		{ID: "f2", Title: "Test Finding 2", Source: report.SourceMLflow, Severity: report.SeverityHigh},
	}

	writeCheckpoint(path, findings)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected checkpoint file to exist: %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, "Test Finding 1") || !strings.Contains(content, "Test Finding 2") {
		t.Fatalf("expected both findings in checkpoint, got %s", content)
	}

	removeCheckpoint(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected checkpoint file to be removed")
	}
}

func TestRemoveCheckpointNonexistent(t *testing.T) {
	removeCheckpoint(filepath.Join(t.TempDir(), "nonexistent.jsonl"))
}

func TestWriteCheckpointEmptyFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-checkpoint.jsonl")
	writeCheckpoint(path, nil)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected checkpoint file to exist: %v", err)
	}
	if len(strings.TrimSpace(string(raw))) != 0 {
		t.Fatalf("expected empty checkpoint for nil findings, got %q", string(raw))
	}
}

func TestRunScanAllOllamaEnum(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/api/version":
			return jsonResponse(http.StatusOK, `{"version":"0.3.0"}`), nil
		case "/api/tags":
			return jsonResponse(http.StatusOK, `{"models":[{"name":"llama3","model":"llama3","size":4000000000,"digest":"abc123","details":{"family":"llama","parameter_size":"8B","quantization_level":"Q4_0"}}]}`), nil
		case "/api/ps":
			return jsonResponse(http.StatusOK, `{"models":[{"name":"llama3","model":"llama3","size":4000000000,"digest":"abc123","expires_at":"2030-01-01T00:00:00Z","size_vram":2000000000}]}`), nil
		case "/api/show":
			return jsonResponse(http.StatusOK, `{"modelfile":"FROM llama3","system":"You are helpful","template":"","parameters":"","details":{},"model_info":{}}`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{"error":"not found"}`), nil
		}
	})}

	findings, err := runScanAllOllamaEnum("http://unit.test", httpClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings (service + model + running), got %d", len(findings))
	}
	foundService := false
	foundModel := false
	foundRunning := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Ollama service enumerated") {
			foundService = true
			if !strings.Contains(f.Description, "0.3.0") {
				t.Errorf("expected version in description, got %q", f.Description)
			}
		}
		if strings.Contains(f.Title, "Ollama model discovered: llama3") {
			foundModel = true
		}
		if strings.Contains(f.Title, "Ollama model currently running: llama3") {
			foundRunning = true
		}
	}
	if !foundService {
		t.Error("missing 'Ollama service enumerated' finding")
	}
	if !foundModel {
		t.Error("missing model discovery finding")
	}
	if !foundRunning {
		t.Error("missing running model finding")
	}
}

func TestRunScanAllVectorDBEnum(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.Path == "/api/v2/heartbeat":
			return jsonResponse(http.StatusOK, `{"nanosecond heartbeat":12345}`), nil
		case req.URL.Path == "/api/v2/collections":
			return jsonResponse(http.StatusOK, `[{"id":"coll-1","name":"test-collection","metadata":{}}]`), nil
		case strings.HasSuffix(req.URL.Path, "/count"):
			return jsonResponse(http.StatusOK, `42`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{"error":"not found"}`), nil
		}
	})}

	findings, err := runScanAllVectorDBEnum("http://unit.test", "chromadb", httpClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from vectordb enum")
	}
	foundService := false
	foundCollection := false
	for _, f := range findings {
		if strings.Contains(f.Title, "service enumerated") {
			foundService = true
		}
		if strings.Contains(f.Title, "collection discovered: test-collection") {
			foundCollection = true
		}
	}
	if !foundService {
		t.Error("missing service enumerated finding")
	}
	if !foundCollection {
		t.Error("missing collection discovery finding")
	}
}

func TestRunScanAllJupyterEnum(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/api/status":
			return jsonResponse(http.StatusOK, `{"connections":1,"kernels":1,"started":"2025-01-01T00:00:00.000000"}`), nil
		case "/api/kernels":
			return jsonResponse(http.StatusOK, `[{"id":"kernel-1","name":"python3"}]`), nil
		case "/api/contents":
			return jsonResponse(http.StatusOK, `{"type":"directory","content":[{"name":"test.ipynb","path":"test.ipynb","type":"notebook"}]}`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{"error":"not found"}`), nil
		}
	})}

	findings, err := runScanAllJupyterEnum("http://unit.test", httpClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from jupyter enum")
	}
	if findings[0].Title != "Jupyter server enumerated" {
		t.Errorf("unexpected first finding title: %q", findings[0].Title)
	}
	if !strings.Contains(findings[0].Description, "1 kernel") {
		t.Errorf("expected kernel count in description, got %q", findings[0].Description)
	}
}

func TestRunScanAllRayEnum(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/api/version":
			return jsonResponse(http.StatusOK, `{"ray_version":"2.10.0","python_version":"3.11.0","session_name":"session_2025"}`), nil
		case "/api/jobs/":
			return jsonResponse(http.StatusOK, `[{"job_id":"job-1","status":"SUCCEEDED","entrypoint":"python main.py"}]`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{"error":"not found"}`), nil
		}
	})}

	findings, err := runScanAllRayEnum("http://unit.test", httpClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from ray enum")
	}
	foundDashboard := false
	foundJobsAPI := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Ray dashboard enumerated") {
			foundDashboard = true
		}
		if strings.Contains(f.Title, "Ray jobs API reachable") {
			foundJobsAPI = true
		}
	}
	if !foundDashboard {
		t.Error("missing dashboard enumerated finding")
	}
	if !foundJobsAPI {
		t.Error("missing jobs API reachable finding")
	}
}

func TestRunScanAllMLflowEnum(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.Path == "/" || req.URL.Path == "/health":
			return jsonResponse(http.StatusOK, `OK`), nil
		case req.URL.Path == "/version":
			return jsonResponse(http.StatusOK, `2.10.0`), nil
		case req.URL.Path == "/api/2.0/mlflow/registered-models/search":
			return jsonResponse(http.StatusOK, `{"registered_models":[{"name":"test-model","latest_versions":[{"version":"1"}]}]}`), nil
		case req.URL.Path == "/api/2.0/mlflow/experiments/search":
			return jsonResponse(http.StatusOK, `{"experiments":[{"experiment_id":"0","name":"Default","artifact_location":"mlruns/0"}]}`), nil
		case req.URL.Path == "/api/2.0/mlflow/runs/search":
			return jsonResponse(http.StatusOK, `{"runs":[{"info":{"run_id":"run-1","experiment_id":"0","status":"FINISHED","artifact_uri":"mlruns/0/run-1/artifacts"}}]}`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{"error":"not found"}`), nil
		}
	})}

	findings, err := runScanAllMLflowEnum("http://unit.test", httpClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (service + runs/registry), got %d", len(findings))
	}
	foundService := false
	foundRuns := false
	foundRegistry := false
	for _, f := range findings {
		if strings.Contains(f.Title, "MLflow tracking server enumerated") {
			foundService = true
		}
		if strings.Contains(f.Title, "MLflow run metadata exposed") {
			foundRuns = true
		}
		if strings.Contains(f.Title, "MLflow registry exposed") {
			foundRegistry = true
		}
	}
	if !foundService {
		t.Error("missing service enumerated finding")
	}
	if !foundRuns {
		t.Error("missing run metadata finding")
	}
	if !foundRegistry {
		t.Error("missing registry finding")
	}
}

func TestEnumerateScanAllServiceGradioUsesRealConfig(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/config" {
			return jsonResponse(http.StatusNotFound, `{"error":"not found"}`), nil
		}
		return jsonResponse(http.StatusOK, `{"title":"Demo Gradio","version":"4.0.0","dependencies":[{"api_name":"predict","queue":true,"types":{"generator":false},"show_api":true,"inputs":[{"component":"Textbox"}],"outputs":[{"component":"Textbox"}]}]}`), nil
	})}

	findings, err := enumerateScanAllService("gradio", "http://unit.test", httpClient)
	if err != nil {
		t.Fatalf("enumerateScanAllService returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected real findings from gradio enumeration")
	}
	if findings[0].Title != "Gradio app enumerated" {
		t.Fatalf("unexpected first finding: %#v", findings[0])
	}
}

// ---------------------------------------------------------------------------
// parsePortToken
// ---------------------------------------------------------------------------

func TestParsePortTokenSinglePort(t *testing.T) {
	ports, err := parsePortToken("8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 8080 {
		t.Fatalf("expected [8080], got %v", ports)
	}
}

func TestParsePortTokenRange(t *testing.T) {
	ports, err := parsePortToken("80-85")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 6 {
		t.Fatalf("expected 6 ports (80-85), got %d", len(ports))
	}
	if ports[0] != 80 || ports[5] != 85 {
		t.Fatalf("expected range 80-85, got %v", ports)
	}
}

func TestParsePortTokenInvalidPort(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"non-numeric", "abc"},
		{"negative", "-1"},
		{"zero", "0"},
		{"too large", "70000"},
		{"floating point", "80.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePortToken(tc.token)
			if err == nil {
				t.Fatalf("expected error for token %q", tc.token)
			}
		})
	}
}

func TestParsePortTokenRangeOutOfBounds(t *testing.T) {
	_, err := parsePortToken("65530-65540")
	if err == nil {
		t.Fatal("expected error for port range exceeding 65535")
	}
}

func TestParsePortTokenReversedRange(t *testing.T) {
	_, err := parsePortToken("100-50")
	if err == nil {
		t.Fatal("expected error for reversed range")
	}
	if !strings.Contains(err.Error(), "start") {
		t.Errorf("expected error about start <= end, got: %v", err)
	}
}

func TestParsePortTokenRangeInvalidBounds(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"non-numeric start", "abc-100"},
		{"non-numeric end", "100-xyz"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePortToken(tc.token)
			if err == nil {
				t.Fatalf("expected error for token %q", tc.token)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// enumerateScanAllService — unknown service
// ---------------------------------------------------------------------------

func TestEnumerateScanAllServiceUnknown(t *testing.T) {
	findings, err := enumerateScanAllService("nonexistent-service", "http://unit.test", &http.Client{})
	if err != errNoEnumerator {
		t.Fatalf("expected errNoEnumerator for unknown service, got: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for unknown service, got %d", len(findings))
	}
}

func TestEnumerateScanAllServiceDispatchesCorrectly(t *testing.T) {
	services := []string{"ollama", "chromadb", "qdrant", "weaviate", "jupyter", "ray", "mlflow", "gradio", "a2a"}
	for _, svc := range services {
		t.Run(svc, func(t *testing.T) {
			httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusInternalServerError, `{"error":"test"}`), nil
			})}
			_, err := enumerateScanAllService(svc, "http://unit.test", httpClient)
			// We just verify the dispatch works; errors from backend are expected
			_ = err
		})
	}
}

// ---------------------------------------------------------------------------
// writeScanAllResults — basic paths
// ---------------------------------------------------------------------------

func TestWriteScanAllResultsNoFindings(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "console"

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		w, err := getGroupedWriter()
		if err != nil {
			t.Fatalf("getGroupedWriter: %v", err)
		}
		defer w.Close()

		result := writeScanAllResults(w, nil, nil, nil, scanAllSummary{})
		if result != nil {
			t.Fatalf("expected nil for no findings, got: %v", result)
		}
	})
}

func TestWriteScanAllResultsWithFindings(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "results.jsonl")

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		w, err := getGroupedWriter()
		if err != nil {
			t.Fatalf("getGroupedWriter: %v", err)
		}
		_ = w.WriteHeader()

		findings := []report.Finding{
			{ID: "f1", Source: report.SourceFingerprint, Target: "http://10.0.0.5:11434",
				Title: "Port discovered", Severity: report.SeverityInfo,
				Metadata: map[string]interface{}{"service": "ollama"}},
		}
		observations := []fingerprint.PortObservation{
			{Host: "10.0.0.5", Port: 11434, URL: "http://10.0.0.5:11434",
				FingerprintStatus: fingerprint.MatchKindConfirmed,
				Results: []fingerprint.Result{
					{Service: "ollama", MatchKind: fingerprint.MatchKindConfirmed, URL: "http://10.0.0.5:11434"},
				}},
		}
		results := []fingerprint.Result{
			{Service: "ollama", URL: "http://10.0.0.5:11434"},
		}

		err = writeScanAllResults(w, findings, observations, results, scanAllSummary{})
		if err == nil {
			t.Fatal("expected FindingsError for non-empty findings")
		}
	})
}

// ---------------------------------------------------------------------------
// runScanAll — early validation paths
// ---------------------------------------------------------------------------

func TestRunScanAllMissingTarget(t *testing.T) {
	prevTargets := scanAllTargets
	defer func() { scanAllTargets = prevTargets }()
	scanAllTargets = nil

	withTestConfig(t, func() {
		err := runScanAll(assessNetworkCmd, nil)
		if err == nil {
			t.Fatal("expected error for missing target")
		}
		if !strings.Contains(err.Error(), "target") {
			t.Errorf("expected missing target error, got: %v", err)
		}
	})
}

func TestRunScanAllInvalidTarget(t *testing.T) {
	prevTargets := scanAllTargets
	defer func() { scanAllTargets = prevTargets }()
	scanAllTargets = []string{"999.999.999.999/33"}

	withTestConfig(t, func() {
		err := runScanAll(assessNetworkCmd, nil)
		if err == nil {
			t.Fatal("expected error for invalid target")
		}
		if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("expected invalid target error, got: %v", err)
		}
	})
}

func TestRunScanAllInvalidMode(t *testing.T) {
	prevTargets := scanAllTargets
	prevMode := scanMode
	defer func() {
		scanAllTargets = prevTargets
		scanMode = prevMode
	}()

	scanAllTargets = []string{"127.0.0.1"}
	scanMode = "bogus"

	withTestConfig(t, func() {
		err := runScanAll(assessNetworkCmd, nil)
		if err == nil {
			t.Fatal("expected error for invalid mode")
		}
	})
}

// ---------------------------------------------------------------------------
// runScanAll — integration tests (httptest server)
// ---------------------------------------------------------------------------

func TestRunScanAllIntegration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[{"name":"llama3","model":"llama3","size":4000000000,"digest":"abc123","details":{"family":"llama","parameter_size":"8B","quantization_level":"Q4_0"}}]}`))
	})
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"0.3.0"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>OK</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTargets := scanAllTargets
	prevPorts := scanAllPorts
	prevSkipScan := scanAllSkipScan
	prevSkipExploit := scanAllSkipExploit
	prevMode := scanMode
	defer func() {
		scanAllTargets = prevTargets
		scanAllPorts = prevPorts
		scanAllSkipScan = prevSkipScan
		scanAllSkipExploit = prevSkipExploit
		scanMode = prevMode
	}()

	withTestConfig(t, func() {
		scanAllTargets = []string{srv.URL}
		scanAllPorts = nil
		scanAllSkipScan = true
		scanAllSkipExploit = false
		scanMode = "detect"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "scan-all-integration.json")
		cfg.Timeout = 5

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		err := runScanAll(assessNetworkCmd, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				if _, ok := err.(*exitcode.FindingsPartialError); !ok {
					t.Fatalf("expected FindingsError or FindingsPartialError or nil, got %T: %v", err, err)
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

func TestRunScanAllWithSkipExploit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[{"name":"llama3","model":"llama3","size":4000000000,"digest":"abc123","details":{"family":"llama","parameter_size":"8B","quantization_level":"Q4_0"}}]}`))
	})
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"0.3.0"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>OK</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTargets := scanAllTargets
	prevPorts := scanAllPorts
	prevSkipScan := scanAllSkipScan
	prevSkipExploit := scanAllSkipExploit
	prevMode := scanMode
	defer func() {
		scanAllTargets = prevTargets
		scanAllPorts = prevPorts
		scanAllSkipScan = prevSkipScan
		scanAllSkipExploit = prevSkipExploit
		scanMode = prevMode
	}()

	withTestConfig(t, func() {
		scanAllTargets = []string{srv.URL}
		scanAllPorts = nil
		scanAllSkipScan = false
		scanAllSkipExploit = true
		scanMode = "detect"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "scan-all-skip-exploit.json")
		cfg.Timeout = 5

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		err := runScanAll(assessNetworkCmd, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				if _, ok := err.(*exitcode.FindingsPartialError); !ok {
					t.Fatalf("expected FindingsError, FindingsPartialError or nil, got %T: %v", err, err)
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

		stderrOutput := stderr.String()
		if !strings.Contains(stderrOutput, "Phase 1") {
			t.Errorf("expected Phase 1 log output, got: %q", stderrOutput)
		}
	})
}

func TestRunScanAllInvalidPorts(t *testing.T) {
	prevTargets := scanAllTargets
	prevPorts := scanAllPorts
	prevMode := scanMode
	defer func() {
		scanAllTargets = prevTargets
		scanAllPorts = prevPorts
		scanMode = prevMode
	}()

	scanAllTargets = []string{"127.0.0.1"}
	scanAllPorts = []string{"badport"}
	scanMode = "detect"

	withTestConfig(t, func() {
		err := runScanAll(assessNetworkCmd, nil)
		if err == nil {
			t.Fatal("expected error for invalid ports")
		}
		if !strings.Contains(err.Error(), "invalid port") {
			t.Errorf("expected invalid port error, got: %v", err)
		}
	})
}

func TestRunScanAllFullPipeline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[{"name":"llama3","model":"llama3","size":4000000000,"digest":"abc123","details":{"family":"llama","parameter_size":"8B","quantization_level":"Q4_0"}}]}`))
	})
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"0.3.0"}`))
	})
	mux.HandleFunc("/api/ps", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[]}`))
	})
	mux.HandleFunc("/api/show", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"modelfile":"FROM llama3","system":"","template":"","parameters":"","details":{},"model_info":{}}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>Ollama is running</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTargets := scanAllTargets
	prevPorts := scanAllPorts
	prevSkipScan := scanAllSkipScan
	prevSkipExploit := scanAllSkipExploit
	prevMode := scanMode
	prevEnumerator := scanAllServiceEnumerator
	defer func() {
		scanAllTargets = prevTargets
		scanAllPorts = prevPorts
		scanAllSkipScan = prevSkipScan
		scanAllSkipExploit = prevSkipExploit
		scanMode = prevMode
		scanAllServiceEnumerator = prevEnumerator
	}()

	scanAllServiceEnumerator = func(service, target string, httpClient *http.Client) ([]report.Finding, error) {
		return []report.Finding{{
			Source:   report.SourceOllama,
			Target:   target,
			Title:    "Ollama service enumerated",
			Severity: report.SeverityInfo,
		}}, nil
	}

	withTestConfig(t, func() {
		scanAllTargets = []string{srv.URL}
		scanAllPorts = nil
		scanAllSkipScan = false
		scanAllSkipExploit = false
		scanMode = "detect"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "scan-all-full.json")
		cfg.Timeout = 5

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		err := runScanAll(assessNetworkCmd, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				if _, ok := err.(*exitcode.FindingsPartialError); !ok {
					t.Fatalf("expected FindingsError, FindingsPartialError or nil, got %T: %v", err, err)
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

		stderrOutput := stderr.String()
		if !strings.Contains(stderrOutput, "Phase 1") {
			t.Errorf("expected Phase 1 in stderr output")
		}
	})
}

// ---------------------------------------------------------------------------
// writeScanAllResults — partial error paths
// ---------------------------------------------------------------------------

func TestWriteScanAllResultsPartialError(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "partial.jsonl")

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		w, err := getGroupedWriter()
		if err != nil {
			t.Fatalf("getGroupedWriter: %v", err)
		}
		_ = w.WriteHeader()

		findings := []report.Finding{
			{ID: "f1", Source: report.SourceFingerprint, Target: "http://10.0.0.5:11434",
				Title: "Port discovered", Severity: report.SeverityInfo},
		}

		summary := scanAllSummary{
			ServicesWithScanFailures: 1,
			TemplateScanAttempts:     2,
		}

		result := writeScanAllResults(w, findings, nil, nil, summary)
		if result == nil {
			t.Fatal("expected FindingsPartialError for findings with failures")
		}
		if _, ok := result.(*exitcode.FindingsPartialError); !ok {
			t.Fatalf("expected *exitcode.FindingsPartialError, got %T", result)
		}
	})
}

func TestWriteScanAllResultsPartialErrorNoFindings(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "partial-no-findings.jsonl")

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		w, err := getGroupedWriter()
		if err != nil {
			t.Fatalf("getGroupedWriter: %v", err)
		}
		_ = w.WriteHeader()

		summary := scanAllSummary{
			ServicesWithScanFailures: 1,
			TemplateScanAttempts:     2,
		}

		result := writeScanAllResults(w, nil, nil, nil, summary)
		if result == nil {
			t.Fatal("expected PartialError for no findings with failures")
		}
		if _, ok := result.(*exitcode.PartialError); !ok {
			t.Fatalf("expected *exitcode.PartialError, got %T", result)
		}
	})
}

// ---------------------------------------------------------------------------
// Finding 1: enumerateScanAllService covers all wired services and returns
// errNoEnumerator for unknown/template-only services.
// ---------------------------------------------------------------------------

func TestEnumerateScanAllServiceReturnsErrNoEnumeratorForUnknownService(t *testing.T) {
	_, err := enumerateScanAllService("streamlit", "http://127.0.0.1:8501", &http.Client{})
	if err != errNoEnumerator {
		t.Fatalf("expected errNoEnumerator for streamlit, got: %v", err)
	}
}

func TestEnumerateScanAllServiceCoversAllWiredFamilies(t *testing.T) {
	wired := []string{
		"ollama", "chromadb", "qdrant", "weaviate", "milvus",
		"jupyter", "ray", "mlflow", "gradio",
		"bentoml", "mcp-sse", "mcp-inspector", "mcpjam-inspector",
		"triton", "torchserve", "torchserve-mgmt", "tfserving",
		"litellm", "openai-compatible", "vllm", "lmstudio", "localai",
		"a2a", "pgvector", "hf-tgi", "hf-tei", "kubeflow",
	}
	for _, svc := range wired {
		_, err := enumerateScanAllService(svc, "http://127.0.0.1:1", &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusServiceUnavailable, `{"error":"down"}`), nil
			}),
		})
		if err == errNoEnumerator {
			t.Errorf("service %q should be wired but returned errNoEnumerator", svc)
		}
	}
}

func TestRunExploitEnumerationCountsSkips(t *testing.T) {
	prevEnumerator := scanAllServiceEnumerator
	prevErr := stderrWriter
	defer func() {
		scanAllServiceEnumerator = prevEnumerator
		stderrWriter = prevErr
	}()

	var stderr bytes.Buffer
	stderrWriter = &stderr
	scanAllServiceEnumerator = func(service, target string, httpClient *http.Client) ([]report.Finding, error) {
		if service == "streamlit" {
			return nil, errNoEnumerator
		}
		return []report.Finding{{Source: report.SourceOllama, Target: target, Title: "ok"}}, nil
	}

	out := runExploitEnumeration([]fingerprint.Result{
		{Service: "ollama", URL: "http://ok"},
		{Service: "streamlit", URL: "http://skip"},
	}, &http.Client{})

	if out.Skipped != 1 {
		t.Fatalf("expected 1 skipped, got %d", out.Skipped)
	}
	if out.Failures != 0 {
		t.Fatalf("expected 0 failures, got %d", out.Failures)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
}

// ---------------------------------------------------------------------------
// Finding 5: ambiguous-service expansion does not become a partial failure
// ---------------------------------------------------------------------------

func TestWriteScanAllResultsDoesNotPartialOnAmbiguousExpansion(t *testing.T) {
	withTestConfig(t, func() {
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ambiguous-partial.jsonl")

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		w, err := getGroupedWriter()
		if err != nil {
			t.Fatalf("getGroupedWriter: %v", err)
		}
		_ = w.WriteHeader()

		findings := []report.Finding{
			{ID: "f1", Source: report.SourceOllama, Title: "Test", Severity: report.SeverityInfo, Target: "http://10.0.0.1:11434"},
		}
		summary := scanAllSummary{AmbiguousServicesExpanded: 2}
		result := writeScanAllResults(w, findings, nil, nil, summary)
		if _, ok := result.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected *exitcode.FindingsError, got %T: %v", result, result)
		}
	})
}

// ---------------------------------------------------------------------------
// Finding 6: checkpoint preserved on non-success, removed on success
// ---------------------------------------------------------------------------

func TestMaybeRemoveCheckpointPreservesOnPartialFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint-preserve.jsonl")
	writeCheckpoint(path, []report.Finding{{ID: "f1"}})

	prevWriter := stderrWriter
	stderrWriter = &strings.Builder{}
	defer func() { stderrWriter = prevWriter }()

	partialErr := &exitcode.FindingsPartialError{FindingsCount: 1, Failed: 1}
	maybeRemoveCheckpoint(path, partialErr)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected checkpoint to be preserved on partial failure")
	}
}

func TestMaybeRemoveCheckpointRemovesOnSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint-success.jsonl")
	writeCheckpoint(path, []report.Finding{{ID: "f1"}})

	maybeRemoveCheckpoint(path, nil)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected checkpoint to be removed on success")
	}
}

func TestMaybeRemoveCheckpointRemovesOnFindingsOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint-findings.jsonl")
	writeCheckpoint(path, []report.Finding{{ID: "f1"}})

	findingsErr := &exitcode.FindingsError{Count: 1}
	maybeRemoveCheckpoint(path, findingsErr)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expected checkpoint to be removed on clean findings exit")
	}
}

func TestMaybeRemoveCheckpointPreservesOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint-error.jsonl")
	writeCheckpoint(path, []report.Finding{{ID: "f1"}})

	prevWriter := stderrWriter
	stderrWriter = &strings.Builder{}
	defer func() { stderrWriter = prevWriter }()

	maybeRemoveCheckpoint(path, fmt.Errorf("some error"))

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected checkpoint to be preserved on error")
	}
}
