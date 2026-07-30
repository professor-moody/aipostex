package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
)

func TestRunBentoEnumAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "iris-classifier", "version": "1.0.0",
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/docs.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"paths": map[string]any{
				"/predict": map[string]any{
					"post": map[string]any{"summary": "Run prediction"},
				},
			},
		})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# HELP bentoml_request_total\nbentoml_request_total 42\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := bentoTarget
	defer func() { bentoTarget = prev }()

	withTestConfig(t, func() {
		bentoTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "bento-enum.json")

		err := runBentoEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "BentoML service enumerated") {
			t.Fatalf("expected enum finding, got %s", content)
		}
		if !strings.Contains(content, "iris-classifier") {
			t.Fatalf("expected service name in output, got %s", content)
		}
	})
}

func TestRunBentoRoutesAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/docs.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"paths": map[string]any{
				"/classify": map[string]any{
					"post": map[string]any{
						"summary": "Classify input",
						"requestBody": map[string]any{
							"content": map[string]any{
								"application/json": map[string]any{
									"schema": map[string]any{
										"type":     "object",
										"required": []any{"instances"},
										"properties": map[string]any{
											"instances": map[string]any{
												"type":  "array",
												"items": map[string]any{"type": "string"},
											},
										},
									},
								},
							},
						},
					},
				},
				"/healthz": map[string]any{
					"get": map[string]any{"summary": "Health check"},
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := bentoTarget
	defer func() { bentoTarget = prev }()

	withTestConfig(t, func() {
		bentoTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "bento-routes.json")

		err := runBentoRoutes(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "/classify") || !strings.Contains(content, "/healthz") {
			t.Fatalf("expected both routes in output, got %s", content)
		}
		if !strings.Contains(content, "predict --endpoint /classify") || !strings.Contains(content, "\\\"instances\\\"") {
			t.Fatalf("expected route workflow to carry concrete classify payload, got %s", content)
		}
	})
}

func TestRunBentoPredictAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/predict", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		confidence := 0.95
		if strings.Contains(string(body), "aipxq") {
			confidence = 0.51
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": "setosa", "confidence": confidence})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := bentoTarget
	prevEndpoint := bentoEndpoint
	prevPayload := bentoPayload
	defer func() {
		bentoTarget = prevTarget
		bentoEndpoint = prevEndpoint
		bentoPayload = prevPayload
	}()

	withTestConfig(t, func() {
		bentoTarget = srv.URL
		bentoEndpoint = "/predict"
		bentoPayload = `{"input":"test"}`
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "bento-predict.json")

		err := runBentoPredict(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "input-dependent inference verified") {
			t.Fatalf("expected verified inference finding in output, got %s", string(raw))
		}
		out := string(raw)
		if !strings.Contains(out, `"inference_verified":true`) {
			t.Fatalf("expected verified inference, got %s", out)
		}
		if !strings.Contains(out, `"landed":"execution-confirmed"`) {
			t.Fatalf("expected execution-confirmed inference, got %s", out)
		}
	})
}

func TestRunBentoMetricsAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# HELP bentoml_request_total\nbentoml_request_total 100\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := bentoTarget
	defer func() { bentoTarget = prev }()

	withTestConfig(t, func() {
		bentoTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "bento-metrics.json")

		err := runBentoMetrics(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "metrics") {
			t.Fatalf("expected metrics finding in output, got %s", string(raw))
		}
	})
}

func TestNewBentoClientRequiresTarget(t *testing.T) {
	prev := bentoTarget
	defer func() { bentoTarget = prev }()
	bentoTarget = ""

	_, _, err := newBentoClient()
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("expected missing target error, got %v", err)
	}
}

func TestRunBentoPredictMissingPayload(t *testing.T) {
	prevTarget, prevPayload, prevForce := bentoTarget, bentoPayload, cfg.ForceExploit
	defer func() { bentoTarget, bentoPayload, cfg.ForceExploit = prevTarget, prevPayload, prevForce }()
	withTestConfig(t, func() {
		bentoTarget = "http://127.0.0.1:3000"
		bentoPayload = ""
		cfg.ForceExploit = true
		err := runBentoPredict(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "payload") {
			t.Fatalf("expected missing payload error, got %v", err)
		}
	})
}

func TestRunBentoPredictRequiresForceExploit(t *testing.T) {
	prevTarget, prevPayload, prevForce := bentoTarget, bentoPayload, cfg.ForceExploit
	defer func() { bentoTarget, bentoPayload, cfg.ForceExploit = prevTarget, prevPayload, prevForce }()
	withTestConfig(t, func() {
		bentoTarget = "http://127.0.0.1:3000"
		bentoPayload = `{"x":1}`
		cfg.ForceExploit = false
		err := runBentoPredict(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "force") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}
