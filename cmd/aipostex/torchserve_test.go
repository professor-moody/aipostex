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

func TestRunTSEnumAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"Healthy"}`))
	})
	mux.HandleFunc("/models", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{"modelName": "resnet-18", "status": "READY"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tsTarget
	prevInference := tsInferenceURL
	defer func() {
		tsTarget = prev
		tsInferenceURL = prevInference
	}()

	withTestConfig(t, func() {
		tsTarget = srv.URL
		tsInferenceURL = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-enum.json")

		err := runTSEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "TorchServe service enumerated") {
			t.Fatalf("expected enum finding, got %s", content)
		}
		if !strings.Contains(content, "resnet-18") {
			t.Fatalf("expected model name in output, got %s", content)
		}
		// The Next-Actions follow-on command must thread the discovered model
		// name in, not emit a bare <model> placeholder.
		if !strings.Contains(content, "models --model resnet-18") {
			t.Fatalf("expected follow-on command to thread discovered model, got %s", content)
		}
		if strings.Contains(content, "<model>") {
			t.Fatalf("follow-on command must not emit a bare <model> placeholder, got %s", content)
		}
	})
}

func TestRunTSModelsAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/models", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{"modelName": "bert", "status": "READY"},
				{"modelName": "gpt2", "status": "READY"},
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
		tsModel = ""
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-models.json")

		err := runTSModels(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "bert") || !strings.Contains(content, "gpt2") {
			t.Fatalf("expected both models in output, got %s", content)
		}
	})
}

func TestRunTSPredictAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/predictions/resnet", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"class": "cat", "probability": 0.9})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tsTarget
	prevModel := tsModel
	prevPayload := tsPayload
	prevInference := tsInferenceURL
	defer func() {
		tsTarget = prev
		tsModel = prevModel
		tsPayload = prevPayload
		tsInferenceURL = prevInference
	}()

	withTestConfig(t, func() {
		tsTarget = srv.URL
		tsInferenceURL = srv.URL
		tsModel = "resnet"
		tsPayload = `{"data":"test"}`
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-predict.json")

		err := runTSPredict(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "prediction") {
			t.Fatalf("expected prediction finding, got %s", string(raw))
		}
	})
}

func TestRunTSRegisterAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/models", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"Model registered"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tsTarget
	prevModelURL := tsModelURL
	prevModel := tsModel
	prevPayload := tsPayload
	prevInitialWorkers := tsInitialWorkers
	defer func() {
		tsTarget = prev
		tsModelURL = prevModelURL
		tsModel = prevModel
		tsPayload = prevPayload
		tsInitialWorkers = prevInitialWorkers
	}()

	withTestConfig(t, func() {
		tsTarget = srv.URL
		tsModelURL = "http://attacker.com/test.mar"
		tsModel = ""
		tsPayload = ""
		tsInitialWorkers = 1
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-register.json")

		err := runTSRegister(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "ShellTorch") {
			t.Fatalf("expected ShellTorch in output, got %s", string(raw))
		}
		// 0B: a 2xx registration without out-of-band SSRF confirmation must be
		// labeled influenced (not execution-confirmed) and flagged
		// unverified, so the report does not claim a confirmed SSRF.
		if !strings.Contains(string(raw), "influenced") {
			t.Fatalf("expected influenced label for unverified register, got %s", string(raw))
		}
		if strings.Contains(string(raw), "execution-confirmed") {
			t.Fatalf("unverified register must not claim execution-confirmed: %s", string(raw))
		}
		if !strings.Contains(string(raw), "unverified") {
			t.Fatalf("expected the finding to flag SSRF as unverified, got %s", string(raw))
		}
	})
}

func TestRunTSRegisterVerifiesHandlerAgainstMockServer(t *testing.T) {
	registered := false
	mux := http.NewServeMux()
	mux.HandleFunc("/models", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if got := r.URL.Query().Get("url"); got != "http://attacker.com/aipostex.mar" {
			t.Fatalf("expected model URL query, got %q", got)
		}
		if got := r.URL.Query().Get("model_name"); got != "aipostex-handler" {
			t.Fatalf("expected model_name query, got %q", got)
		}
		if got := r.URL.Query().Get("initial_workers"); got != "1" {
			t.Fatalf("expected initial_workers=1, got %q", got)
		}
		if got := r.URL.Query().Get("synchronous"); got != "true" {
			t.Fatalf("expected synchronous=true, got %q", got)
		}
		registered = true
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "Model registered"})
	})
	mux.HandleFunc("/models/aipostex-handler", func(w http.ResponseWriter, r *http.Request) {
		if !registered {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"modelName":    "aipostex-handler",
			"modelVersion": "1.0",
			"status":       "READY",
			"runtime":      "python",
			"handler":      "aipostex_handler.handle",
			"minWorkers":   1,
			"maxWorkers":   1,
		}})
	})
	mux.HandleFunc("/predictions/aipostex-handler", func(w http.ResponseWriter, r *http.Request) {
		if !registered {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Input-dependent output: echo the request data so a mutated probe input
		// yields a distinct response, which the inference reality probe requires
		// before claiming own/execution-confirmed.
		body, _ := io.ReadAll(r.Body)
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"handler_executed": true,
			"model":            "aipostex-handler",
			"echo":             in["data"],
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tsTarget
	prevModelURL := tsModelURL
	prevModel := tsModel
	prevPayload := tsPayload
	prevInference := tsInferenceURL
	prevInitialWorkers := tsInitialWorkers
	defer func() {
		tsTarget = prev
		tsModelURL = prevModelURL
		tsModel = prevModel
		tsPayload = prevPayload
		tsInferenceURL = prevInference
		tsInitialWorkers = prevInitialWorkers
	}()

	withTestConfig(t, func() {
		tsTarget = srv.URL
		tsInferenceURL = srv.URL
		tsModelURL = "http://attacker.com/aipostex.mar"
		tsModel = "aipostex-handler"
		tsPayload = `{"data":"run"}`
		tsInitialWorkers = 1
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-register-handler.json")

		err := runTSRegister(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "registered model handler executed") {
			t.Fatalf("expected handler execution title, got %s", content)
		}
		if !strings.Contains(content, `"handler_verified":true`) {
			t.Fatalf("expected handler_verified metadata, got %s", content)
		}
		if !strings.Contains(content, `"stage":"own"`) || !strings.Contains(content, `"landed":"execution-confirmed"`) {
			t.Fatalf("expected own/execution-confirmed, got %s", content)
		}
	})
}

// TestRunTSRegisterCannedHandlerStaysInfluenced proves the honesty guardrail: a
// registered model whose predict endpoint returns a canned (input-independent)
// response must NOT reach own/execution-confirmed — the inference reality probe
// sees identical output for distinct inputs and caps the finding at impact/influenced.
func TestRunTSRegisterCannedHandlerStaysInfluenced(t *testing.T) {
	registered := false
	mux := http.NewServeMux()
	mux.HandleFunc("/models", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		registered = true
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "Model registered"})
	})
	mux.HandleFunc("/models/aipostex-handler", func(w http.ResponseWriter, r *http.Request) {
		if !registered {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"modelName": "aipostex-handler", "status": "READY", "handler": "aipostex_handler.handle",
		}})
	})
	mux.HandleFunc("/predictions/aipostex-handler", func(w http.ResponseWriter, r *http.Request) {
		if !registered {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Canned response: identical regardless of input — a fixture, not real inference.
		_ = json.NewEncoder(w).Encode(map[string]any{"handler_executed": true})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tsTarget
	prevModelURL := tsModelURL
	prevModel := tsModel
	prevPayload := tsPayload
	prevInference := tsInferenceURL
	prevInitialWorkers := tsInitialWorkers
	defer func() {
		tsTarget = prev
		tsModelURL = prevModelURL
		tsModel = prevModel
		tsPayload = prevPayload
		tsInferenceURL = prevInference
		tsInitialWorkers = prevInitialWorkers
	}()

	withTestConfig(t, func() {
		tsTarget = srv.URL
		tsInferenceURL = srv.URL
		tsModelURL = "http://attacker.com/aipostex.mar"
		tsModel = "aipostex-handler"
		tsPayload = `{"data":"run"}`
		tsInitialWorkers = 1
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-register-canned.json")

		err := runTSRegister(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if strings.Contains(content, `"handler_verified":true`) {
			t.Fatalf("canned handler must not be handler_verified: %s", content)
		}
		if strings.Contains(content, `"stage":"own"`) || strings.Contains(content, `"landed":"execution-confirmed"`) {
			t.Fatalf("canned handler must not reach own/execution-confirmed: %s", content)
		}
		if !strings.Contains(content, `"landed":"influenced"`) {
			t.Fatalf("registration-accepted-with-canned-predict should stay influenced: %s", content)
		}
		if !strings.Contains(content, `"handler_input_dependent":false`) {
			t.Fatalf("expected handler_input_dependent:false metadata, got %s", content)
		}
	})
}

func TestRunTSScaleAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/models/resnet", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"Workers scaled"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tsTarget
	prevModel := tsModel
	prevWorkers := tsMinWorkers
	defer func() {
		tsTarget = prev
		tsModel = prevModel
		tsMinWorkers = prevWorkers
	}()

	withTestConfig(t, func() {
		tsTarget = srv.URL
		tsModel = "resnet"
		tsMinWorkers = 2
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-scale.json")

		err := runTSScale(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "scale") {
			t.Fatalf("expected scale finding, got %s", string(raw))
		}
	})
}

func TestRunTSUnregisterAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/models/resnet", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"Model unregistered"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
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
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-unreg.json")

		err := runTSUnregister(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "unregister") {
			t.Fatalf("expected unregister finding, got %s", string(raw))
		}
	})
}

func TestRunTSMetricsAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# HELP ts_inference_requests_total\nts_inference_requests_total 500\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tsTarget
	prevMetrics := tsMetricsURL
	defer func() {
		tsTarget = prev
		tsMetricsURL = prevMetrics
	}()

	withTestConfig(t, func() {
		tsTarget = srv.URL
		tsMetricsURL = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ts-metrics.json")

		err := runTSMetrics(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "metrics") {
			t.Fatalf("expected metrics finding, got %s", string(raw))
		}
	})
}
