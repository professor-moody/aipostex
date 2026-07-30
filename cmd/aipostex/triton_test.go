package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
)

func TestRunTritonEnumAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "triton", "version": "2.40.0",
			"extensions": []string{"classification", "sequence"},
		})
	})
	mux.HandleFunc("/v2/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/models", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{"name": "resnet50", "version": "1", "state": "READY"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tritonTarget
	defer func() { tritonTarget = prev }()

	withTestConfig(t, func() {
		tritonTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "triton-enum.json")

		err := runTritonEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "Triton Inference Server enumerated") {
			t.Fatalf("expected enum finding, got %s", content)
		}
		if !strings.Contains(content, "2.40.0") {
			t.Fatalf("expected version in output, got %s", content)
		}
	})
}

func TestRunTritonModelsAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	// Correct KServe contract: model listing is POST /v2/repository/index,
	// returning a JSON array (not GET /v2/models, which Triton does not serve).
	mux.HandleFunc("/v2/repository/index", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "bert-base", "version": "1", "state": "READY"},
			{"name": "gpt2", "version": "1", "state": "READY"},
		})
	})
	mux.HandleFunc("/v2/models/bert-base", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "bert-base", "version": "1", "platform": "pytorch_libtorch",
		})
	})
	mux.HandleFunc("/v2/models/gpt2", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "gpt2", "version": "1", "platform": "onnxruntime_onnx",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tritonTarget
	defer func() { tritonTarget = prev }()

	withTestConfig(t, func() {
		tritonTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "triton-models.json")

		err := runTritonModels(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "bert-base") || !strings.Contains(content, "gpt2") {
			t.Fatalf("expected both models in output, got %s", content)
		}
		// The follow-on plan must thread a discovered model into the gated infer
		// command instead of emitting a bare "<model>" placeholder.
		if !strings.Contains(content, "infer --model bert-base") {
			t.Fatalf("expected discovered model threaded into infer follow-on, got %s", content)
		}
		if !strings.Contains(content, "model-config --model bert-base") {
			t.Fatalf("expected discovered model threaded into model-config follow-on, got %s", content)
		}
		if strings.Contains(content, "infer --model <model>") {
			t.Fatalf("models plan must not emit a <model> placeholder in the infer command, got %s", content)
		}
	})
}

// TestRunTritonEnumWorkflowPlanNoModelPlaceholder asserts the enum plan — which
// has no model name in scope — does not emit a gated infer command carrying a
// "<model>" placeholder. Model discovery happens in the models step, so enum stops
// at listing models rather than emitting an unfillable exploit command.
func TestRunTritonEnumWorkflowPlanNoModelPlaceholder(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "triton", "version": "2.40.0",
		})
	})
	mux.HandleFunc("/v2/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tritonTarget
	defer func() { tritonTarget = prev }()

	withTestConfig(t, func() {
		tritonTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "triton-enum-plan.json")

		err := runTritonEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if strings.Contains(content, "<model>") {
			t.Fatalf("enum plan must not emit a <model> placeholder, got %s", content)
		}
		if !strings.Contains(content, "triton --target "+srv.URL+" models") {
			t.Fatalf("expected enum plan to recommend the models step, got %s", content)
		}
	})
}

func TestRunTritonModelConfigAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/models/resnet50/config", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "resnet50", "platform": "pytorch_libtorch", "backend": "pytorch",
			"instance_group": []map[string]any{
				{"kind": "KIND_GPU", "count": 1},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tritonTarget
	prevModel := tritonModel
	defer func() {
		tritonTarget = prev
		tritonModel = prevModel
	}()

	withTestConfig(t, func() {
		tritonTarget = srv.URL
		tritonModel = "resnet50"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "triton-config.json")

		err := runTritonModelConfig(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "resnet50") {
			t.Fatalf("expected model name in output, got %s", string(raw))
		}
	})
}

func TestRunTritonInferAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/models/resnet50/infer", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model_name": "resnet50",
			"outputs":    []map[string]any{{"name": "output", "data": []float64{0.1, 0.9}}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tritonTarget
	prevModel := tritonModel
	prevPayload := tritonPayload
	defer func() {
		tritonTarget = prev
		tritonModel = prevModel
		tritonPayload = prevPayload
	}()

	withTestConfig(t, func() {
		tritonTarget = srv.URL
		tritonModel = "resnet50"
		tritonPayload = `{"inputs":[]}`
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "triton-infer.json")

		err := runTritonInfer(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "inference") {
			t.Fatalf("expected inference finding, got %s", string(raw))
		}
	})
}

func TestRunTritonModelLoadAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/repository/models/test-model/load", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tritonTarget
	prevModel := tritonModel
	prevPayload := tritonPayload
	defer func() {
		tritonTarget = prev
		tritonModel = prevModel
		tritonPayload = prevPayload
	}()

	withTestConfig(t, func() {
		tritonTarget = srv.URL
		tritonModel = "test-model"
		tritonPayload = ""
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "triton-load.json")

		err := runTritonModelLoad(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "model load") {
			t.Fatalf("expected model load finding, got %s", string(raw))
		}
	})
}

func TestRunTritonModelLoadVerifiesInference(t *testing.T) {
	loaded := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/repository/models/aipostex-injected/load", func(w http.ResponseWriter, _ *http.Request) {
		loaded = true
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v2/models/aipostex-injected", func(w http.ResponseWriter, _ *http.Request) {
		if !loaded {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":     "aipostex-injected",
			"version":  "1",
			"state":    "READY",
			"platform": "onnxruntime_onnx",
			"inputs":   []map[string]any{{"name": "INPUT0", "datatype": "FP32", "shape": []int{1, 1}}},
			"outputs":  []map[string]any{{"name": "OUTPUT0", "datatype": "FP32", "shape": []int{1, 1}}},
		})
	})
	mux.HandleFunc("/v2/models/aipostex-injected/infer", func(w http.ResponseWriter, _ *http.Request) {
		if !loaded {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model_name": "aipostex-injected",
			"outputs":    []map[string]any{{"name": "OUTPUT0", "datatype": "FP32", "shape": []int{1, 1}, "data": []float64{1.0}}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tritonTarget
	prevModel := tritonModel
	prevPayload := tritonPayload
	defer func() {
		tritonTarget = prev
		tritonModel = prevModel
		tritonPayload = prevPayload
	}()

	withTestConfig(t, func() {
		tritonTarget = srv.URL
		tritonModel = "aipostex-injected"
		tritonPayload = `{"inputs":[{"name":"INPUT0","datatype":"FP32","shape":[1,1],"data":[1.0]}]}`
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "triton-load-verified.json")

		err := runTritonModelLoad(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "Triton model loaded and inferable") {
			t.Fatalf("expected verified load title, got %s", content)
		}
		if !strings.Contains(content, `"load_verified":true`) {
			t.Fatalf("expected load_verified=true, got %s", content)
		}
		if !strings.Contains(content, `"stage":"own"`) || !strings.Contains(content, `"landed":"execution-confirmed"`) {
			t.Fatalf("expected own/execution-confirmed, got %s", content)
		}
	})
}

func TestRunTritonModelUnloadAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/repository/models/test-model/unload", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tritonTarget
	prevModel := tritonModel
	defer func() {
		tritonTarget = prev
		tritonModel = prevModel
	}()

	withTestConfig(t, func() {
		tritonTarget = srv.URL
		tritonModel = "test-model"
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "triton-unload.json")

		err := runTritonModelUnload(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "model unload") {
			t.Fatalf("expected model unload finding, got %s", string(raw))
		}
	})
}

// ---------------------------------------------------------------------------
// Missing flag / force-exploit validation tests
// ---------------------------------------------------------------------------

func TestNewTritonClientMissingTarget(t *testing.T) {
	prev := tritonTarget
	defer func() { tritonTarget = prev }()
	tritonTarget = ""

	withTestConfig(t, func() {
		_, _, err := newTritonClient()
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunTritonModelConfigMissingModel(t *testing.T) {
	prevModel := tritonModel
	defer func() { tritonModel = prevModel }()
	tritonModel = ""

	err := runTritonModelConfig(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--model") {
		t.Fatalf("expected --model error, got %v", err)
	}
}

func TestRunTritonInferRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		cfg.ForceExploit = false
		err := runTritonInfer(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected --force-exploit error, got %v", err)
		}
	})
}

func TestRunTritonInferMissingModel(t *testing.T) {
	prevModel := tritonModel
	prevPayload := tritonPayload
	defer func() {
		tritonModel = prevModel
		tritonPayload = prevPayload
	}()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		tritonModel = ""
		tritonPayload = `{"inputs":[]}`

		err := runTritonInfer(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--model") {
			t.Fatalf("expected --model error, got %v", err)
		}
	})
}

func TestRunTritonInferMissingPayload(t *testing.T) {
	prevModel := tritonModel
	prevPayload := tritonPayload
	defer func() {
		tritonModel = prevModel
		tritonPayload = prevPayload
	}()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		tritonModel = "resnet50"
		tritonPayload = ""

		err := runTritonInfer(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--payload") {
			t.Fatalf("expected --payload error, got %v", err)
		}
	})
}

func TestRunTritonModelLoadRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		cfg.ForceExploit = false
		err := runTritonModelLoad(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected --force-exploit error, got %v", err)
		}
	})
}

func TestRunTritonModelLoadMissingModel(t *testing.T) {
	prevModel := tritonModel
	prevPayload := tritonPayload
	defer func() {
		tritonModel = prevModel
		tritonPayload = prevPayload
	}()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		tritonModel = ""
		tritonPayload = ""

		err := runTritonModelLoad(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--model") {
			t.Fatalf("expected --model error, got %v", err)
		}
	})
}

func TestRunTritonModelUnloadRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		cfg.ForceExploit = false
		err := runTritonModelUnload(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected --force-exploit error, got %v", err)
		}
	})
}

func TestRunTritonModelUnloadMissingModel(t *testing.T) {
	prevModel := tritonModel
	defer func() { tritonModel = prevModel }()

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		tritonModel = ""

		err := runTritonModelUnload(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--model") {
			t.Fatalf("expected --model error, got %v", err)
		}
	})
}

func TestRunTritonSHMProbeMissingTarget(t *testing.T) {
	prev := tritonTarget
	defer func() { tritonTarget = prev }()
	tritonTarget = ""

	withTestConfig(t, func() {
		err := runTritonSHMProbe(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunTritonEnumMissingTarget(t *testing.T) {
	prev := tritonTarget
	defer func() { tritonTarget = prev }()
	tritonTarget = ""

	withTestConfig(t, func() {
		err := runTritonEnum(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunTritonModelsMissingTarget(t *testing.T) {
	prev := tritonTarget
	defer func() { tritonTarget = prev }()
	tritonTarget = ""

	withTestConfig(t, func() {
		err := runTritonModels(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunTritonSHMProbeAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/systemsharedmemory/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"name": "shm_region_0", "key": "/shm_region_0", "offset": 0, "byte_size": 4096},
		})
	})
	mux.HandleFunc("/v2/cudasharedmemory/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := tritonTarget
	defer func() { tritonTarget = prev }()

	withTestConfig(t, func() {
		tritonTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "triton-shm.json")

		err := runTritonSHMProbe(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "shared memory") {
			t.Fatalf("expected shared memory finding, got %s", string(raw))
		}
	})
}
