package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
)

func newTFServingMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model_version_status":[{"version":"1","state":"AVAILABLE"}]}`))
	})
	mux.HandleFunc("/v1/models/default", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model_version_status":[{"version":"1","state":"AVAILABLE","status":{"error_code":"OK"}}]}`))
	})
	mux.HandleFunc("/v1/models/default/metadata", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model_spec":{"name":"default","version":"1"},"metadata":{"signature_def":{"signature_def":{"serving_default":{"inputs":{"features":{"dtype":"DT_FLOAT","tensor_shape":{"dim":[{"size":"-1"},{"size":"3"}]},"name":"features:0"}},"outputs":{"scores":{"dtype":"DT_FLOAT","tensor_shape":{"dim":[{"size":"-1"},{"size":"1"}]}}}}}}}}`))
	})
	mux.HandleFunc("/v1/models/default:predict", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "8") {
			_, _ = w.Write([]byte(`{"outputs":{"scores":[[0.91]]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"outputs":{"scores":[[0.14]]}}`))
	})
	mux.HandleFunc("/monitoring/prometheus/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("# HELP tensorflow_serving_request_count\ntensorflow_serving_request_count 42\n"))
	})
	return httptest.NewServer(mux)
}

func TestRunTFServingEnumAgainstMockServer(t *testing.T) {
	srv := newTFServingMockServer(t)
	defer srv.Close()

	prev := tfservingTarget
	defer func() { tfservingTarget = prev }()

	withTestConfig(t, func() {
		tfservingTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "tfs-enum.json")

		err := runTFServingEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "tfserving") {
			t.Fatalf("expected tfserving in output, got %s", string(raw))
		}
	})
}

func TestRunTFServingModelsAgainstMockServer(t *testing.T) {
	srv := newTFServingMockServer(t)
	defer srv.Close()

	prev := tfservingTarget
	defer func() { tfservingTarget = prev }()

	withTestConfig(t, func() {
		tfservingTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "tfs-models.json")

		err := runTFServingModels(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "default") {
			t.Fatalf("expected model name in output, got %s", string(raw))
		}
		// The models flow discovered "default", so the follow-on metadata/predict
		// commands must carry the real name — never a "<name>" placeholder.
		out := string(raw)
		if !strings.Contains(out, "tfserving") || !strings.Contains(out, "--model default") {
			t.Fatalf("expected follow-on command threaded with discovered model name, got %s", out)
		}
		if strings.Contains(out, "--model <name>") || strings.Contains(out, "--model <a-discovered-model>") {
			t.Fatalf("expected no placeholder model in models workflow, got %s", out)
		}
		if !strings.Contains(out, "predict --model default") {
			t.Fatalf("expected gated predict command guarded behind known model name, got %s", out)
		}
	})
}

func TestRunTFServingEnumWorkflowLeavesModelHonest(t *testing.T) {
	srv := newTFServingMockServer(t)
	defer srv.Close()

	prev := tfservingTarget
	defer func() { tfservingTarget = prev }()

	withTestConfig(t, func() {
		tfservingTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "tfs-enum-wf.json")

		err := runTFServingEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		// JSON HTML-escapes < and > as < / >; un-escape so the readable
		// placeholder assertions below match the serialized command strings (and so
		// the negative checks below actually catch a bare token).
		out = strings.ReplaceAll(out, "\\u003c", "<")
		out = strings.ReplaceAll(out, "\\u003e", ">")
		// Enumerate() learns no model name, so the metadata step must read as a
		// value to supply, not a bare "<name>" TODO token, and no gated predict
		// command may be emitted carrying a placeholder.
		if strings.Contains(out, "--model <name>") {
			t.Fatalf("expected reworded placeholder, not bare <name>, got %s", out)
		}
		if !strings.Contains(out, "--model <a-discovered-model>") {
			t.Fatalf("expected honest reworded model parameter in enum workflow, got %s", out)
		}
		if strings.Contains(out, "predict --model <") {
			t.Fatalf("expected no gated predict command carrying a placeholder in enum workflow, got %s", out)
		}
	})
}

func TestRunTFServingMetadataAgainstMockServer(t *testing.T) {
	srv := newTFServingMockServer(t)
	defer srv.Close()

	prev, prevModel := tfservingTarget, tfservingModel
	defer func() { tfservingTarget, tfservingModel = prev, prevModel }()

	withTestConfig(t, func() {
		tfservingTarget = srv.URL
		tfservingModel = "default"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "tfs-metadata.json")

		err := runTFServingMetadata(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "default") {
			t.Fatalf("expected model name in output, got %s", string(raw))
		}
		out := string(raw)
		if !strings.Contains(out, "predict --model default") || !strings.Contains(out, "\\\"instances\\\"") {
			t.Fatalf("expected metadata workflow to carry concrete predict payload, got %s", out)
		}
	})
}

func TestRunTFServingPredictAgainstMockServer(t *testing.T) {
	srv := newTFServingMockServer(t)
	defer srv.Close()

	prev, prevModel, prevPayload := tfservingTarget, tfservingModel, tfservingPayload
	defer func() {
		tfservingTarget, tfservingModel, tfservingPayload = prev, prevModel, prevPayload
	}()

	withTestConfig(t, func() {
		tfservingTarget = srv.URL
		tfservingModel = "default"
		tfservingPayload = `{"instances":[[1,2,3]]}`
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "tfs-predict.json")

		err := runTFServingPredict(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
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

func TestRunTFServingPredictRequiresForceExploit(t *testing.T) {
	prev, prevModel, prevPayload, prevForce := tfservingTarget, tfservingModel, tfservingPayload, cfg.ForceExploit
	defer func() {
		tfservingTarget, tfservingModel, tfservingPayload, cfg.ForceExploit = prev, prevModel, prevPayload, prevForce
	}()

	withTestConfig(t, func() {
		tfservingTarget = "http://127.0.0.1:8501"
		tfservingModel = "default"
		tfservingPayload = `{"instances":[]}`
		cfg.ForceExploit = false

		err := runTFServingPredict(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "force") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

func TestRunTFServingMetricsAgainstMockServer(t *testing.T) {
	srv := newTFServingMockServer(t)
	defer srv.Close()

	prev := tfservingTarget
	defer func() { tfservingTarget = prev }()

	withTestConfig(t, func() {
		tfservingTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "tfs-metrics.json")

		err := runTFServingMetrics(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "tensorflow_serving") {
			t.Fatalf("expected prometheus metric in output, got %s", string(raw))
		}
	})
}
