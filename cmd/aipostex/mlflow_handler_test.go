package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/pkg/exploit/mlflow"
)

func mlflowMux() *http.ServeMux {
	mux := http.NewServeMux()
	var tagMu sync.Mutex
	modelVersionTags := map[string]string{
		"lab_seed_key": "fraud-classifier-v1",
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("2.14.0"))
	})
	mux.HandleFunc("/api/2.0/mlflow/experiments/search", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"experiments": []map[string]any{
				{"experiment_id": "1", "name": "default", "artifact_location": "mlruns/1"},
				{"experiment_id": "2", "name": "fraud-detection", "artifact_location": "mlruns/2"},
			},
		})
	})
	mux.HandleFunc("/api/2.0/mlflow/runs/search", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"runs": []map[string]any{
				{
					"info": map[string]any{
						"run_id":        "run-abc-123",
						"experiment_id": "1",
						"status":        "FINISHED",
						"artifact_uri":  "mlruns/1/run-abc-123/artifacts",
					},
					"data": map[string]any{
						"params":  []map[string]any{{"key": "lr", "value": "0.01"}},
						"metrics": []map[string]any{{"key": "accuracy", "value": "0.95"}},
						"tags":    []map[string]any{{"key": "mlflow.source.name", "value": "train.py"}},
					},
				},
			},
		})
	})
	mux.HandleFunc("/api/2.0/mlflow/artifacts/list", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"files": []map[string]any{
				{"path": "model/MLmodel", "is_dir": false, "file_size": 1234},
				{"path": "model/weights.pkl", "is_dir": false, "file_size": 56789},
			},
		})
	})
	mux.HandleFunc("/api/2.0/mlflow/registered-models/search", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"registered_models": []map[string]any{
				{
					"name": "fraud-classifier",
					"latest_versions": []map[string]any{
						{"version": "1"},
						{"version": "2"},
					},
				},
			},
		})
	})
	mux.HandleFunc("/api/2.0/mlflow/model-versions/search", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model_versions": []map[string]any{
				{"name": "fraud-classifier", "version": "1", "current_stage": "Production", "source": "runs:/run-abc-123/model", "run_id": "run-abc-123"},
				{"name": "fraud-classifier", "version": "2", "current_stage": "Staging", "source": "runs:/run-def-456/model", "run_id": "run-def-456"},
			},
		})
	})
	mux.HandleFunc("/api/2.0/mlflow/model-versions/get", func(w http.ResponseWriter, _ *http.Request) {
		tagMu.Lock()
		tags := make([]map[string]any, 0, len(modelVersionTags))
		for key, value := range modelVersionTags {
			tags = append(tags, map[string]any{"key": key, "value": value})
		}
		tagMu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model_version": map[string]any{
				"name":          "fraud-classifier",
				"version":       "1",
				"current_stage": "Production",
				"source":        "runs:/run-abc-123/model",
				"run_id":        "run-abc-123",
				"tags":          tags,
			},
		})
	})
	mux.HandleFunc("/api/2.0/mlflow/model-versions/set-tag", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Key     string `json:"key"`
			Value   string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tagMu.Lock()
		modelVersionTags[payload.Key] = payload.Value
		tagMu.Unlock()
		if payload.Key == "aipostex.hook.url" && strings.HasPrefix(payload.Value, "http://") {
			go func(hookURL string) {
				resp, err := http.Post(hookURL, "application/json", strings.NewReader(`{"module":"mlflow","action":"hook","model":"fraud-classifier","version":"1"}`)) //nolint:noctx
				if err == nil && resp != nil {
					_ = resp.Body.Close()
				}
			}(payload.Value)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	})
	mux.HandleFunc("/api/2.0/mlflow/experiments/create", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"experiment_id": "99"})
	})
	mux.HandleFunc("/api/2.0/mlflow/runs/create", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"run": map[string]any{
				"info": map[string]any{"run_id": "proof-run-001"},
			},
		})
	})
	mux.HandleFunc("/api/2.0/mlflow/runs/log-parameter", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/get-artifact", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("artifact_key: model\nflavor: sklearn\nrun_id: run-abc-123\nartifact_path: model/MLmodel"))
	})

	return mux
}

func withMLflowMock(t *testing.T, fn func(srv *httptest.Server)) {
	t.Helper()
	srv := httptest.NewServer(mlflowMux())
	defer srv.Close()

	prevTarget := mlflowTarget
	prevFactory := mlflowClientFactory
	prevExperiment := mlflowExperiment
	prevRunID := mlflowRunID
	prevArtifactPrefix := mlflowArtifactPrefix
	prevModel := mlflowModel
	prevVersion := mlflowVersion
	prevLimit := mlflowLimit
	prevBulkMaxFiles := mlflowBulkMaxFiles
	prevBulkMaxBytes := mlflowBulkMaxBytes
	prevBulkPerFile := mlflowBulkPerFile
	prevHookTagKey := mlflowHookTagKey
	defer func() {
		mlflowTarget = prevTarget
		mlflowClientFactory = prevFactory
		mlflowExperiment = prevExperiment
		mlflowRunID = prevRunID
		mlflowArtifactPrefix = prevArtifactPrefix
		mlflowModel = prevModel
		mlflowVersion = prevVersion
		mlflowLimit = prevLimit
		mlflowBulkMaxFiles = prevBulkMaxFiles
		mlflowBulkMaxBytes = prevBulkMaxBytes
		mlflowBulkPerFile = prevBulkPerFile
		mlflowHookTagKey = prevHookTagKey
	}()

	mlflowTarget = srv.URL
	mlflowClientFactory = func() (*mlflow.Client, http.Header, error) {
		client, err := mlflow.NewClient(currentContext(), srv.URL, cfg.Timeout, nil)
		if err != nil {
			return nil, nil, err
		}
		client.HTTPClient = srv.Client()
		client.ForceExploit = cfg.ForceExploit
		return client, nil, nil
	}

	fn(srv)
}

func TestRunMLflowEnumAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-enum.json")

			err := runMLflowEnum(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "MLflow") {
				t.Fatalf("expected MLflow in output, got %s", out)
			}
			if !strings.Contains(out, "default") && !strings.Contains(out, "fraud-detection") {
				t.Fatalf("expected experiment names in output, got %s", out)
			}
		})
	})
}

func TestRunMLflowExperimentsAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-experiments.json")
			mlflowExperiment = ""
			mlflowLimit = 10

			err := runMLflowExperiments(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "fraud-detection") {
				t.Fatalf("expected experiment name in output, got %s", out)
			}
		})
	})
}

func TestRunMLflowRunsAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-runs.json")
			mlflowExperiment = ""
			mlflowLimit = 10

			err := runMLflowRuns(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "run-abc-123") {
				t.Fatalf("expected run ID in output, got %s", out)
			}
		})
	})
}

func TestRunMLflowArtifactsAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-artifacts.json")
			mlflowRunID = "run-abc-123"
			mlflowLimit = 25

			err := runMLflowArtifacts(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "MLmodel") {
				t.Fatalf("expected artifact path in output, got %s", out)
			}
			if strings.Contains(out, `"landed":"execution-confirmed"`) || strings.Contains(out, `"landed":"takeover-capable"`) {
				t.Fatalf("artifact listings must stay reachable-only, got %s", out)
			}
		})
	})
}

func TestRunMLflowRegistryAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-registry.json")
			mlflowLimit = 10

			err := runMLflowRegistry(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "fraud-classifier") {
				t.Fatalf("expected registered model name in output, got %s", out)
			}
		})
	})
}

func TestRunMLflowModelVersionsAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-model-versions.json")
			mlflowModel = "fraud-classifier"
			mlflowLimit = 10

			err := runMLflowModelVersions(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "fraud-classifier") || !strings.Contains(out, "Production") {
				t.Fatalf("expected model version info in output, got %s", out)
			}
		})
	})
}

func TestRunMLflowModelArtifactsAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-model-artifacts.json")
			mlflowModel = "fraud-classifier"
			mlflowVersion = ""
			mlflowLimit = 25

			err := runMLflowModelArtifacts(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "fraud-classifier") {
				t.Fatalf("expected model name in output, got %s", out)
			}
		})
	})
}

func TestRunMLflowTamperProofAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-tamper.json")
			cfg.ForceExploit = true

			err := runMLflowTamperProof(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "tamper") {
				t.Fatalf("expected tamper proof in output, got %s", out)
			}
		})
	})
}

func TestRunMLflowTamperProofRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = false
			err := runMLflowTamperProof(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
				t.Fatalf("expected --force-exploit error, got %v", err)
			}
		})
	})
}

func TestRunMLflowHookAgainstMockCallbackConfirmed(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-hook.json")
			cfg.ForceExploit = true
			cfg.CallbackURL = fmt.Sprintf("http://127.0.0.1:%d/mlflow-hook", oobFreePort(t))
			mlflowModel = "fraud-classifier"
			mlflowVersion = "1"
			mlflowHookTagKey = "aipostex.hook.url"

			err := runMLflowHook(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, `"action":"hook"`) {
				t.Fatalf("expected hook action in output, got %s", out)
			}
			if !strings.Contains(out, `"callback_confirmed":true`) {
				t.Fatalf("expected callback confirmation, got %s", out)
			}
			if !strings.Contains(out, `"stage":"own"`) || !strings.Contains(out, `"landed":"takeover-capable"`) {
				t.Fatalf("expected own/takeover-capable for controller-confirmed hook, got %s", out)
			}
			if strings.Contains(out, `"landed":"execution-confirmed"`) {
				t.Fatalf("MLflow hook delivery must not claim arbitrary code execution, got %s", out)
			}
		})
	})
}

func TestRunMLflowHookRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = false
			cfg.CallbackURL = "http://127.0.0.1:9999/hook"
			mlflowModel = "fraud-classifier"
			mlflowVersion = "1"
			err := runMLflowHook(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
				t.Fatalf("expected --force-exploit error, got %v", err)
			}
		})
	})
}

func TestRunMLflowHookRequiresHTTPCallback(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = true
			cfg.CallbackURL = "tcp://127.0.0.1:4444"
			mlflowModel = "fraud-classifier"
			mlflowVersion = "1"
			err := runMLflowHook(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "HTTP(S)") {
				t.Fatalf("expected HTTP callback validation error, got %v", err)
			}
		})
	})
}

func TestRunMLflowDownloadArtifactAgainstMock(t *testing.T) {
	prevArtifactPath := mlflowArtifactPath
	defer func() {
		mlflowArtifactPath = prevArtifactPath
	}()

	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-download.json")
			mlflowRunID = "run-abc-123"
			mlflowArtifactPath = "model/MLmodel"

			err := runMLflowDownloadArtifact(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "MLmodel") {
				t.Fatalf("expected artifact path in output, got %s", out)
			}
			if !strings.Contains(out, "download-artifact") {
				t.Fatalf("expected download-artifact action in output, got %s", out)
			}
			if !strings.Contains(out, `"landed":"takeover-capable"`) {
				t.Fatalf("expected model artifact read to be takeover-capable, got %s", out)
			}
			if strings.Contains(out, `"landed":"execution-confirmed"`) {
				t.Fatalf("MLflow artifact reads must not claim execution-confirmed, got %s", out)
			}
		})
	})
}

func TestRunMLflowBulkDownloadAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-bulk.json")
			cfg.ForceExploit = true
			mlflowRunID = "run-abc-123"
			mlflowArtifactPrefix = "model"
			mlflowBulkMaxFiles = 5
			mlflowBulkMaxBytes = 1024 * 1024
			mlflowBulkPerFile = 256 * 1024

			err := runMLflowBulkDownload(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "bulk-download") {
				t.Fatalf("expected bulk-download action in output, got %s", out)
			}
			if !strings.Contains(out, "model/MLmodel") || !strings.Contains(out, "model/weights.pkl") {
				t.Fatalf("expected downloaded artifact paths in output, got %s", out)
			}
			if !strings.Contains(out, `"bulk":true`) {
				t.Fatalf("expected bulk metadata in output, got %s", out)
			}
			if !strings.Contains(out, `"landed":"takeover-capable"`) {
				t.Fatalf("expected model bulk read to be takeover-capable, got %s", out)
			}
			if strings.Contains(out, `"landed":"execution-confirmed"`) {
				t.Fatalf("MLflow bulk artifact reads must not claim execution-confirmed, got %s", out)
			}
		})
	})
}

func TestRunMLflowBulkDownloadRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = false
			mlflowRunID = "run-abc-123"
			err := runMLflowBulkDownload(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
				t.Fatalf("expected --force-exploit error, got %v", err)
			}
		})
	})
}

func TestRunMLflowBulkDownloadRequiresRunOrModel(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = true
			mlflowRunID = ""
			mlflowModel = ""
			err := runMLflowBulkDownload(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "either --run-id or --model") {
				t.Fatalf("expected run-id/model validation error, got %v", err)
			}
		})
	})
}

func TestRunMLflowExperimentsFilteredByName(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-experiments-filtered.json")
			mlflowExperiment = "fraud-detection"
			mlflowLimit = 10

			err := runMLflowExperiments(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "fraud-detection") {
				t.Fatalf("expected filtered experiment name in output, got %s", out)
			}
		})
	})
}

func TestRunMLflowExperimentsNoMatch(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(_ *httptest.Server) {
			mlflowExperiment = "nonexistent-experiment"
			mlflowLimit = 10

			err := runMLflowExperiments(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "no MLflow experiment matched") {
				t.Fatalf("expected no-match error, got %v", err)
			}
		})
	})
}

func TestRunMLflowModelVersionsRequiresModel(t *testing.T) {
	prevModel := mlflowModel
	defer func() { mlflowModel = prevModel }()

	mlflowModel = ""
	err := runMLflowModelVersions(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--model") {
		t.Fatalf("expected --model error, got %v", err)
	}
}

func TestRunMLflowModelArtifactsRequiresModel(t *testing.T) {
	prevModel := mlflowModel
	defer func() { mlflowModel = prevModel }()

	mlflowModel = ""
	err := runMLflowModelArtifacts(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--model") {
		t.Fatalf("expected --model error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// resolveMLflowExperimentID — branches
// ---------------------------------------------------------------------------

func TestResolveMLflowExperimentIDEmpty(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(srv *httptest.Server) {
			client, _, err := newMLflowClient()
			if err != nil {
				t.Fatalf("newMLflowClient: %v", err)
			}
			id, err := resolveMLflowExperimentID(client, "")
			if err != nil {
				t.Fatalf("expected nil error for empty filter, got %v", err)
			}
			if id != "" {
				t.Errorf("expected empty ID for empty filter, got %q", id)
			}
		})
	})
}

func TestResolveMLflowExperimentIDByName(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(srv *httptest.Server) {
			client, _, err := newMLflowClient()
			if err != nil {
				t.Fatalf("newMLflowClient: %v", err)
			}
			id, err := resolveMLflowExperimentID(client, "default")
			if err != nil {
				t.Fatalf("expected match for 'default' experiment, got %v", err)
			}
			if id == "" {
				t.Error("expected non-empty experiment ID")
			}
			if id != "1" {
				t.Errorf("expected experiment ID '1', got %q", id)
			}
		})
	})
}

func TestResolveMLflowExperimentIDNoMatch(t *testing.T) {
	withTestConfig(t, func() {
		withMLflowMock(t, func(srv *httptest.Server) {
			client, _, err := newMLflowClient()
			if err != nil {
				t.Fatalf("newMLflowClient: %v", err)
			}
			_, err = resolveMLflowExperimentID(client, "nonexistent-experiment-xyz")
			if err == nil || !strings.Contains(err.Error(), "no MLflow experiment matched") {
				t.Fatalf("expected no-match error, got %v", err)
			}
		})
	})
}

// ---------------------------------------------------------------------------
// runMLflowRuns — with experiment filter
// ---------------------------------------------------------------------------

func TestRunMLflowRunsWithExperiment(t *testing.T) {
	prevExperiment := mlflowExperiment
	defer func() { mlflowExperiment = prevExperiment }()

	withTestConfig(t, func() {
		withMLflowMock(t, func(srv *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-runs.json")
			mlflowExperiment = "default"
			mlflowLimit = 100

			err := runMLflowRuns(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
		})
	})
}

// ---------------------------------------------------------------------------
// runMLflowDownloadArtifact — missing flags
// ---------------------------------------------------------------------------

func TestRunMLflowDownloadArtifactMissingRunID(t *testing.T) {
	prevRunID := mlflowRunID
	defer func() { mlflowRunID = prevRunID }()
	mlflowRunID = ""

	withTestConfig(t, func() {
		withMLflowMock(t, func(srv *httptest.Server) {
			err := runMLflowDownloadArtifact(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "run-id") {
				t.Fatalf("expected run-id error, got %v", err)
			}
		})
	})
}

func TestRunMLflowDownloadArtifactMissingPath(t *testing.T) {
	prevRunID := mlflowRunID
	prevPath := mlflowArtifactPath
	defer func() {
		mlflowRunID = prevRunID
		mlflowArtifactPath = prevPath
	}()

	mlflowRunID = "abc123"
	mlflowArtifactPath = ""

	withTestConfig(t, func() {
		withMLflowMock(t, func(srv *httptest.Server) {
			err := runMLflowDownloadArtifact(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "artifact-path") {
				t.Fatalf("expected artifact-path error, got %v", err)
			}
		})
	})
}

// ---------------------------------------------------------------------------
// runMLflowArtifacts — missing run-id
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// newMLflowClient — missing target
// ---------------------------------------------------------------------------

func TestNewMLflowClientMissingTarget(t *testing.T) {
	prevTarget := mlflowTarget
	defer func() { mlflowTarget = prevTarget }()
	mlflowTarget = ""

	_, _, err := newMLflowClient()
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("expected missing target error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// runMLflowEnum — missing target
// ---------------------------------------------------------------------------

func TestRunMLflowEnumMissingTarget(t *testing.T) {
	prevTarget := mlflowTarget
	prevFactory := mlflowClientFactory
	defer func() {
		mlflowTarget = prevTarget
		mlflowClientFactory = prevFactory
	}()

	mlflowTarget = ""
	mlflowClientFactory = newMLflowClient

	withTestConfig(t, func() {
		err := runMLflowEnum(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// runMLflowRegistry — empty result (no models)
// ---------------------------------------------------------------------------

func TestRunMLflowRegistryEmptyResult(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("2.14.0"))
	})
	mux.HandleFunc("/api/2.0/mlflow/registered-models/search", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"registered_models": []map[string]any{},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := mlflowTarget
	prevFactory := mlflowClientFactory
	prevLimit := mlflowLimit
	defer func() {
		mlflowTarget = prevTarget
		mlflowClientFactory = prevFactory
		mlflowLimit = prevLimit
	}()

	withTestConfig(t, func() {
		mlflowTarget = srv.URL
		mlflowLimit = 10
		mlflowClientFactory = func() (*mlflow.Client, http.Header, error) {
			client, err := mlflow.NewClient(currentContext(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-registry-empty.json")

		err := runMLflowRegistry(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		out := string(raw)
		if !strings.Contains(out, "registry") {
			t.Fatalf("expected registry in output, got %s", out)
		}
	})
}

// ---------------------------------------------------------------------------
// selectMLflowModelVersion — edge cases
// ---------------------------------------------------------------------------

func TestSelectMLflowModelVersionEmpty(t *testing.T) {
	_, err := selectMLflowModelVersion(nil, "")
	if err == nil || !strings.Contains(err.Error(), "no model versions returned") {
		t.Fatalf("expected no model versions error, got %v", err)
	}
}

func TestSelectMLflowModelVersionDefaultFirst(t *testing.T) {
	versions := []mlflow.ModelVersion{
		{Model: "test", Version: "1", Stage: "Production"},
		{Model: "test", Version: "2", Stage: "Staging"},
	}
	v, err := selectMLflowModelVersion(versions, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Version != "1" {
		t.Errorf("expected version 1, got %s", v.Version)
	}
}

func TestSelectMLflowModelVersionSpecific(t *testing.T) {
	versions := []mlflow.ModelVersion{
		{Model: "test", Version: "1"},
		{Model: "test", Version: "2"},
	}
	v, err := selectMLflowModelVersion(versions, "2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Version != "2" {
		t.Errorf("expected version 2, got %s", v.Version)
	}
}

func TestSelectMLflowModelVersionNoMatch(t *testing.T) {
	versions := []mlflow.ModelVersion{
		{Model: "test", Version: "1"},
	}
	_, err := selectMLflowModelVersion(versions, "99")
	if err == nil || !strings.Contains(err.Error(), "no model version matched") {
		t.Fatalf("expected no match error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// filterExperiments — with filter that matches
// ---------------------------------------------------------------------------

func TestFilterExperimentsByName(t *testing.T) {
	experiments := []mlflow.Experiment{
		{ID: "1", Name: "a"},
		{ID: "2", Name: "b"},
	}
	result := filterExperiments(experiments, "b")
	if len(result) != 1 {
		t.Errorf("expected 1 filtered experiment, got %d", len(result))
	}
	if result[0].ID != "2" {
		t.Errorf("expected experiment ID 2, got %s", result[0].ID)
	}
}

func TestFilterExperimentsByID(t *testing.T) {
	experiments := []mlflow.Experiment{
		{ID: "1", Name: "a"},
		{ID: "2", Name: "b"},
	}
	result := filterExperiments(experiments, "1")
	if len(result) != 1 {
		t.Errorf("expected 1 filtered experiment, got %d", len(result))
	}
	if result[0].Name != "a" {
		t.Errorf("expected experiment name a, got %s", result[0].Name)
	}
}

// ---------------------------------------------------------------------------
// runMLflowModelVersions — empty result
// ---------------------------------------------------------------------------

func TestRunMLflowModelVersionsEmptyResult(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("2.14.0"))
	})
	mux.HandleFunc("/api/2.0/mlflow/model-versions/search", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model_versions": []map[string]any{},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := mlflowTarget
	prevFactory := mlflowClientFactory
	prevModel := mlflowModel
	prevLimit := mlflowLimit
	defer func() {
		mlflowTarget = prevTarget
		mlflowClientFactory = prevFactory
		mlflowModel = prevModel
		mlflowLimit = prevLimit
	}()

	withTestConfig(t, func() {
		mlflowTarget = srv.URL
		mlflowModel = "nonexistent-model"
		mlflowLimit = 10
		mlflowClientFactory = func() (*mlflow.Client, http.Header, error) {
			client, err := mlflow.NewClient(currentContext(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "mlflow-versions-empty.json")

		err := runMLflowModelVersions(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// runMLflowArtifacts — missing run-id
// ---------------------------------------------------------------------------

func TestRunMLflowArtifactsMissingRunID(t *testing.T) {
	prevRunID := mlflowRunID
	defer func() { mlflowRunID = prevRunID }()
	mlflowRunID = ""

	withTestConfig(t, func() {
		withMLflowMock(t, func(srv *httptest.Server) {
			err := runMLflowArtifacts(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "run-id") {
				t.Fatalf("expected run-id error, got %v", err)
			}
		})
	})
}
