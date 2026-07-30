package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/pkg/exploit/mlflow"
)

// TestRunMLflowRunsBareSurfacesTokenAcrossExperiments drives the ATTENDEE's exact
// command — bare `mlflow runs` with NO --experiment — through the full cmd path
// against a mock that enforces the real MLflow contract (runs/search with no
// experiment_ids returns nothing). It asserts the HF token seeded in the named
// customer-embedding-model experiment actually surfaces in the emitted output.
// This is the tool-level guard for the signature-chain break: nothing exercised
// this user-facing command before, so the experiment-scoping bug shipped green.
func TestRunMLflowRunsBareSurfacesTokenAcrossExperiments(t *testing.T) {
	const hfToken = "hf_FAKE_aBcDeFgHiJkLmNoPqRsTuVwXyZ123"
	prevFactory := mlflowClientFactory
	prevTarget := mlflowTarget
	prevExperiment := mlflowExperiment
	prevLimit := mlflowLimit
	defer func() {
		mlflowClientFactory = prevFactory
		mlflowTarget = prevTarget
		mlflowExperiment = prevExperiment
		mlflowLimit = prevLimit
	}()

	mlflowClientFactory = func() (*mlflow.Client, http.Header, error) {
		client, err := mlflow.NewClient(context.Background(), "http://127.0.0.1:5000", time.Second, nil)
		if err != nil {
			return nil, nil, err
		}
		client.HTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Path {
				case "/api/2.0/mlflow/experiments/search":
					return jsonResponse(http.StatusOK, `{"experiments":[{"experiment_id":"0","name":"Default"},{"experiment_id":"2","name":"customer-embedding-model"}]}`), nil
				case "/api/2.0/mlflow/runs/search":
					var payload struct {
						ExperimentIDs []string `json:"experiment_ids"`
					}
					_ = json.NewDecoder(req.Body).Decode(&payload)
					scoped := false
					for _, id := range payload.ExperimentIDs {
						if id == "2" {
							scoped = true
						}
					}
					if !scoped {
						return jsonResponse(http.StatusOK, `{"runs":[]}`), nil
					}
					return jsonResponse(http.StatusOK, `{"runs":[{"info":{"run_id":"embed-run","experiment_id":"2","status":"FINISHED","artifact_uri":"s3://acme/embed"},"data":{"params":[{"key":"hf_token","value":"`+hfToken+`"}]}}]}`), nil
				default:
					return jsonResponse(http.StatusNotFound, "not found"), nil
				}
			}),
		}
		return client, nil, nil
	}

	withTestConfig(t, func() {
		mlflowTarget = "http://127.0.0.1:5000"
		mlflowExperiment = "" // BARE — exactly what an attendee runs after looting the Basic cred
		mlflowLimit = 20
		outFile := filepath.Join(t.TempDir(), "runs.jsonl")
		cfg.Format = "jsonl"
		cfg.OutputFile = outFile

		// A non-nil *FindingsError is the success signal (findings were emitted);
		// any other error is a real failure.
		if err := runMLflowRuns(nil, nil); err != nil {
			var fe *exitcode.FindingsError
			if !errors.As(err, &fe) {
				t.Fatalf("runMLflowRuns(bare) returned a real error: %v", err)
			}
		}
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatalf("reading output: %v", err)
		}
		if !strings.Contains(string(data), hfToken) {
			t.Fatalf("bare `mlflow runs` MUST surface the HF token from the named experiment (chain hop 2); output did not contain it:\n%s", string(data))
		}
	})
}

func TestFilterExperiments(t *testing.T) {
	experiments := []mlflow.Experiment{
		{ID: "1", Name: "default"},
		{ID: "2", Name: "fraud-detection"},
		{ID: "3", Name: "sentiment"},
	}
	tests := []struct {
		name    string
		filter  string
		wantLen int
		wantID  string
	}{
		{"empty filter returns all", "", 3, ""},
		{"whitespace filter returns all", "   ", 3, ""},
		{"filter by name", "fraud-detection", 1, "2"},
		{"filter by ID", "3", 1, "3"},
		{"no match returns empty", "nonexistent", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := filterExperiments(experiments, tc.filter)
			if len(got) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(got), tc.wantLen)
			}
			if tc.wantID != "" && got[0].ID != tc.wantID {
				t.Fatalf("ID = %q, want %q", got[0].ID, tc.wantID)
			}
		})
	}
}

func TestFilterExperimentsEmptyInput(t *testing.T) {
	got := filterExperiments(nil, "anything")
	if len(got) != 0 {
		t.Fatalf("expected empty result for nil input, got %d", len(got))
	}
}

func TestCollectExperimentNames(t *testing.T) {
	tests := []struct {
		name  string
		input []mlflow.Experiment
		want  []string
	}{
		{"nil input", nil, []string{}},
		{"empty input", []mlflow.Experiment{}, []string{}},
		{
			"extracts names",
			[]mlflow.Experiment{
				{ID: "1", Name: "alpha"},
				{ID: "2", Name: "beta"},
				{ID: "3", Name: "gamma"},
			},
			[]string{"alpha", "beta", "gamma"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := collectExperimentNames(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("index %d: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestCollectRunIDs(t *testing.T) {
	tests := []struct {
		name  string
		input []mlflow.Run
		want  []string
	}{
		{"nil input", nil, []string{}},
		{"empty input", []mlflow.Run{}, []string{}},
		{
			"extracts IDs",
			[]mlflow.Run{
				{ID: "run-abc"},
				{ID: "run-def"},
			},
			[]string{"run-abc", "run-def"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := collectRunIDs(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("index %d: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestMapKeys(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]string
		want  []string
	}{
		{"nil map", nil, []string{}},
		{"empty map", map[string]string{}, []string{}},
		{
			"extracts keys",
			map[string]string{"lr": "0.01", "epochs": "10", "batch": "32"},
			[]string{"batch", "epochs", "lr"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapKeys(tc.input)
			sort.Strings(got)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("index %d: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSelectMLflowModelVersion(t *testing.T) {
	versions := []mlflow.ModelVersion{
		{Model: "demo", Version: "1", Stage: "Production", Source: "runs:/abc/model", RunID: "abc"},
		{Model: "demo", Version: "2", Stage: "Staging", Source: "runs:/def/model", RunID: "def"},
		{Model: "demo", Version: "3", Stage: "None", Source: "runs:/ghi/model", RunID: "ghi"},
	}

	tests := []struct {
		name        string
		wanted      string
		wantVersion string
		wantErr     bool
	}{
		{"empty wanted returns first", "", "1", false},
		{"whitespace wanted returns first", "  ", "1", false},
		{"specific version found", "2", "2", false},
		{"specific version found with spaces", " 3 ", "3", false},
		{"nonexistent version errors", "99", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectMLflowModelVersion(versions, tc.wanted)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Version != tc.wantVersion {
				t.Fatalf("version = %q, want %q", got.Version, tc.wantVersion)
			}
		})
	}
}

func TestSelectMLflowModelVersionEmptySlice(t *testing.T) {
	_, err := selectMLflowModelVersion(nil, "")
	if err == nil || !strings.Contains(err.Error(), "no model versions") {
		t.Fatalf("expected 'no model versions' error, got %v", err)
	}
}

func TestParseMLflowSourceURI(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantRunID  string
		wantPrefix string
	}{
		{"empty string", "", "", ""},
		{"non-runs URI", "s3://bucket/path", "", ""},
		{"runs URI with path", "runs:/abc123/model", "abc123", "model"},
		{"runs URI without path", "runs:/abc123", "abc123", ""},
		{"runs URI with deep path", "runs:/abc123/model/nested/path", "abc123", "model/nested/path"},
		{"runs URI with leading slashes", "runs:///abc123/model", "abc123", "model"},
		{"runs URI whitespace trimmed", "  runs:/abc123/model  ", "abc123", "model"},
		{"http URI ignored", "http://mlflow.internal/artifact", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runID, prefix := parseMLflowSourceURI(tc.raw)
			if runID != tc.wantRunID {
				t.Fatalf("runID = %q, want %q", runID, tc.wantRunID)
			}
			if prefix != tc.wantPrefix {
				t.Fatalf("prefix = %q, want %q", prefix, tc.wantPrefix)
			}
		})
	}
}

func TestMLflowDownloadArtifactRequiresRunIDAndPath(t *testing.T) {
	prevTarget := mlflowTarget
	prevRunID := mlflowRunID
	prevArtifactPath := mlflowArtifactPath
	defer func() {
		mlflowTarget = prevTarget
		mlflowRunID = prevRunID
		mlflowArtifactPath = prevArtifactPath
	}()

	mlflowTarget = "http://127.0.0.1:5000"
	mlflowRunID = ""
	mlflowArtifactPath = ""

	err := runMLflowDownloadArtifact(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--run-id") {
		t.Fatalf("expected run-id validation error, got %v", err)
	}

	mlflowRunID = "run-1"
	err = runMLflowDownloadArtifact(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--artifact-path") {
		t.Fatalf("expected artifact-path validation error, got %v", err)
	}
}
