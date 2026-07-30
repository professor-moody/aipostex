package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/pkg/exploit/kubeflow"
)

func newKFMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/pipeline/api/v1beta1/pipelines", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pipelines":[{"id":"pipe-001","name":"training-pipeline","description":"ML training","created_at":"2026-04-01T00:00:00Z","parameters":[{"name":"lr","value":"0.001"},{"name":"HF_TOKEN","value":"hf_FAKE_kf_test_123"}]}],"total_size":1}`))
	})
	mux.HandleFunc("/pipeline/api/v1beta1/runs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			_, _ = w.Write([]byte(`{"run":{"id":"run-new","name":"injected-run"}}`))
		} else {
			_, _ = w.Write([]byte(`{"runs":[{"id":"run-001","name":"train-run-1","status":"Succeeded","pipeline_spec":{"pipeline_id":"pipe-001"}}],"total_size":1}`))
		}
	})
	mux.HandleFunc("/pipeline/api/v1beta1/experiments", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"experiments":[{"id":"exp-001","name":"Default","created_at":"2026-04-01T00:00:00Z"}],"total_size":1}`))
	})
	mux.HandleFunc("/notebook/api/namespaces/kubeflow/notebooks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"notebooks":[{"metadata":{"name":"my-notebook","namespace":"kubeflow"},"status":{"readyReplicas":1,"containerState":"running"}}]}`))
	})
	return httptest.NewServer(mux)
}

func TestRunKFEnumAgainstMockServer(t *testing.T) {
	srv := newKFMockServer(t)
	defer srv.Close()

	prev := kubeflowTarget
	defer func() { kubeflowTarget = prev }()

	withTestConfig(t, func() {
		kubeflowTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "kf-enum.json")

		err := runKFEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "kubeflow") {
			t.Fatalf("expected kubeflow in output, got %s", string(raw))
		}
		if strings.Contains(string(raw), "kubeflow --target "+srv.URL+" notebooks") {
			t.Fatalf("enum should not suggest notebooks before the notebooks API is confirmed, got %s", string(raw))
		}
		if strings.Contains(string(raw), "run-pipeline") {
			t.Fatalf("enum should not suggest run-pipeline before a pipeline ID is known, got %s", string(raw))
		}
	})
}

func TestNewKFClientUsesRuntimeHTTPConfig(t *testing.T) {
	prevTarget, prevHeaders := kubeflowTarget, kubeflowHeaders
	defer func() {
		kubeflowTarget = prevTarget
		kubeflowHeaders = prevHeaders
	}()

	withTestConfig(t, func() {
		kubeflowTarget = "http://127.0.0.1:8080"
		cfg.Proxy = "http://[::1"
		if _, err := newKFClient(); err == nil {
			t.Fatal("expected invalid proxy from runtime HTTP config to be surfaced")
		}
	})
}

func TestRunKFPipelinesAgainstMockServer(t *testing.T) {
	srv := newKFMockServer(t)
	defer srv.Close()

	prev := kubeflowTarget
	defer func() { kubeflowTarget = prev }()

	withTestConfig(t, func() {
		kubeflowTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "kf-pipelines.json")

		err := runKFPipelines(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "training-pipeline") {
			t.Fatalf("expected pipeline name in output, got %s", string(raw))
		}
		if !strings.Contains(string(raw), "run-pipeline --pipeline-id pipe-001") {
			t.Fatalf("expected concrete gated run-pipeline follow-on, got %s", string(raw))
		}
		// Pipeline-param secrets must reach the structured credential channel so
		// `report view --credentials` lists them (not just the count).
		if !strings.Contains(string(raw), "extracted_credentials") {
			t.Fatalf("expected structured extracted_credentials in output, got %s", string(raw))
		}
		if !strings.Contains(string(raw), "hf_FAKE_kf_test_123") {
			t.Fatalf("expected pipeline-param secret value in output, got %s", string(raw))
		}
	})
}

func TestBuildKFPipelinesWorkflowPlanThreadsPipelineID(t *testing.T) {
	plan := buildKFPipelinesWorkflowPlan("http://127.0.0.1:8080", []kubeflow.Pipeline{
		{ID: "", Name: "no-id-pipeline"},
		{ID: "pipe-042", Name: "training-pipeline"},
	})

	var gated *workflowRecommendation
	for i := range plan.Recommendations {
		if plan.Recommendations[i].Gated {
			gated = &plan.Recommendations[i]
			break
		}
	}
	if gated == nil {
		t.Fatalf("expected a gated run-pipeline recommendation, got %+v", plan.Recommendations)
	}
	if !strings.Contains(gated.Command, "run-pipeline --pipeline-id pipe-042") {
		t.Fatalf("expected discovered pipeline ID threaded into gated command, got %q", gated.Command)
	}
	if strings.Contains(gated.Command, "<pipeline-id>") {
		t.Fatalf("gated command must not emit a placeholder when a pipeline ID is known, got %q", gated.Command)
	}
}

func TestBuildKFPipelinesWorkflowPlanGuardsGatedStepWithoutID(t *testing.T) {
	plan := buildKFPipelinesWorkflowPlan("http://127.0.0.1:8080", []kubeflow.Pipeline{
		{ID: "", Name: "no-id-pipeline"},
	})
	for _, rec := range plan.Recommendations {
		if rec.Gated {
			t.Fatalf("gated run-pipeline step must be omitted when no pipeline ID is known, got %q", rec.Command)
		}
		if strings.Contains(rec.Command, "<pipeline-id>") {
			t.Fatalf("no follow-on command should emit a placeholder pipeline ID, got %q", rec.Command)
		}
	}
}

func TestRunKFRunsAgainstMockServer(t *testing.T) {
	srv := newKFMockServer(t)
	defer srv.Close()

	prev := kubeflowTarget
	defer func() { kubeflowTarget = prev }()

	withTestConfig(t, func() {
		kubeflowTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "kf-runs.json")

		err := runKFRuns(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "train-run") {
			t.Fatalf("expected run name in output, got %s", string(raw))
		}
	})
}

func TestRunKFNotebooksAgainstMockServer(t *testing.T) {
	srv := newKFMockServer(t)
	defer srv.Close()

	prev := kubeflowTarget
	prevNS := kubeflowNamespace
	defer func() {
		kubeflowTarget = prev
		kubeflowNamespace = prevNS
	}()

	withTestConfig(t, func() {
		kubeflowTarget = srv.URL
		kubeflowNamespace = "kubeflow"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "kf-notebooks.json")

		err := runKFNotebooks(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "my-notebook") {
			t.Fatalf("expected notebook name in output, got %s", string(raw))
		}
	})
}
