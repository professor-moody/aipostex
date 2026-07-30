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

func TestRunJupyterEnumAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"started": "2024-01-01T00:00:00Z", "connections": 1, "kernels": 1,
		})
	})
	mux.HandleFunc("/api/kernels", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "kernel-abc", "name": "python3"},
		})
	})
	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})
	mux.HandleFunc("/api/contents", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "directory",
			"content": []map[string]any{
				{"name": "demo.ipynb", "path": "demo.ipynb", "type": "notebook"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := jupyterTarget
	defer func() { jupyterTarget = prev }()

	withTestConfig(t, func() {
		jupyterTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "jupyter-enum.json")

		err := runJupyterEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "Jupyter server enumerated") {
			t.Fatalf("expected enum finding in output, got %s", content)
		}
	})
}

func TestRunJupyterKernelsAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/kernels", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "kernel-111", "name": "python3"},
			{"id": "kernel-222", "name": "ir"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := jupyterTarget
	defer func() { jupyterTarget = prev }()

	withTestConfig(t, func() {
		jupyterTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "jupyter-kernels.json")

		err := runJupyterKernels(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		if !strings.Contains(content, "kernel-111") || !strings.Contains(content, "kernel-222") {
			t.Fatalf("expected both kernels in output, got %s", content)
		}
	})
}

func TestRunJupyterReadNotebookMissingNotebook(t *testing.T) {
	prevPath := jupyterPath
	defer func() { jupyterPath = prevPath }()
	jupyterPath = ""
	withTestConfig(t, func() {
		err := runJupyterReadNotebook(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "path") {
			t.Fatalf("expected missing path error, got %v", err)
		}
	})
}

func TestRunJupyterReadNotebookAgainstMockServer(t *testing.T) {
	nbContent := map[string]any{
		"cells": []any{
			map[string]any{"cell_type": "code", "source": []string{"print('hello')"}},
		},
	}
	nbJSON, _ := json.Marshal(nbContent)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/contents/test.ipynb", func(w http.ResponseWriter, _ *http.Request) {
		body, _ := json.Marshal(map[string]any{
			"name": "test.ipynb", "path": "test.ipynb", "type": "notebook",
			"format": "json", "content": json.RawMessage(nbJSON),
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := jupyterTarget
	prevPath := jupyterPath
	defer func() {
		jupyterTarget = prevTarget
		jupyterPath = prevPath
	}()

	withTestConfig(t, func() {
		jupyterTarget = srv.URL
		jupyterPath = "test.ipynb"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "jupyter-read.json")

		err := runJupyterReadNotebook(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "test.ipynb") {
			t.Fatalf("expected notebook path in output, got %s", string(raw))
		}
	})
}

// A mined notebook secret must now surface as a structured credential (→ the console
// creds: block) AND still keep its explicit follow-on command — populating
// extracted_credentials (chainable=false) must not strip the jupyter workflow plan's
// Next Actions.
func TestRunJupyterReadNotebookSurfacesCredsAndPreservesNextActions(t *testing.T) {
	nbContent := map[string]any{
		"cells": []any{
			map[string]any{"cell_type": "code", "source": []string{"OPENAI_API_KEY = 'sk-proj-FAKE-notebook-key-1234567890abcd'\n"}},
		},
	}
	nbJSON, _ := json.Marshal(nbContent)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/contents/rag.ipynb", func(w http.ResponseWriter, _ *http.Request) {
		body, _ := json.Marshal(map[string]any{
			"name": "rag.ipynb", "path": "rag.ipynb", "type": "notebook",
			"format": "json", "content": json.RawMessage(nbJSON),
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := jupyterTarget
	prevPath := jupyterPath
	defer func() {
		jupyterTarget = prevTarget
		jupyterPath = prevPath
	}()

	withTestConfig(t, func() {
		jupyterTarget = srv.URL
		jupyterPath = "rag.ipynb"
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "jupyter-read.jsonl")

		if err := runJupyterReadNotebook(nil, nil); err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		const key = "sk-proj-FAKE-notebook-key-1234567890abcd"
		if !strings.Contains(out, "extracted_credentials") || !strings.Contains(out, key) {
			t.Fatalf("expected the mined key surfaced as a structured credential, got %s", out)
		}
		// The explicit jupyter follow-on must survive (Next Actions not stripped).
		if !strings.Contains(out, "openai-compat") || !strings.Contains(out, "auth-sweep") {
			t.Fatalf("expected the openai-compat auth-sweep follow-on preserved, got %s", out)
		}
	})
}

func TestRunJupyterStartKernelAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"started": "2024-01-01T00:00:00Z"})
	})
	mux.HandleFunc("/api/kernels", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "new-kernel-xyz", "name": "python3",
			})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := jupyterTarget
	defer func() { jupyterTarget = prev }()

	withTestConfig(t, func() {
		jupyterTarget = srv.URL
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "jupyter-start.json")

		err := runJupyterStartKernel(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "new-kernel-xyz") {
			t.Fatalf("expected new kernel id in output, got %s", string(raw))
		}
	})
}

// TestRunJupyterPipProofSkipped — pip-proof and reverse-shell-proof require
// websocket connections to kernel channels, which cannot be mocked with
// httptest alone. These handlers are covered at the client level in
// pkg/exploit/jupyter tests.
func TestRunJupyterPipProofSkipped(t *testing.T) {
	t.Skip("pip-proof requires websocket kernel channel — tested at client level")
}
