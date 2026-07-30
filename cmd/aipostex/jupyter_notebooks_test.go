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
	"github.com/professor-moody/aipostex/pkg/report"
)

func TestJupyterNotebooksMineSecretsFindsCredentialInSecondNotebook(t *testing.T) {
	notebookWithKey := map[string]interface{}{
		"cells": []interface{}{
			map[string]interface{}{
				"cell_type": "code",
				"source":    []string{"API_KEY=sk-abcdefghijklmnopqrstuvwxyz"},
			},
		},
	}
	nbJSON, err := json.Marshal(notebookWithKey)
	if err != nil {
		t.Fatal(err)
	}
	listing := map[string]interface{}{
		"type": "directory",
		"content": []interface{}{
			map[string]interface{}{"name": "clean.ipynb", "path": "clean.ipynb", "type": "notebook"},
			map[string]interface{}{"name": "leak.ipynb", "path": "leak.ipynb", "type": "notebook"},
		},
	}
	listingBytes, _ := json.Marshal(listing)

	cleanNB := map[string]interface{}{
		"cells": []interface{}{
			map[string]interface{}{"cell_type": "code", "source": []string{"print(1)"}},
		},
	}
	cleanBytes, _ := json.Marshal(cleanNB)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/contents" && r.URL.RawQuery == "content=1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(listingBytes)
		case r.URL.Path == "/api/contents/clean.ipynb":
			body, _ := json.Marshal(map[string]interface{}{
				"name": "clean.ipynb", "path": "clean.ipynb", "type": "notebook",
				"format": "json", "content": json.RawMessage(cleanBytes),
			})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		case r.URL.Path == "/api/contents/leak.ipynb":
			body, _ := json.Marshal(map[string]interface{}{
				"name": "leak.ipynb", "path": "leak.ipynb", "type": "notebook",
				"format": "json", "content": json.RawMessage(nbJSON),
			})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prevTarget := jupyterTarget
	prevMine := jupyterMineSecrets
	defer func() {
		jupyterTarget = prevTarget
		jupyterMineSecrets = prevMine
	}()

	withTestConfig(t, func() {
		jupyterTarget = srv.URL
		jupyterMineSecrets = true
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "out.jsonl")
		cfg.Concurrency = 2

		err := runJupyterNotebooks(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("runJupyterNotebooks: %v", err)
			}
		}

		data, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		var secretFinding bool
		var listCount int
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var f report.Finding
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				t.Fatal(err)
			}
			if f.Metadata["action"] == "notebooks" && strings.Contains(f.Title, "notebook entry") {
				listCount++
			}
			if f.Metadata["action"] == "notebooks" && strings.Contains(f.Title, "Credential in notebook") {
				secretFinding = true
				if f.Metadata["path"] != "leak.ipynb" {
					t.Fatalf("expected leak.ipynb, got %v", f.Metadata["path"])
				}
				if f.Metadata["mine_secrets"] != true {
					t.Fatalf("expected mine_secrets metadata")
				}
			}
		}
		if listCount != 2 {
			t.Fatalf("expected 2 listing findings, got %d", listCount)
		}
		if !secretFinding {
			t.Fatal("expected credential finding from --mine-secrets")
		}
	})
}
