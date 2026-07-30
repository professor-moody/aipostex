package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
)

func TestRunWandbSecretsIncludesProofMetadata(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"project": map[string]interface{}{
					"runs": map[string]interface{}{
						"edges": []map[string]interface{}{
							{"node": map[string]interface{}{
								"id":     "run-1",
								"config": `{"openai_api_key":{"value":"sk-proj-FAKEWandBSecret1234567890"}}`,
							}},
						},
						"pageInfo": map[string]interface{}{"hasNextPage": false},
					},
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget, prevEntity, prevProject, prevLimit := wandbTarget, wandbEntity, wandbProject, wandbLimit
	defer func() {
		wandbTarget = prevTarget
		wandbEntity = prevEntity
		wandbProject = prevProject
		wandbLimit = prevLimit
	}()

	withTestConfig(t, func() {
		wandbTarget = srv.URL
		wandbEntity = "acme"
		wandbProject = "churn"
		wandbLimit = 25
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "wandb-secrets.json")

		err := runWandbSecrets(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}

		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		content := string(raw)
		for _, want := range []string{
			`"action":"secrets"`,
			`"key":"openai_api_key"`,
			`"value":"sk-proj-FAKEWandBSecret1234567890"`,
			`"value_redacted":"sk-p...7890"`,
			`"stage":"impact"`,
			`"landed":"read-confirmed"`,
		} {
			if !strings.Contains(content, want) {
				t.Fatalf("expected output to contain %s, got %s", want, content)
			}
		}
	})
}

func TestRunWandbEnumThreadsDiscoveredViewerEntity(t *testing.T) {
	// With no --entity/--project supplied, the enum should thread the entity it
	// actually discovered (the viewer's username) into the follow-on commands,
	// and leave project as a supply-a-value token rather than a bare TODO.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0.42.0"))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"viewer": map[string]interface{}{
					"username": "labadmin",
					"admin":    true,
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget, prevEntity, prevProject := wandbTarget, wandbEntity, wandbProject
	defer func() {
		wandbTarget = prevTarget
		wandbEntity = prevEntity
		wandbProject = prevProject
	}()

	withTestConfig(t, func() {
		wandbTarget = srv.URL
		wandbEntity = ""
		wandbProject = ""
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "wandb-enum.json")

		err := runWandbEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}

		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		content := string(raw)
		// JSON HTML-escapes < and > as < / >; un-escape so the readable
		// placeholder assertions below match the serialized command strings.
		content = strings.ReplaceAll(content, "\\u003c", "<")
		content = strings.ReplaceAll(content, "\\u003e", ">")
		for _, want := range []string{
			`projects --entity labadmin`,
			`runs --entity labadmin --project <a-listed-project>`,
			`secrets --entity labadmin --project <a-listed-project>`,
		} {
			if !strings.Contains(content, want) {
				t.Fatalf("expected output to contain %q, got %s", want, content)
			}
		}
		if strings.Contains(content, "<entity>") || strings.Contains(content, "<project>") {
			t.Fatalf("expected reworded honest tokens, got bare TODO placeholder: %s", content)
		}
	})
}

func TestNewWandbClientAppliesAPIKeyUnlessAuthorizationHeaderProvided(t *testing.T) {
	prevTarget, prevHeaders, prevAPIKey := wandbTarget, wandbHeaders, wandbAPIKey
	defer func() {
		wandbTarget = prevTarget
		wandbHeaders = prevHeaders
		wandbAPIKey = prevAPIKey
	}()
	t.Setenv("WANDB_API_KEY", "env-key")

	withTestConfig(t, func() {
		wandbTarget = "http://127.0.0.1:8080"
		wandbHeaders = nil
		wandbAPIKey = "flag-key"
		_, headers, err := newWandbClient()
		if err != nil {
			t.Fatalf("newWandbClient: %v", err)
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("api:flag-key"))
		if got := headers.Get("Authorization"); got != want {
			t.Fatalf("expected flag API key auth %q, got %q", want, got)
		}

		wandbHeaders = []string{"Authorization: Bearer explicit"}
		wandbAPIKey = "ignored"
		_, headers, err = newWandbClient()
		if err != nil {
			t.Fatalf("newWandbClient with header: %v", err)
		}
		if got := headers.Get("Authorization"); got != "Bearer explicit" {
			t.Fatalf("explicit Authorization header should win, got %q", got)
		}
	})
}

func TestRunWandbEnumIncludesWorkflowMetadata(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0.42.0"))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"viewer": map[string]interface{}{
					"username": "labadmin",
					"entity":   "acme",
					"admin":    true,
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget, prevEntity, prevProject := wandbTarget, wandbEntity, wandbProject
	defer func() {
		wandbTarget = prevTarget
		wandbEntity = prevEntity
		wandbProject = prevProject
	}()

	withTestConfig(t, func() {
		wandbTarget = srv.URL
		wandbEntity = "acme"
		wandbProject = "churn"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "wandb-enum.json")

		err := runWandbEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}

		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		content := string(raw)
		for _, want := range []string{
			`"workflow"`,
			`wandb --target`,
			`projects --entity acme`,
			`secrets --entity acme --project churn`,
			`"landed":"reachable"`,
		} {
			if !strings.Contains(content, want) {
				t.Fatalf("expected output to contain %s, got %s", want, content)
			}
		}
	})
}
