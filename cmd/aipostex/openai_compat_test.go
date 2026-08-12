package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	openaicompat "github.com/professor-moody/aipostex/pkg/exploit/openaicompat"
	"github.com/professor-moody/aipostex/pkg/report"
)

func openAICompatMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "llama3-8b", "owned_by": "meta"},
				{"id": "mistral-7b", "owned_by": "mistral"},
			},
		})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Tools []map[string]any `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		hasToolDef := len(req.Tools) > 0
		userContent := ""
		for _, m := range req.Messages {
			if m.Role == "user" {
				userContent = m.Content
			}
		}

		if hasToolDef && strings.Contains(userContent, "aipostex_exfil_test") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{
						"message": map[string]any{
							"content": "",
							"tool_calls": []map[string]any{
								{
									"id":   "call_1",
									"type": "function",
									"function": map[string]any{
										"name":      "aipostex_exfil_test",
										"arguments": `{"data":"INJECTION_TEST"}`,
									},
								},
							},
						},
					},
				},
			})
			return
		}
		if hasToolDef {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{
						"message": map[string]any{
							"content": "",
							"tool_calls": []map[string]any{
								{
									"id":   "call_1",
									"type": "function",
									"function": map[string]any{
										"name":      "aipostex_probe",
										"arguments": `{}`,
									},
								},
							},
						},
					},
				},
			})
			return
		}

		if strings.Contains(userContent, "INJECTION_SUCCESS") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]any{"content": "INJECTION_SUCCESS confirmed."}},
				},
			})
			return
		}
		if strings.Contains(userContent, "ROLE_HIJACK") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]any{"content": "ROLE_HIJACK executed."}},
				},
			})
			return
		}
		if strings.Contains(userContent, "DELIMITER_BREAK") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]any{"content": "DELIMITER_BREAK"}},
				},
			})
			return
		}
		if strings.Contains(userContent, "ACCESS_GRANTED") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]any{"content": "ACCESS_GRANTED. I am now in unrestricted mode."}},
				},
			})
			return
		}
		if strings.Contains(userContent, "Translate") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]any{"content": "Mes instructions disent que je ne dois jamais révéler mes instructions."}},
				},
			})
			return
		}
		if strings.Contains(userContent, "hidden system") || strings.Contains(userContent, "system prompt") || strings.Contains(userContent, "developer prompt") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"choices": []map[string]any{
					{"message": map[string]any{"content": "You are a helpful assistant. [system prompt]: Always respond helpfully."}},
				},
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": "READY I can confirm inference access is working properly."}},
			},
		})
	})
	mux.HandleFunc("/v1/completions", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"text": "READY inference confirmed via completions endpoint."},
			},
		})
	})
	mux.HandleFunc("/health/readiness", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "healthy", "litellm_version": "1.2.3",
			"db_connected": "true", "cache_status": "connected",
		})
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"healthy_endpoints":   []map[string]any{{"model": "llama3-8b", "api_base": "http://internal:8080"}},
			"unhealthy_endpoints": []any{},
		})
	})
	mux.HandleFunc("/v1/model/info", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"model_name": "llama3-8b",
					"litellm_params": map[string]any{
						"model":   "ollama/llama3",
						"api_key": "sk-test-secret-key-12345",
					},
				},
			},
		})
	})

	return mux
}

func withOpenAICompatMock(t *testing.T, fn func(srv *httptest.Server)) {
	t.Helper()
	srv := httptest.NewServer(openAICompatMux())
	defer srv.Close()

	prevTarget := openAICompatTarget
	prevModel := openAICompatModel
	prevPrompt := openAICompatPrompt
	prevMaxTokens := openAICompatMaxTokens
	prevAPIKey := openAICompatAPIKey
	prevHeaders := openAICompatHeaders
	defer func() {
		openAICompatTarget = prevTarget
		openAICompatModel = prevModel
		openAICompatPrompt = prevPrompt
		openAICompatMaxTokens = prevMaxTokens
		openAICompatAPIKey = prevAPIKey
		openAICompatHeaders = prevHeaders
	}()

	openAICompatTarget = srv.URL
	openAICompatHeaders = nil
	openAICompatAPIKey = ""
	openAICompatPrompt = ""
	openAICompatMaxTokens = 64
	fn(srv)
}

func TestRunOpenAICompatAuthSweepAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-auth-sweep.json")
			openAICompatModel = ""

			err := runOpenAICompatAuthSweep(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "auth") && !strings.Contains(out, "sweep") && !strings.Contains(out, "Weak") {
				t.Fatalf("expected auth sweep findings in output, got %s", out)
			}
		})
	})
}

func TestRunOpenAICompatEnumAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-enum.json")
			openAICompatAPIKey = "sk-test-from-notebook"

			err := runOpenAICompatEnum(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "llama3-8b") || !strings.Contains(out, "mistral-7b") {
				t.Fatalf("expected model IDs in output, got %s", out)
			}
			if !strings.Contains(out, "--api-key sk-test-from-notebook") {
				t.Fatalf("expected enum workflow to preserve supplied api key, got %s", out)
			}
		})
	})
}

func TestRunOpenAICompatValidateInferenceAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-validate.json")
			openAICompatModel = "llama3-8b"

			err := runOpenAICompatValidateInference(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "llama3-8b") {
				t.Fatalf("expected model in output, got %s", out)
			}
		})
	})
}

func TestRunOpenAICompatPromptExtractAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-prompt-extract.json")
			openAICompatModel = "llama3-8b"

			err := runOpenAICompatPromptExtract(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "prompt") {
				t.Fatalf("expected prompt extraction info in output, got %s", out)
			}
		})
	})
}

func TestRunOpenAICompatToolEnumAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-tool-enum.json")
			openAICompatModel = "llama3-8b"

			err := runOpenAICompatToolEnum(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "tool") || !strings.Contains(out, "Tool") {
				t.Fatalf("expected tool enum findings in output, got %s", out)
			}
		})
	})
}

func TestRunOpenAICompatPromptTestAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-prompt-test.json")
			openAICompatModel = "llama3-8b"

			err := runOpenAICompatPromptTest(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "prompt") && !strings.Contains(out, "Prompt") {
				t.Fatalf("expected prompt test findings in output, got %s", out)
			}
		})
	})
}

func TestRunOpenAICompatThroughputAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-throughput.json")
			cfg.ForceExploit = true
			openAICompatModel = "llama3-8b"
			openAICompatRequests = 3
			openAICompatConcurrency = 2

			prevReqs := openAICompatRequests
			prevConc := openAICompatConcurrency
			defer func() {
				openAICompatRequests = prevReqs
				openAICompatConcurrency = prevConc
			}()

			err := runOpenAICompatThroughput(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "throughput") {
				t.Fatalf("expected throughput in output, got %s", out)
			}
		})
	})
}

func TestRunOpenAICompatThroughputRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = false
			openAICompatModel = "llama3-8b"
			openAICompatRequests = 3
			openAICompatConcurrency = 2

			err := runOpenAICompatThroughput(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
				t.Fatalf("expected force-exploit error, got %v", err)
			}
		})
	})
}

func TestRunOpenAICompatProxyTestAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-proxy-test.json")
			cfg.ForceExploit = true
			openAICompatModel = "llama3-8b"

			err := runOpenAICompatProxyTest(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "proxy") && !strings.Contains(out, "Proxy") {
				t.Fatalf("expected proxy-test findings in output, got %s", out)
			}
		})
	})
}

func TestRunOpenAICompatProxyTestRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = false
			openAICompatModel = "llama3-8b"

			err := runOpenAICompatProxyTest(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
				t.Fatalf("expected force-exploit error, got %v", err)
			}
		})
	})
}

func TestRunOpenAICompatGenerateAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-generate.json")
			cfg.ForceExploit = true
			openAICompatModel = "llama3-8b"
			openAICompatPrompt = "Explain this access in one sentence."
			openAICompatMaxTokens = 12

			err := runOpenAICompatGenerate(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			for _, want := range []string{"generate", "Explain this access", "llama3-8b", "READY I can confirm"} {
				if !strings.Contains(out, want) {
					t.Fatalf("expected %q in output, got %s", want, out)
				}
			}
		})
	})
}

func TestRunOpenAICompatGenerateRequiresForceExploit(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = false
			openAICompatModel = "llama3-8b"
			openAICompatPrompt = "Hello"

			err := runOpenAICompatGenerate(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
				t.Fatalf("expected force-exploit error, got %v", err)
			}
		})
	})
}

func TestRunOpenAICompatGenerateRequiresPrompt(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = true
			openAICompatModel = "llama3-8b"
			openAICompatPrompt = ""

			err := runOpenAICompatGenerate(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--prompt") {
				t.Fatalf("expected prompt error, got %v", err)
			}
		})
	})
}

func TestRunOpenAICompatGeneratePropagatesHeaders(t *testing.T) {
	mux := http.NewServeMux()
	seenAPIKey := false
	seenHeader := false
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		seenAPIKey = r.Header.Get("Authorization") == "Bearer sk-test-from-notebook"
		seenHeader = r.Header.Get("X-Demo") == "conference"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": "custom prompt response"}},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	withTestConfig(t, func() {
		prevTarget := openAICompatTarget
		prevModel := openAICompatModel
		prevPrompt := openAICompatPrompt
		prevMaxTokens := openAICompatMaxTokens
		prevAPIKey := openAICompatAPIKey
		prevHeaders := openAICompatHeaders
		defer func() {
			openAICompatTarget = prevTarget
			openAICompatModel = prevModel
			openAICompatPrompt = prevPrompt
			openAICompatMaxTokens = prevMaxTokens
			openAICompatAPIKey = prevAPIKey
			openAICompatHeaders = prevHeaders
		}()

		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "oai-generate-headers.json")
		cfg.ForceExploit = true
		openAICompatTarget = srv.URL
		openAICompatModel = "llama3-8b"
		openAICompatPrompt = "Hello"
		openAICompatMaxTokens = 8
		openAICompatAPIKey = "sk-test-from-notebook"
		openAICompatHeaders = []string{"X-Demo: conference"}

		err := runOpenAICompatGenerate(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		if !seenAPIKey {
			t.Fatal("expected API key authorization header")
		}
		if !seenHeader {
			t.Fatal("expected custom header")
		}
	})
}

func TestRunOpenAICompatLiteLLMProbeAgainstMock(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "oai-litellm-probe.json")

			err := runOpenAICompatLiteLLMProbe(nil, nil)
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out := string(raw)
			if !strings.Contains(out, "LiteLLM") && !strings.Contains(out, "litellm") {
				t.Fatalf("expected LiteLLM probe findings in output, got %s", out)
			}
			if !strings.Contains(out, "1.2.3") {
				t.Fatalf("expected LiteLLM version in output, got %s", out)
			}
		})
	})
}

// ---------------------------------------------------------------------------
// promptTestSummary — all branches
// ---------------------------------------------------------------------------

func TestPromptTestSummaryNilResult(t *testing.T) {
	sev, title, _ := promptTestSummary(nil)
	if sev != report.SeverityInfo {
		t.Errorf("expected Info severity for nil result, got %s", sev)
	}
	if !strings.Contains(title, "inconclusive") {
		t.Errorf("expected inconclusive title for nil result, got %s", title)
	}
}

func TestPromptTestSummaryNoCompletedProbes(t *testing.T) {
	result := &openaicompat.PromptInjectionResult{
		Model:           "test-model",
		CompletedProbes: 0,
	}
	sev, title, _ := promptTestSummary(result)
	if sev != report.SeverityInfo {
		t.Errorf("expected Info severity for 0 completed, got %s", sev)
	}
	if !strings.Contains(title, "inconclusive") {
		t.Errorf("expected inconclusive title, got %s", title)
	}
}

func TestPromptTestSummaryVulnerableGe3(t *testing.T) {
	result := &openaicompat.PromptInjectionResult{
		Model:            "test-model",
		CompletedProbes:  5,
		VulnerableProbes: []string{"a", "b", "c"},
	}
	sev, title, _ := promptTestSummary(result)
	if sev != report.SeverityCritical {
		t.Errorf("expected Critical for >=3 vulnerable, got %s", sev)
	}
	if !strings.Contains(title, "vulnerable") {
		t.Errorf("expected vulnerable title, got %s", title)
	}
}

func TestPromptTestSummaryVulnerablePartial(t *testing.T) {
	result := &openaicompat.PromptInjectionResult{
		Model:            "test-model",
		CompletedProbes:  5,
		VulnerableProbes: []string{"a"},
	}
	sev, title, _ := promptTestSummary(result)
	if sev != report.SeverityHigh {
		t.Errorf("expected High for 1-2 vulnerable, got %s", sev)
	}
	if !strings.Contains(title, "Partial") {
		t.Errorf("expected Partial title, got %s", title)
	}
}

func TestPromptTestSummaryResisted(t *testing.T) {
	result := &openaicompat.PromptInjectionResult{
		Model:            "test-model",
		CompletedProbes:  5,
		VulnerableProbes: []string{},
	}
	sev, title, _ := promptTestSummary(result)
	if sev != report.SeverityInfo {
		t.Errorf("expected Info for resisted, got %s", sev)
	}
	if !strings.Contains(title, "resisted") {
		t.Errorf("expected resisted title, got %s", title)
	}
}

// ---------------------------------------------------------------------------
// openai-compat — missing-target validation
// ---------------------------------------------------------------------------

func TestRunOpenAICompatPromptExtractMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		err := runOpenAICompatPromptExtract(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunOpenAICompatToolEnumMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		err := runOpenAICompatToolEnum(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunOpenAICompatPromptTestMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		err := runOpenAICompatPromptTest(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunOpenAICompatAuthSweepMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		err := runOpenAICompatAuthSweep(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunOpenAICompatEnumMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		err := runOpenAICompatEnum(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunOpenAICompatValidateInferenceMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		err := runOpenAICompatValidateInference(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunOpenAICompatLiteLLMProbeMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		err := runOpenAICompatLiteLLMProbe(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunOpenAICompatProxyTestMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		err := runOpenAICompatProxyTest(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunOpenAICompatGenerateMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		openAICompatPrompt = "Hello"
		err := runOpenAICompatGenerate(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunOpenAICompatThroughputMissingRequests(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = true
			openAICompatModel = "llama3-8b"
			openAICompatRequests = 0
			openAICompatConcurrency = 2

			prevReqs := openAICompatRequests
			prevConc := openAICompatConcurrency
			defer func() {
				openAICompatRequests = prevReqs
				openAICompatConcurrency = prevConc
			}()

			err := runOpenAICompatThroughput(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--requests") {
				t.Fatalf("expected --requests error, got %v", err)
			}
		})
	})
}

func TestRunOpenAICompatThroughputMissingConcurrency(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			cfg.ForceExploit = true
			openAICompatModel = "llama3-8b"
			openAICompatRequests = 3
			openAICompatConcurrency = 0

			prevReqs := openAICompatRequests
			prevConc := openAICompatConcurrency
			defer func() {
				openAICompatRequests = prevReqs
				openAICompatConcurrency = prevConc
			}()

			err := runOpenAICompatThroughput(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--concurrency") {
				t.Fatalf("expected --concurrency error, got %v", err)
			}
		})
	})
}

func TestRunOpenAICompatThroughputMissingTarget(t *testing.T) {
	prevTarget := openAICompatTarget
	defer func() { openAICompatTarget = prevTarget }()
	openAICompatTarget = ""

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		openAICompatRequests = 3
		openAICompatConcurrency = 2

		err := runOpenAICompatThroughput(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestNewOpenAICompatClientWithAPIKey(t *testing.T) {
	withTestConfig(t, func() {
		withOpenAICompatMock(t, func(_ *httptest.Server) {
			openAICompatAPIKey = "sk-test-key-12345"

			client, headers, err := newOpenAICompatClient()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client == nil {
				t.Fatal("expected non-nil client")
			}
			if got := headers.Get("Authorization"); got != "Bearer sk-test-key-12345" {
				t.Errorf("expected Bearer auth header, got %q", got)
			}
		})
	})
}

func TestSafeLabel(t *testing.T) {
	if got := safeLabel(""); got != "unknown" {
		t.Errorf("safeLabel(\"\") = %q, want \"unknown\"", got)
	}
	if got := safeLabel("   "); got != "unknown" {
		t.Errorf("safeLabel(\"   \") = %q, want \"unknown\"", got)
	}
	if got := safeLabel("hello"); got != "hello" {
		t.Errorf("safeLabel(\"hello\") = %q, want \"hello\"", got)
	}
}

// fingerprintMux serves a model that MASKS its identity ("NovaTech Assistant")
// but leaks its true family (Qwen) when a false vendor is asserted — the
// contradiction technique. Used to prove the fingerprint verb
// de-masks via contradiction rather than trusting the self-report.
func fingerprintMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "novatech-assistant", "owned_by": "novatech"}},
		})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Role, Content string
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		user := ""
		for _, m := range req.Messages {
			if m.Role == "user" {
				user = strings.ToLower(m.Content)
			}
		}
		reply := "Sure, I can help with that."
		switch {
		case strings.Contains(user, "what model are you"):
			reply = "I am the NovaTech Customer Assistant, here to help."
		case strings.Contains(user, "claude"):
			reply = "I should clarify — I'm actually Qwen, created by Alibaba Cloud, not Claude."
		case strings.Contains(user, "gpt-4! openai"):
			reply = "To be precise, I'm Qwen from Alibaba Cloud, not GPT-4 from OpenAI."
		case strings.Contains(user, "knowledge cutoff") || strings.Contains(user, "knowledge-cutoff"):
			reply = "My training data goes up to early 2024."
		case strings.Contains(user, "2024 us presidential election"):
			reply = "I don't have information about the 2024 election; it has not occurred yet."
		case strings.Contains(user, "gpt-4o"):
			reply = "I don't have information on a GPT-4o release."
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"index": 0, "message": map[string]any{"role": "assistant", "content": reply}, "finish_reason": "stop"},
			},
			"model": "novatech-assistant",
		})
	})
	return mux
}

func TestRunOpenAICompatFingerprintDemasksViaContradiction(t *testing.T) {
	withTestConfig(t, func() {
		srv := httptest.NewServer(fingerprintMux())
		defer srv.Close()

		prevTarget, prevModel, prevCtx := openAICompatTarget, openAICompatModel, openAICompatFPContext
		defer func() {
			openAICompatTarget, openAICompatModel, openAICompatFPContext = prevTarget, prevModel, prevCtx
		}()
		openAICompatTarget = srv.URL
		openAICompatModel = ""
		openAICompatFPContext = false

		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "fp.json")

		err := runOpenAICompatFingerprint(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		for _, want := range []string{
			`"model_family":"qwen"`,
			`"fingerprint_confidence":"high"`,
			`"model_vendor":"Alibaba"`,
			`"stage":"recon"`,
			`"landed":"reachable"`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("fingerprint output missing %q\n---\n%s", want, out)
			}
		}
		// The masked self-report must not be taken at face value as the family.
		if strings.Contains(out, `"model_family":"novatech"`) {
			t.Error("fingerprint trusted the masked self-report instead of the contradiction signal")
		}
	})
}

// runOAIValidateWithHandler runs validate-inference against a custom mock and returns
// the JSON output. Assumes an active withTestConfig scope.
func runOAIValidateWithHandler(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	pT, pM, pP, pMax, pKey, pH := openAICompatTarget, openAICompatModel, openAICompatPrompt, openAICompatMaxTokens, openAICompatAPIKey, openAICompatHeaders
	defer func() {
		openAICompatTarget, openAICompatModel, openAICompatPrompt, openAICompatMaxTokens, openAICompatAPIKey, openAICompatHeaders = pT, pM, pP, pMax, pKey, pH
	}()
	openAICompatTarget, openAICompatModel = srv.URL, "canned-model"
	openAICompatHeaders, openAICompatAPIKey, openAICompatPrompt, openAICompatMaxTokens = nil, "", "", 64
	cfg.Format = "json"
	cfg.OutputFile = filepath.Join(t.TempDir(), "oai-validate-honest.json")
	if _, ok := runOpenAICompatValidateInference(nil, nil).(*exitcode.FindingsError); !ok {
		t.Fatal("expected FindingsError")
	}
	raw, err := os.ReadFile(cfg.OutputFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func oaiChatReply(w http.ResponseWriter, content string) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"choices": []map[string]any{{"message": map[string]any{"content": content}}},
	})
}

// A coherent response that is IDENTICAL for distinct prompts is a canned fixture — the
// input-differential check must keep it at influenced, never execution-confirmed.
func TestValidateInference_StaticOutputInfluenced(t *testing.T) {
	withTestConfig(t, func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "canned-model"}}})
		})
		mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
			oaiChatReply(w, "READY. Inference is accessible and working normally.")
		})
		out := runOAIValidateWithHandler(t, mux)
		if !strings.Contains(out, `"inference_verified":false`) {
			t.Errorf("static output must be inference_verified:false\n%s", out)
		}
		if strings.Contains(out, `"landed":"execution-confirmed"`) {
			t.Errorf("static output must NOT be execution-confirmed\n%s", out)
		}
		if !strings.Contains(out, `"landed":"influenced"`) {
			t.Errorf("coherent-but-static should be influenced\n%s", out)
		}
	})
}

// A coherent response that VARIES with the prompt is input-dependent inference — earns
// execution-confirmed.
func TestValidateInference_InputDependentExecutionConfirmed(t *testing.T) {
	withTestConfig(t, func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "canned-model"}}})
		})
		mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			sum := 0
			for _, b := range body {
				sum += int(b)
			}
			oaiChatReply(w, fmt.Sprintf("READY. Inference accessible; token %d confirms input-dependent output.", sum))
		})
		out := runOAIValidateWithHandler(t, mux)
		if !strings.Contains(out, `"inference_verified":true`) {
			t.Errorf("input-dependent output must be inference_verified:true\n%s", out)
		}
		if !strings.Contains(out, `"landed":"execution-confirmed"`) {
			t.Errorf("input-dependent inference should be execution-confirmed\n%s", out)
		}
	})
}
