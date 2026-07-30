package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/pkg/exploit/openaicompat"
)

func TestClassifyModelProviderHints(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{"gpt-4o", "openai"},
		{"openai/gpt-4", "openai"},
		{"anthropic/claude-3", "anthropic"},
		{"ollama/llama3", "ollama/local"},
		{"vertex_ai/gemini", "google"},
		{"azure/gpt-4", "azure"},
		{"custom-local", "unknown"},
	}
	for _, tc := range tests {
		if got := classifyModel(tc.model); got != tc.want {
			t.Fatalf("classifyModel(%q) = %q, want %q", tc.model, got, tc.want)
		}
	}
}

func TestClassifyModelWithInfoPrefersBackendMetadata(t *testing.T) {
	infoMap := map[string]string{
		"prod-chat":    "openai",
		"internal-llm": "anthropic",
	}
	tests := []struct {
		alias string
		want  string
	}{
		{"prod-chat", "openai"},
		{"internal-llm", "anthropic"},
		{"gpt-4", "openai"},
		{"unknown-alias", "unknown"},
	}
	for _, tc := range tests {
		if got := classifyModelWithInfo(tc.alias, infoMap); got != tc.want {
			t.Fatalf("classifyModelWithInfo(%q) = %q, want %q", tc.alias, got, tc.want)
		}
	}
}

func TestBuildModelInfoProviderMap(t *testing.T) {
	info := &openaicompat.LiteLLMModelInfoResponse{
		Data: []map[string]interface{}{
			{
				"model_name": "prod-chat",
				"litellm_params": map[string]interface{}{
					"model":    "openai/gpt-4",
					"api_base": "https://api.openai.com/v1",
				},
			},
			{
				"model_name": "internal-embed",
				"litellm_params": map[string]interface{}{
					"model":    "some-custom-model",
					"api_base": "https://api.anthropic.com/v1",
				},
			},
			{
				"model_name": "local-only",
				"litellm_params": map[string]interface{}{
					"model":    "custom-finetune",
					"api_base": "http://localhost:8080",
				},
			},
		},
	}
	m := buildModelInfoProviderMap(info)
	if m["prod-chat"] != "openai" {
		t.Fatalf("prod-chat: got %q, want openai", m["prod-chat"])
	}
	if m["internal-embed"] != "anthropic" {
		t.Fatalf("internal-embed: got %q, want anthropic (from api_base fallback)", m["internal-embed"])
	}
	if _, ok := m["local-only"]; ok {
		t.Fatalf("local-only should not be mapped (unknown model + localhost api_base)")
	}
}

func TestBuildModelInfoProviderMapNil(t *testing.T) {
	m := buildModelInfoProviderMap(nil)
	if m != nil {
		t.Fatalf("expected nil for nil input, got %v", m)
	}
}

func TestClassifyProviderFromAPIBase(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://api.openai.com/v1", "openai"},
		{"https://api.anthropic.com/v1", "anthropic"},
		{"https://us-east1-aiplatform.googleapis.com/v1", "google"},
		{"https://myresource.openai.azure.com/openai", "azure"},
		{"https://runtime.sagemaker.us-east-1.amazonaws.com", "aws"},
		{"https://api.cohere.ai/v1", "cohere"},
		{"https://api-inference.huggingface.co/models", "huggingface"},
		{"http://localhost:8080/v1", "unknown"},
	}
	for _, tc := range tests {
		if got := classifyProviderFromAPIBase(tc.url); got != tc.want {
			t.Fatalf("classifyProviderFromAPIBase(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestExtractHealthSecrets(t *testing.T) {
	health := &openaicompat.LiteLLMHealthResponse{
		HealthyEndpoints: []map[string]interface{}{
			{
				"model":    "gpt-4",
				"api_base": "https://api.openai.com/v1",
				"api_key":  "sk-openai-secret-key-1234567890abcdef",
			},
			{
				"model":    "claude-3",
				"api_base": "https://api.anthropic.com/v1",
				"api_key":  "sk-ant-anthropic-key-abcdefghij1234567890",
			},
		},
		UnhealthyEndpoints: []map[string]interface{}{
			{
				"model":    "local-model",
				"api_base": "http://ollama:11434",
				"error":    "connection refused",
			},
		},
	}

	secrets := extractHealthSecrets(health)
	if len(secrets) < 2 {
		t.Fatalf("expected at least 2 secrets from health endpoints, got %d: %v", len(secrets), secrets)
	}

	foundOpenAI := false
	foundAnthropic := false
	for _, s := range secrets {
		if strings.Contains(s, "sk-openai-secret-key") {
			foundOpenAI = true
		}
		if strings.Contains(s, "sk-ant-anthropic-key") {
			foundAnthropic = true
		}
	}
	if !foundOpenAI {
		t.Error("expected OpenAI key from healthy_endpoints")
	}
	if !foundAnthropic {
		t.Error("expected Anthropic key from healthy_endpoints")
	}
}

func TestExtractHealthSecrets_NoKeys(t *testing.T) {
	health := &openaicompat.LiteLLMHealthResponse{
		HealthyEndpoints:   []map[string]interface{}{{"model": "gpt-4"}},
		UnhealthyEndpoints: nil,
	}
	secrets := extractHealthSecrets(health)
	for _, s := range secrets {
		if strings.Contains(s, "sk-") || strings.Contains(s, "sk-ant-") {
			t.Fatalf("expected no API key secrets, got %q", s)
		}
	}
}

func TestExtractHealthSecrets_Nil(t *testing.T) {
	health := &openaicompat.LiteLLMHealthResponse{}
	secrets := extractHealthSecrets(health)
	if len(secrets) != 0 {
		t.Fatalf("expected 0 secrets for empty health, got %d", len(secrets))
	}
}

func TestRunLiteLLMEnumAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/readiness", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "healthy", "litellm_version": "9.9.9", "db_connected": "true", "cache_status": "connected",
		})
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"healthy_endpoints": []map[string]any{{"model": "gpt-4"}}, "unhealthy_endpoints": []any{},
		})
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "gpt-4-mini"}},
		})
	})
	mux.HandleFunc("/v1/model/info", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := litellmTarget
	defer func() { litellmTarget = prev }()

	withTestConfig(t, func() {
		litellmTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "litellm-enum.json")

		err := runLiteLLMEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "9.9.9") || !strings.Contains(string(raw), "gpt-4-mini") {
			t.Fatalf("expected readiness version and model id in output, got %s", string(raw))
		}
	})
}

func TestRunLiteLLMConfigExtractAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/model/info", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"model_name": "gpt-4",
					"litellm_params": map[string]any{
						"model":   "gpt-4",
						"api_key": "sk-openai-live-key-1234567890abcdef",
					},
				},
			},
		})
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"healthy_endpoints": []map[string]any{
				{"model": "gpt-4", "api_base": "https://api.openai.com/v1", "api_key": "sk-openai-live-key-1234567890abcdef"},
			},
			"unhealthy_endpoints": []any{},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := litellmTarget
	defer func() { litellmTarget = prev }()

	withTestConfig(t, func() {
		litellmTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "litellm-config-extract.json")

		err := runLiteLLMConfigExtract(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "gpt-4") {
			t.Fatalf("expected model name in output, got %s", out)
		}
		if !strings.Contains(out, "config") {
			t.Fatalf("expected config-extract action in output, got %s", out)
		}
	})
}

func TestRunLiteLLMBudgetProbeAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/model/info", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"model_name": "gpt-4",
					"max_budget": 100.0,
					"tpm":        60000,
					"rpm":        500,
					"litellm_params": map[string]any{
						"model":      "gpt-4",
						"max_budget": 50.0,
					},
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := litellmTarget
	defer func() { litellmTarget = prev }()

	withTestConfig(t, func() {
		litellmTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "litellm-budget.json")

		err := runLiteLLMBudgetProbe(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "budget") {
			t.Fatalf("expected budget reference in output, got %s", out)
		}
		if !strings.Contains(out, "gpt-4") {
			t.Fatalf("expected model name in output, got %s", out)
		}
	})
}

func TestRunLiteLLMProxyChainAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "prod-chat"},
				{"id": "anthropic/claude-3"},
			},
		})
	})
	mux.HandleFunc("/v1/model/info", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"model_name": "prod-chat",
					"litellm_params": map[string]any{
						"model":    "openai/gpt-4",
						"api_base": "https://api.openai.com/v1",
					},
				},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := litellmTarget
	defer func() { litellmTarget = prev }()

	withTestConfig(t, func() {
		litellmTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "litellm-proxy-chain.json")

		err := runLiteLLMProxyChain(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "proxy-chain") {
			t.Fatalf("expected proxy-chain action in output, got %s", out)
		}
		if !strings.Contains(out, "openai") {
			t.Fatalf("expected 'prod-chat' to be classified as openai via model info, got %s", out)
		}
		if !strings.Contains(out, "anthropic") {
			t.Fatalf("expected anthropic provider in output, got %s", out)
		}
	})
}

func TestHTTPStatusFromError(t *testing.T) {
	if got := httpStatusFromError(nil); got != "200" {
		t.Fatalf("nil -> %q, want 200", got)
	}
	if got := httpStatusFromError(fmt.Errorf("listing models: unexpected status 401")); got != "401" {
		t.Fatalf("401 err -> %q, want 401", got)
	}
	if got := httpStatusFromError(fmt.Errorf("dial tcp: connection refused")); got != "error" {
		t.Fatalf("no-code err -> %q, want error", got)
	}
}

// The relay-test must only mark credential_gated when a no-credential control probe to the SAME
// model/provider path is rejected. An open endpoint (with or without a dummy header) must NOT be
// marked gated — the anti-fake-win invariant.
func TestLiteLLMRelayTestCredentialGate(t *testing.T) {
	makeServer := func(gated bool, validKey string) *httptest.Server {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "prod-chat"}}})
		})
		mux.HandleFunc("/v1/model/info", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{
				{"model_name": "prod-chat", "litellm_params": map[string]any{"model": "openai/gpt-4"}},
			}})
		})
		chat := func(w http.ResponseWriter, r *http.Request) {
			if gated && r.Header.Get("Authorization") != "Bearer "+validKey {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{
				{"message": map[string]any{"content": "PROXY_OK. The relay is operational and ready to serve inference."}},
			}})
		}
		mux.HandleFunc("/v1/chat/completions", chat)
		mux.HandleFunc("/chat/completions", chat)
		return httptest.NewServer(mux)
	}

	run := func(t *testing.T, srvURL, apiKey string, headers []string) string {
		t.Helper()
		pT, pK, pH, pR := litellmTarget, litellmAPIKey, litellmHeaders, litellmRelayTest
		defer func() { litellmTarget, litellmAPIKey, litellmHeaders, litellmRelayTest = pT, pK, pH, pR }()
		var out string
		withTestConfig(t, func() {
			litellmTarget = srvURL
			litellmAPIKey = apiKey
			litellmHeaders = headers
			litellmRelayTest = true
			cfg.Format = "json"
			cfg.OutputFile = filepath.Join(t.TempDir(), "out.json")
			_ = runLiteLLMProxyChain(nil, nil)
			raw, err := os.ReadFile(cfg.OutputFile)
			if err != nil {
				t.Fatal(err)
			}
			out = string(raw)
		})
		return out
	}
	gated := func(out string) bool {
		return strings.Contains(out, `"credential_gated":true`) || strings.Contains(out, `"credential_gated": true`)
	}

	t.Run("gated endpoint with looted key -> credential_gated true", func(t *testing.T) {
		srv := makeServer(true, "sk-master")
		defer srv.Close()
		if out := run(t, srv.URL, "sk-master", nil); !gated(out) {
			t.Fatalf("expected credential_gated true, got %s", out)
		}
	})
	t.Run("open endpoint no header -> not gated", func(t *testing.T) {
		srv := makeServer(false, "")
		defer srv.Close()
		if out := run(t, srv.URL, "", nil); gated(out) {
			t.Fatalf("open endpoint must not be credential_gated, got %s", out)
		}
	})
	t.Run("open endpoint random header -> not gated", func(t *testing.T) {
		srv := makeServer(false, "")
		defer srv.Close()
		if out := run(t, srv.URL, "", []string{"Authorization: Bearer dummy"}); gated(out) {
			t.Fatalf("open endpoint with dummy header must not be credential_gated, got %s", out)
		}
	})
}
