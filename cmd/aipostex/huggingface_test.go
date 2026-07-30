package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
)

func newHFTGIMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model_id":"meta-llama/Llama-2-7b-chat-hf","model_sha":"abc123","version":"2.0.0","max_input_length":4096,"max_total_tokens":4096}`))
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"meta-llama/Llama-2-7b-chat-hf","object":"model"}]}`))
	})
	mux.HandleFunc("/generate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"generated_text":"Hello!"}`))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("# HELP tgi_request_count\ntgi_request_count 42\n"))
	})
	return httptest.NewServer(mux)
}

func newHFTEIMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model_id":"BAAI/bge-base-en-v1.5","model_type":"bert","version":"1.0.0"}`))
	})
	mux.HandleFunc("/embed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[[0.1,0.2,0.3]]`))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("# HELP te_request_count\nte_request_count 10\n"))
	})
	return httptest.NewServer(mux)
}

func TestRunHFEnumAgainstMockServer(t *testing.T) {
	srv := newHFTGIMockServer(t)
	defer srv.Close()

	prev := hfTarget
	defer func() { hfTarget = prev }()

	withTestConfig(t, func() {
		hfTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-enum.json")

		err := runHFEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "huggingface") {
			t.Fatalf("expected huggingface in output, got %s", string(raw))
		}
	})
}

func TestNewHFClientUsesRuntimeHTTPConfig(t *testing.T) {
	prevTarget, prevHeaders := hfTarget, hfHeaders
	defer func() {
		hfTarget = prevTarget
		hfHeaders = prevHeaders
	}()

	withTestConfig(t, func() {
		hfTarget = "http://127.0.0.1:8080"
		cfg.Proxy = "http://[::1"
		if _, err := newHFClient(); err == nil {
			t.Fatal("expected invalid proxy from runtime HTTP config to be surfaced")
		}
	})
}

func TestRunHFModelsAgainstMockServer(t *testing.T) {
	srv := newHFTGIMockServer(t)
	defer srv.Close()

	prev := hfTarget
	defer func() { hfTarget = prev }()

	withTestConfig(t, func() {
		hfTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-models.json")

		err := runHFModels(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "Llama") {
			t.Fatalf("expected model name in output, got %s", string(raw))
		}
	})
}

func TestRunHFMetricsAgainstMockServer(t *testing.T) {
	srv := newHFTGIMockServer(t)
	defer srv.Close()

	prev := hfTarget
	defer func() { hfTarget = prev }()

	withTestConfig(t, func() {
		hfTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-metrics.json")

		err := runHFMetrics(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "metrics") {
			t.Fatalf("expected metrics in output, got %s", string(raw))
		}
	})
}

func TestRunHFModelDownloadAgainstMockHub(t *testing.T) {
	tgi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/info" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model_id":"org/test-model","sha":"abc123","version":"2.0.0","max_input_length":4096}`))
	}))
	defer tgi.Close()

	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hub-token" {
			t.Fatalf("expected explicit hub token, got %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/org/test-model/resolve/main/config.json":
			_, _ = w.Write([]byte(`{"model_type":"gpt"}`))
		case "/org/test-model/resolve/main/model.safetensors":
			_, _ = w.Write([]byte("0123456789abcdef"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer hub.Close()

	prevTarget, prevModelID, prevRevision, prevFiles := hfTarget, hfModelID, hfRevision, hfDownloadFiles
	prevMax, prevMaxBytes, prevPerFile := hfDownloadMax, hfDownloadMaxBytes, hfDownloadPerFile
	prevDir, prevHubBase, prevHubHeaders, prevForce := hfDownloadDir, hfHubBase, hfHubHeaders, cfg.ForceExploit
	defer func() {
		hfTarget, hfModelID, hfRevision, hfDownloadFiles = prevTarget, prevModelID, prevRevision, prevFiles
		hfDownloadMax, hfDownloadMaxBytes, hfDownloadPerFile = prevMax, prevMaxBytes, prevPerFile
		hfDownloadDir, hfHubBase, hfHubHeaders, cfg.ForceExploit = prevDir, prevHubBase, prevHubHeaders, prevForce
	}()

	withTestConfig(t, func() {
		outDir := filepath.Join(t.TempDir(), "hf-download")
		hfTarget = tgi.URL
		hfModelID = ""
		hfRevision = "main"
		hfDownloadFiles = []string{"config.json", "model.safetensors"}
		hfDownloadMax = 2
		hfDownloadMaxBytes = 64
		hfDownloadPerFile = 16
		hfDownloadDir = outDir
		hfHubBase = hub.URL
		hfHubHeaders = []string{"Authorization: Bearer hub-token"}
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-model-download.json")

		err := runHFModelDownload(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %T: %v", err, err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		for _, want := range []string{"model-download", "org/test-model", "config.json", "model.safetensors", "takeover-capable", "bytes_read"} {
			if !strings.Contains(out, want) {
				t.Fatalf("expected %q in output, got %s", want, out)
			}
		}
		if _, err := os.Stat(filepath.Join(outDir, "org_test-model", "01-config.json")); err != nil {
			t.Fatalf("expected saved config file: %v", err)
		}
		if _, err := os.Stat(filepath.Join(outDir, "org_test-model", "02-model.safetensors")); err != nil {
			t.Fatalf("expected saved model file: %v", err)
		}
	})
}

func TestRunHFModelDownloadDefaultsHubBaseToTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"model_id":"org/test-model","sha":"abc123","version":"2.0.0","max_input_length":4096}`))
		case "/org/test-model/resolve/main/config.json":
			if r.Header.Get("Range") == "" {
				t.Fatalf("expected bounded Range request")
			}
			_, _ = w.Write([]byte(`{"model_type":"gpt"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	prevTarget, prevModelID, prevRevision, prevFiles := hfTarget, hfModelID, hfRevision, hfDownloadFiles
	prevMax, prevMaxBytes, prevPerFile := hfDownloadMax, hfDownloadMaxBytes, hfDownloadPerFile
	prevDir, prevHubBase, prevHubHeaders, prevForce := hfDownloadDir, hfHubBase, hfHubHeaders, cfg.ForceExploit
	defer func() {
		hfTarget, hfModelID, hfRevision, hfDownloadFiles = prevTarget, prevModelID, prevRevision, prevFiles
		hfDownloadMax, hfDownloadMaxBytes, hfDownloadPerFile = prevMax, prevMaxBytes, prevPerFile
		hfDownloadDir, hfHubBase, hfHubHeaders, cfg.ForceExploit = prevDir, prevHubBase, prevHubHeaders, prevForce
	}()

	withTestConfig(t, func() {
		hfTarget = srv.URL
		hfModelID = ""
		hfRevision = "main"
		hfDownloadFiles = []string{"config.json"}
		hfDownloadMax = 1
		hfDownloadMaxBytes = 64
		hfDownloadPerFile = 16
		hfDownloadDir = ""
		hfHubBase = ""
		hfHubHeaders = nil
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-model-download-default-hub.json")

		err := runHFModelDownload(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %T: %v", err, err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		for _, want := range []string{`"hub_base":"` + srv.URL + `"`, "model-download", "org/test-model", "config.json", `"bytes_read":16`} {
			if !strings.Contains(out, want) {
				t.Fatalf("expected %q in output, got %s", want, out)
			}
		}
	})
}

func TestRunHFModelDownloadFailureIsReachableOnly(t *testing.T) {
	tgi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model_id":"org/missing-model","version":"2.0.0"}`))
	}))
	defer tgi.Close()
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("missing"))
	}))
	defer hub.Close()

	prevTarget, prevModelID, prevRevision, prevFiles := hfTarget, hfModelID, hfRevision, hfDownloadFiles
	prevMax, prevMaxBytes, prevPerFile := hfDownloadMax, hfDownloadMaxBytes, hfDownloadPerFile
	prevDir, prevHubBase, prevHubHeaders, prevForce := hfDownloadDir, hfHubBase, hfHubHeaders, cfg.ForceExploit
	defer func() {
		hfTarget, hfModelID, hfRevision, hfDownloadFiles = prevTarget, prevModelID, prevRevision, prevFiles
		hfDownloadMax, hfDownloadMaxBytes, hfDownloadPerFile = prevMax, prevMaxBytes, prevPerFile
		hfDownloadDir, hfHubBase, hfHubHeaders, cfg.ForceExploit = prevDir, prevHubBase, prevHubHeaders, prevForce
	}()

	withTestConfig(t, func() {
		hfTarget = tgi.URL
		hfModelID = ""
		hfRevision = "main"
		hfDownloadFiles = []string{"config.json"}
		hfDownloadMax = 1
		hfDownloadMaxBytes = 64
		hfDownloadPerFile = 16
		hfDownloadDir = ""
		hfHubBase = hub.URL
		hfHubHeaders = nil
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-model-download-missing.json")

		err := runHFModelDownload(nil, nil)
		if _, ok := err.(*exitcode.FindingsPartialError); !ok {
			t.Fatalf("expected FindingsPartialError, got %T: %v", err, err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		for _, want := range []string{"model download not confirmed", "reachable", `"files_found":0`, `"bytes_read":0`} {
			if !strings.Contains(out, want) {
				t.Fatalf("expected %q in output, got %s", want, out)
			}
		}
		if strings.Contains(out, "takeover-capable") {
			t.Fatalf("failed downloads must not claim takeover-capable: %s", out)
		}
	})
}

func TestRunHFGenerateEvidenceLabelsPromptAndResponse(t *testing.T) {
	srv := newHFTGIMockServer(t)
	defer srv.Close()

	prevTarget := hfTarget
	prevPrompt := hfPrompt
	prevForce := cfg.ForceExploit
	defer func() {
		hfTarget = prevTarget
		hfPrompt = prevPrompt
		cfg.ForceExploit = prevForce
	}()

	withTestConfig(t, func() {
		hfTarget = srv.URL
		hfPrompt = "Hello"
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-generate.json")

		err := runHFGenerate(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		for _, want := range []string{`prompt=\"Hello\"`, `status=200`, `response=\"Hello!\"`} {
			if !strings.Contains(out, want) {
				t.Fatalf("expected %s in output, got %s", want, out)
			}
		}
	})
}

// newHFOpenTGIServer returns generated text for ANY request — even with no
// credential — modelling an open, unauthenticated TGI.
func newHFOpenTGIServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/generate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"generated_text":"Hello from open TGI"}`))
	})
	return httptest.NewServer(mux)
}

// newHFGatedTGIServer rejects /generate without an Authorization header (401) and
// serves it with one — modelling a credential-gated TGI gateway.
func newHFGatedTGIServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"missing credential"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"generated_text":"Hello from gated TGI"}`))
	})
	return httptest.NewServer(mux)
}

// TestRunHFGenerateOpenServerIsNotCredentialReplay proves the no-credential
// control probe prevents the over-claim: a supplied Authorization header against
// an OPEN server must NOT be reported as a credential replay.
func TestRunHFGenerateOpenServerIsNotCredentialReplay(t *testing.T) {
	srv := newHFOpenTGIServer(t)
	defer srv.Close()

	prevTarget, prevPrompt, prevHeaders, prevForce := hfTarget, hfPrompt, hfHeaders, cfg.ForceExploit
	defer func() {
		hfTarget, hfPrompt, hfHeaders, cfg.ForceExploit = prevTarget, prevPrompt, prevHeaders, prevForce
	}()

	withTestConfig(t, func() {
		hfTarget = srv.URL
		hfPrompt = "Hello"
		hfHeaders = []string{"Authorization: Bearer looted-token"}
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-open.json")

		if err := runHFGenerate(nil, nil); err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if strings.Contains(out, "credential replay") {
			t.Fatalf("open server must NOT be titled a credential replay: %s", out)
		}
		if !strings.Contains(out, "unauthenticated generation") {
			t.Fatalf("expected unauthenticated-generation title for open server: %s", out)
		}
		if !strings.Contains(out, "credential_gated=false") {
			t.Fatalf("expected credential_gated=false evidence: %s", out)
		}
	})
}

// TestRunHFGenerateGatedServerIsCredentialReplay proves the control probe
// confirms a replay when the endpoint genuinely rejects an un-credentialed call.
func TestRunHFGenerateGatedServerIsCredentialReplay(t *testing.T) {
	srv := newHFGatedTGIServer(t)
	defer srv.Close()

	prevTarget, prevPrompt, prevHeaders, prevForce := hfTarget, hfPrompt, hfHeaders, cfg.ForceExploit
	defer func() {
		hfTarget, hfPrompt, hfHeaders, cfg.ForceExploit = prevTarget, prevPrompt, prevHeaders, prevForce
	}()

	withTestConfig(t, func() {
		hfTarget = srv.URL
		hfPrompt = "Hello"
		hfHeaders = []string{"Authorization: Bearer looted-token"}
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-gated.json")

		if err := runHFGenerate(nil, nil); err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("expected FindingsError, got %v", err)
			}
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "credential replay") {
			t.Fatalf("gated server must be titled a credential replay: %s", out)
		}
		if !strings.Contains(out, "credential_gated=true") {
			t.Fatalf("expected credential_gated=true evidence: %s", out)
		}
		if !strings.Contains(out, "auth_control_status=401") {
			t.Fatalf("expected auth_control_status=401 evidence: %s", out)
		}
	})
}

func TestRunHFEmbedAgainstMockServer(t *testing.T) {
	srv := newHFTEIMockServer(t)
	defer srv.Close()

	prev := hfTarget
	prevInputs := hfInputs
	defer func() {
		hfTarget = prev
		hfInputs = prevInputs
	}()

	withTestConfig(t, func() {
		hfTarget = srv.URL
		hfInputs = []string{"test sentence"}
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "hf-embed.json")

		err := runHFEmbed(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "embed") {
			t.Fatalf("expected embed in output, got %s", string(raw))
		}
	})
}
