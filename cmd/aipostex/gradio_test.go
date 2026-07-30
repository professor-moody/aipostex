package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	exploitgradio "github.com/professor-moody/aipostex/pkg/exploit/gradio"
)

func TestGradioPredictRequiresExactlyOneSelectorAndInputJSON(t *testing.T) {
	prevTarget := gradioTarget
	prevAPIName := gradioAPIName
	prevFnIndex := gradioFnIndex
	prevInputJSON := gradioInputJSON
	defer func() {
		gradioTarget = prevTarget
		gradioAPIName = prevAPIName
		gradioFnIndex = prevFnIndex
		gradioInputJSON = prevInputJSON
	}()

	gradioTarget = "http://127.0.0.1:7860"
	gradioAPIName = ""
	gradioFnIndex = -1
	gradioInputJSON = ""

	err := runGradioPredict(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--api-name or --fn-index") {
		t.Fatalf("expected selector validation error, got %v", err)
	}

	gradioAPIName = "predict"
	gradioFnIndex = 0
	err = runGradioPredict(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--api-name or --fn-index") {
		t.Fatalf("expected mutual exclusion validation error, got %v", err)
	}

	gradioFnIndex = -1
	err = runGradioPredict(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--input-json") {
		t.Fatalf("expected input-json validation error, got %v", err)
	}
}

func TestGradioActiveCommandsRequireForceExploit(t *testing.T) {
	prevTarget := gradioTarget
	prevAPIName := gradioAPIName
	prevFnIndex := gradioFnIndex
	prevInputJSON := gradioInputJSON
	defer func() {
		gradioTarget = prevTarget
		gradioAPIName = prevAPIName
		gradioFnIndex = prevFnIndex
		gradioInputJSON = prevInputJSON
	}()

	withTestConfig(t, func() {
		gradioTarget = "http://127.0.0.1:7860"
		gradioAPIName = "predict"
		gradioFnIndex = -1
		gradioInputJSON = `["hello"]`
		cfg.ForceExploit = false

		if err := runGradioQueueProbe(nil, nil); err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected queue-probe to require --force-exploit, got %v", err)
		}
		if err := runGradioUploadFile(nil, nil); err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected upload-file to require --force-exploit, got %v", err)
		}
	})
}

func TestRunGradioEnumAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/config", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "4.21.0",
			"title":   "Test Gradio App",
			"dependencies": []map[string]any{
				{
					"api_name": "/predict",
					"fn_index": 0,
					"queue":    true,
					"inputs":   []int{1},
					"outputs":  []int{2},
				},
			},
			"components": []map[string]any{
				{"id": 1, "type": "textbox"},
				{"id": 2, "type": "textbox"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := gradioTarget
	prevFactory := gradioClientFactory
	defer func() {
		gradioTarget = prevTarget
		gradioClientFactory = prevFactory
	}()

	withTestConfig(t, func() {
		gradioTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "gradio-enum.json")

		gradioClientFactory = func() (*exploitgradio.Client, http.Header, error) {
			client, err := exploitgradio.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runGradioEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "Test Gradio App") {
			t.Fatalf("expected app title in output, got %s", out)
		}
		if !strings.Contains(out, "/predict") {
			t.Fatalf("expected endpoint name in output, got %s", out)
		}
	})
}

func TestRunGradioDownloadFileAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "file") || strings.Contains(r.URL.RawQuery, "demo.txt") {
			_, _ = w.Write([]byte("secret-file-content-from-gradio"))
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := gradioTarget
	prevFactory := gradioClientFactory
	prevFile := gradioFile
	defer func() {
		gradioTarget = prevTarget
		gradioClientFactory = prevFactory
		gradioFile = prevFile
	}()

	withTestConfig(t, func() {
		gradioTarget = srv.URL
		gradioFile = "/tmp/gradio/demo.txt"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "gradio-download.json")

		gradioClientFactory = func() (*exploitgradio.Client, http.Header, error) {
			client, err := exploitgradio.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runGradioDownloadFile(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "download-file") {
			t.Fatalf("expected download-file action in output, got %s", out)
		}
		if !strings.Contains(out, "demo.txt") {
			t.Fatalf("expected file path in output, got %s", out)
		}
	})
}

func TestRunGradioFileChainAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "file") || strings.Contains(r.URL.RawQuery, "chain.txt") {
			_, _ = w.Write([]byte("chained-content /tmp/gradio/nested.txt"))
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := gradioTarget
	prevFactory := gradioClientFactory
	prevFile := gradioFile
	defer func() {
		gradioTarget = prevTarget
		gradioClientFactory = prevFactory
		gradioFile = prevFile
	}()

	withTestConfig(t, func() {
		gradioTarget = srv.URL
		gradioFile = "/tmp/gradio/chain.txt"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "gradio-file-chain.json")

		gradioClientFactory = func() (*exploitgradio.Client, http.Header, error) {
			client, err := exploitgradio.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runGradioFileChain(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "file-chain") {
			t.Fatalf("expected file-chain action in output, got %s", out)
		}
		if !strings.Contains(out, "chain.txt") {
			t.Fatalf("expected file path in output, got %s", out)
		}
	})
}

func TestRunGradioPredictAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/gradio_api/call/predict", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":["Hello from test predict"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := gradioTarget
	prevFactory := gradioClientFactory
	prevAPIName := gradioAPIName
	prevFnIndex := gradioFnIndex
	prevInputJSON := gradioInputJSON
	defer func() {
		gradioTarget = prevTarget
		gradioClientFactory = prevFactory
		gradioAPIName = prevAPIName
		gradioFnIndex = prevFnIndex
		gradioInputJSON = prevInputJSON
	}()

	withTestConfig(t, func() {
		gradioTarget = srv.URL
		gradioAPIName = "predict"
		gradioFnIndex = -1
		gradioInputJSON = `["hello"]`
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "gradio-predict.json")

		gradioClientFactory = func() (*exploitgradio.Client, http.Header, error) {
			client, err := exploitgradio.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runGradioPredict(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "predict") {
			t.Fatalf("expected predict action in output, got %s", out)
		}
		if !strings.Contains(out, "Hello from test predict") {
			t.Fatalf("expected response evidence in output, got %s", out)
		}
	})
}

func TestRunGradioQueueProbeAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/queue/join", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"event_id":"test-evt-123","hash":"test-hash"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := gradioTarget
	prevFactory := gradioClientFactory
	prevAPIName := gradioAPIName
	prevFnIndex := gradioFnIndex
	prevInputJSON := gradioInputJSON
	defer func() {
		gradioTarget = prevTarget
		gradioClientFactory = prevFactory
		gradioAPIName = prevAPIName
		gradioFnIndex = prevFnIndex
		gradioInputJSON = prevInputJSON
	}()

	withTestConfig(t, func() {
		gradioTarget = srv.URL
		gradioAPIName = "predict"
		gradioFnIndex = -1
		gradioInputJSON = `["hello"]`
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "gradio-queue-probe.json")
		cfg.ForceExploit = true

		gradioClientFactory = func() (*exploitgradio.Client, http.Header, error) {
			client, err := exploitgradio.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runGradioQueueProbe(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "queue") {
			t.Fatalf("expected queue action in output, got %s", out)
		}
	})
}

func TestRunGradioUploadFileAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/upload", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`["/tmp/gradio/aipostex-proof.txt"]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := gradioTarget
	prevFactory := gradioClientFactory
	defer func() {
		gradioTarget = prevTarget
		gradioClientFactory = prevFactory
	}()

	withTestConfig(t, func() {
		gradioTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "gradio-upload.json")
		cfg.ForceExploit = true

		gradioClientFactory = func() (*exploitgradio.Client, http.Header, error) {
			client, err := exploitgradio.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runGradioUploadFile(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "upload-file") {
			t.Fatalf("expected upload-file action in output, got %s", out)
		}
	})
}

func TestRunGradioServeProbeAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "file") || strings.Contains(r.URL.RawQuery, "served.txt") {
			_, _ = w.Write([]byte("served-content-from-gradio"))
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := gradioTarget
	prevFactory := gradioClientFactory
	prevFile := gradioFile
	defer func() {
		gradioTarget = prevTarget
		gradioClientFactory = prevFactory
		gradioFile = prevFile
	}()

	withTestConfig(t, func() {
		gradioTarget = srv.URL
		gradioFile = "/tmp/gradio/served.txt"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "gradio-serve-probe.json")
		cfg.ForceExploit = true

		gradioClientFactory = func() (*exploitgradio.Client, http.Header, error) {
			client, err := exploitgradio.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runGradioServeProbe(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "serve-probe") {
			t.Fatalf("expected serve-probe action in output, got %s", out)
		}
		if !strings.Contains(out, "served.txt") {
			t.Fatalf("expected file path in output, got %s", out)
		}
	})
}

// The enum plan must never emit a bare <file-ref> TODO, and a gated (--force-exploit)
// command must never carry a placeholder: queue-probe/upload-file are only offered once
// enum named a real endpoint, and serve-probe (which needs a concrete file handle) is
// dropped from enum entirely. When a handle IS known, the file builders thread it.
func TestGradioWorkflowPlansNoPlaceholderInGatedOrFileRef(t *testing.T) {
	// No endpoint discovered: gated probes must be omitted, not emitted with <api-name>.
	empty := buildGradioEnumWorkflowPlan("http://127.0.0.1:7860", nil, nil)
	for _, r := range empty.Recommendations {
		if r.Gated && strings.Contains(r.Command, "<") {
			t.Fatalf("gated enum command carries a placeholder with no discovered endpoint: %q", r.Command)
		}
		if strings.Contains(r.Command, "<file-ref>") {
			t.Fatalf("enum plan leaked a bare <file-ref> TODO: %q", r.Command)
		}
		if r.Gated && strings.Contains(r.Command, "serve-probe") {
			t.Fatalf("enum plan offered serve-probe with no concrete file handle: %q", r.Command)
		}
	}

	// Endpoint discovered: the gated probes appear and name the real endpoint.
	named := buildGradioEnumWorkflowPlan("http://127.0.0.1:7860", []string{"predict"}, []int{0})
	var gatedNamed bool
	for _, r := range named.Recommendations {
		if r.Gated {
			gatedNamed = true
			if strings.Contains(r.Command, "<") {
				t.Fatalf("gated command carries a placeholder despite a discovered endpoint: %q", r.Command)
			}
		}
	}
	if !gatedNamed {
		t.Fatalf("expected gated probes once an endpoint was discovered")
	}

	// A concrete downloaded/handled file threads into the follow-on chain.
	dl := buildGradioDownloadFileSummaryWorkflowPlan("http://127.0.0.1:7860", "/tmp/secret.txt")
	if !strings.Contains(dl.Recommendations[0].Command, "--file /tmp/secret.txt") {
		t.Fatalf("expected the concrete file handle threaded into the file-chain, got %q", dl.Recommendations[0].Command)
	}
}
