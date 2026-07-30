package config

import (
	"testing"
	"time"
)

func TestDefaultConfigHasSensibleDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Concurrency <= 0 {
		t.Fatalf("expected positive concurrency, got %d", cfg.Concurrency)
	}
	if cfg.Timeout <= 0 {
		t.Fatalf("expected positive timeout, got %v", cfg.Timeout)
	}
	if cfg.FingerprintTimeout <= 0 {
		t.Fatalf("expected positive fingerprint timeout, got %v", cfg.FingerprintTimeout)
	}
	if cfg.MaxHosts <= 0 {
		t.Fatalf("expected positive max hosts, got %d", cfg.MaxHosts)
	}
	if cfg.Format != "console" {
		t.Fatalf("expected default format 'console', got %q", cfg.Format)
	}
	if len(cfg.ExcludePaths) == 0 {
		t.Fatal("expected non-empty default exclude paths")
	}
}

func TestDefaultConfigPortsContainExpectedEntries(t *testing.T) {
	cfg := DefaultConfig()
	expected := map[int]string{
		11434: "Ollama",
		8888:  "Jupyter",
		7860:  "Gradio",
		5000:  "MLflow",
		8265:  "Ray",
		6333:  "Qdrant",
		19530: "Milvus",
		5432:  "PostgreSQL",
		3000:  "MCP/BentoML",
		8001:  "Triton gRPC",
	}
	portSet := make(map[int]bool, len(cfg.Ports))
	for _, p := range cfg.Ports {
		portSet[p] = true
	}
	for port, label := range expected {
		if !portSet[port] {
			t.Errorf("expected default ports to contain %d (%s)", port, label)
		}
	}
}

func TestHTTPOptionsPropagatesSettings(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Proxy = "socks5://127.0.0.1:1080"
	cfg.Insecure = true
	cfg.Stealth = true

	opts := cfg.HTTPOptions()
	if opts.ProxyURL != cfg.Proxy {
		t.Fatalf("expected proxy %q, got %q", cfg.Proxy, opts.ProxyURL)
	}
	if !opts.Insecure {
		t.Fatal("expected Insecure=true")
	}
	if !opts.Stealth {
		t.Fatal("expected Stealth=true")
	}
	if opts.Timeout != cfg.Timeout {
		t.Fatalf("expected timeout %v, got %v", cfg.Timeout, opts.Timeout)
	}
}

func TestHTTPOptionsWithTimeoutOverridesTimeout(t *testing.T) {
	cfg := DefaultConfig()
	custom := 42 * time.Second
	opts := cfg.HTTPOptionsWithTimeout(custom)
	if opts.Timeout != custom {
		t.Fatalf("expected timeout %v, got %v", custom, opts.Timeout)
	}
}

func TestNewHTTPClientReturnsNonNil(t *testing.T) {
	cfg := DefaultConfig()
	client, err := cfg.NewHTTPClient()
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil HTTP client")
	}
}

func TestNewFingerprintHTTPClientReturnsNonNil(t *testing.T) {
	cfg := DefaultConfig()
	client, err := cfg.NewFingerprintHTTPClient()
	if err != nil {
		t.Fatalf("NewFingerprintHTTPClient: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil fingerprint HTTP client")
	}
}
