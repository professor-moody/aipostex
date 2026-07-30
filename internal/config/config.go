package config

import (
	"net/http"
	"time"

	"github.com/professor-moody/aipostex/internal/runtimehttp"
)

// Set via ldflags at build time
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// Config holds runtime configuration for all modules
type Config struct {
	// Global
	OutputFile         string
	Format             string // "console", "json", "jsonl", "csv", "html", "sarif", "markdown", "pdf"
	Verbose            bool
	Stealth            bool
	Concurrency        int
	Timeout            time.Duration
	FingerprintTimeout time.Duration
	Proxy              string
	Insecure           bool
	ForceExploit       bool   // Enable mutating exploit actions
	AutoChain          bool   // Generate follow-up commands with discovered credentials
	CallbackURL        string // URL for exploit callback delivery (webhook/tcp/dns)
	SessionID          string // Active session ID for grouping findings
	Width              int    // Console framing width (0 = auto-detect from terminal)
	NoBanner           bool   // Suppress the startup banner
	Quiet              bool   // Findings only: suppress the module summary + evidence hint (implies no banner)

	// Discovery
	ScanPaths    []string
	ExcludePaths []string
	RulesDir     string

	// Network
	Targets      []string // CIDR ranges or hosts
	Ports        []int
	MaxHosts     int
	TemplatesDir string
	Tags         []string
	Severities   []string
	DialTimeout  time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		Format:             "console",
		Concurrency:        10,
		Timeout:            10 * time.Second,
		FingerprintTimeout: 15 * time.Second,
		DialTimeout:        1 * time.Second,
		MaxHosts:           65536,
		ExcludePaths: []string{
			".git", "node_modules", "__pycache__", "venv", ".venv",
			".npm", ".yarn", "vendor", ".tox", "dist",
		},
		Ports: []int{
			80,    // HTTP reverse proxy
			443,   // HTTPS reverse proxy
			8443,  // Alternate HTTPS
			11434, // Ollama
			8000,  // vLLM, ChromaDB, Triton, LangServe
			4000,  // LiteLLM
			4001,  // LiteLLM (authed instance)
			8080,  // LocalAI, Weaviate, TorchServe, HF TGI/TEI, KubeFlow, A2A, W&B (self-hosted default)
			8180,  // HF TGI/TEI gateway (common alternate when 8080 is taken by another service)
			8088,  // Alternate HTTP for W&B local / custom reverse-proxy backends
			8081,  // TorchServe management API
			8090,  // LangServe (alternate)
			1234,  // LM Studio
			6333,  // Qdrant
			8888,  // Jupyter
			8889,  // Jupyter (alternate)
			7860,  // Gradio
			8501,  // Streamlit, TensorFlow Serving
			5000,  // MLflow
			8265,  // Ray Dashboard
			3000,  // Various MCP servers, BentoML
			6274,  // MCP Inspector / MCPJam Inspector
			19530, // Milvus
			5432,  // PostgreSQL / pgvector
			8082,  // TorchServe metrics
			8001,  // Triton gRPC
			8002,  // Triton metrics
			6379,  // Redis (vector store / LLM cache)
		},
	}
}

func (c *Config) HTTPOptions() runtimehttp.Options {
	return c.HTTPOptionsWithTimeout(c.Timeout)
}

func (c *Config) HTTPOptionsWithTimeout(timeout time.Duration) runtimehttp.Options {
	return runtimehttp.Options{
		Timeout:  timeout,
		ProxyURL: c.Proxy,
		Insecure: c.Insecure,
		Stealth:  c.Stealth,
	}
}

// NewHTTPClient creates an HTTP client with the configured transport behavior.
func (c *Config) NewHTTPClient() (*http.Client, error) {
	return runtimehttp.NewClient(c.HTTPOptions())
}

func (c *Config) NewFingerprintHTTPClient() (*http.Client, error) {
	return runtimehttp.NewClient(c.HTTPOptionsWithTimeout(c.FingerprintTimeout))
}
