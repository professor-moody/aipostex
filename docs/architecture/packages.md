# Package Reference

## cmd/aipostex

The CLI layer. All Cobra command definitions, flag parsing, and orchestration logic live here.

| File | Purpose |
|---|---|
| `main.go` | Root command, global persistent flags, subcommand registration |
| `scan.go` | `scan` command -- run YAML vuln templates against targets |
| `scan_files.go` | `discover files` command -- filesystem discovery |
| `scan_network.go` | `discover network` command -- fingerprint + auto-scan |
| `assessment.go` | Scan summaries, finding deduplication, fingerprint dedup |
| `workflow.go` | Workflow plan builder for follow-on command suggestions |
| `ux.go` | Stderr helpers, summary printers, validation errors |
| `exploit_common.go` | `requireForceExploit()`, shared finding builder, output helpers |
| `enrichment.go` | Evidence preview, file reference extraction, stage/landed metadata |
| `target_validation.go` | Target URL normalization and port-missing warnings |
| `templates.go` | `templates` command -- list available templates |
| `template_info.go` | `templates info` command -- show template detail |
| `ollama.go` | Ollama subcommands |
| `vectordb.go` | Vector DB subcommands |
| `jupyter.go` | Jupyter subcommands |
| `mcp.go` | MCP parent command and `enum` subcommand |
| `mcp_analyze.go` | MCP `analyze` subcommand |
| `mcp_poison.go` | MCP `poison` subcommand |
| `mcp_schema.go` | MCP `env-extract` and `chain` subcommands, schema poison helpers |
| `openai_compat.go` | OpenAI-compatible subcommands |
| `ray.go` | Ray subcommands |
| `mlflow.go` | MLflow subcommands |
| `gradio.go` | Gradio subcommands |
| `bentoml.go` | BentoML subcommands |
| `triton.go` | Triton subcommands |
| `torchserve.go` | TorchServe subcommands |
| `litellm.go` | LiteLLM Proxy subcommands (uses openaicompat client) |
| `model_scan.go` | `model-scan` command -- local model file supply-chain scan |
| `scan_all.go` | `assess network` command -- full assessment orchestrator with checkpointing |
| `cli_tree.go` | Command group registration and help categories |
| `cli_flags.go` | Shared flag definitions and binding helpers |
| `workflow_ollama.go` | Ollama-specific workflow plan generation |
| `workflow_jupyter.go` | Jupyter-specific workflow plan generation |
| `workflow_mcp.go` | MCP-specific workflow plan generation |
| `workflow_mlflow.go` | MLflow-specific workflow plan generation |
| `workflow_ray.go` | Ray-specific workflow plan generation |
| `workflow_gradio.go` | Gradio-specific workflow plan generation |
| `workflow_openai.go` | OpenAI-compat-specific workflow plan generation |
| `workflow_vectordb.go` | Vector DB-specific workflow plan generation |
| `merge.go` | `engagement merge` command -- combine JSON or JSONL findings |

---

## pkg/discover

File discovery engine with embedded YAML rules.

### Key Types

**`FileScanner`** -- walks directories with concurrent workers, matches files against rules.

- `NewFileScanner(workers int) *FileScanner`
- `Scan(paths []string, rules []FileRule, excludes []string) ([]report.Finding, error)`
- `ScanDetailed(paths, rules, excludes) ([]FileMatch, ScanStats, error)`

**`FileRule`** -- a single discovery rule parsed from YAML.

- `Name`, `Category`, `Severity`, `Description`
- `FilePatterns` -- glob patterns matched against filenames
- `PathPatterns` -- glob patterns matched against full paths (`**` recursive globs supported)
- `ContentPatterns` -- regex patterns matched against file contents
- `MaxFileSize` -- byte limit for content scanning (default 10MB)

**`FileMatch`** -- a matched file with the rule that triggered it.

- `ToFinding() report.Finding`

### Rule Loading

- `LoadEmbeddedRules() ([]FileRule, error)` -- loads from compiled-in `embed.FS`
- `LoadRules(path string) ([]FileRule, error)` -- loads from a YAML file
- `LoadRulesFromDir(dir string) ([]FileRule, error)` -- loads all YAML in a directory

---

## pkg/fingerprint

Network service fingerprinting with HTTP probes.

### Key Types

**`Scanner`** -- concurrent host/port scanner.

- `NewScanner(timeout time.Duration, concurrency int) *Scanner`
- `NewScannerWithClient(httpClient *http.Client, timeout time.Duration, concurrency int) *Scanner`
- `ScanHost(host string, port int) []Result` -- probe a single host:port, returning all services above `MinSpecificityThreshold`
- `ScanRange(hosts []string, ports []int) []Result` -- concurrent multi-host scan

**`ServiceProbe`** -- defines probes for a service type.

- `Service` -- service identifier (e.g., `ollama`, `chromadb`, `jupyter`)
- `DefaultPort` -- standard port for the service
- `HTTPProbes` -- list of HTTP requests to try

**`HTTPProbe`** -- a single HTTP probe.

- `Method`, `Path`, `Headers`, `Body`
- `MatchStatus`, `MatchBody` -- positive response matching criteria
- `MatchBodyNot` -- reject if body contains this substring (reduces false positives)
- `MatchHeader` -- match response header values (case-insensitive)
- `VersionRegex` -- optional regex to extract version from response body (first capture group)
- `Specificity` -- confidence score (1-100), higher wins

**`Result`** -- a detected service.

- `Host`, `Port`, `Service`, `URL`, `Specificity`
- `Version` -- extracted service version (when `VersionRegex` matched)
- `Details` -- bounded preview of the response body
- `Probes` -- which probe paths matched (diagnostics)
- `ProxyLikely` -- true when 3+ services match the same port (likely behind a reverse proxy)

### Built-in Probes

`BuiltinProbes()` returns probes for more than two dozen services. See [Network Discovery](../operator-guide/network-discovery.md) for the full list.

### Utilities

- `ExpandCIDR(cidr string) ([]string, error)` -- expands CIDR notation to individual IPs

---

## pkg/vulncheck

Template-based vulnerability scanning engine.

### Key Types

**`Engine`** -- loads templates, executes scans.

- `NewEngine(timeout time.Duration, concurrency int) *Engine`
- `LoadTemplates(dir string) error` -- load from directory
- `LoadEmbeddedTemplates() error` -- load compiled-in templates
- `Scan(targets []string) ([]report.Finding, error)`
- `ExecuteTemplate(tmpl Template, target string) ([]report.Finding, error)`
- `FilteredTemplates(tags, severities []string) []Template`

**`Template`** -- a parsed YAML vulnerability template.

- `ID`, `Info` (name, severity, CVSS, author, description, references, tags, classification)
- `Detect` -- optional pre-check HTTP steps
- `Checks` -- vulnerability check steps with matchers and extractors

**`Matcher`** -- response matching rule.

- Types: `status`, `body_contains`, `body_not_contains`, `body_regex`, `header_contains`, `json_path`

**`Extractor`** -- data extraction from responses.

- Types: `regex` (with capture group), `json` (gjson path), `header`
- Extracted values populate `{{variable}}` placeholders in finding text

**`ScanMetrics`** -- counters for templates considered, matched, findings emitted, `RequestErrors` (network failures), and `TemplateErrors` (malformed URLs or template issues).

---

## pkg/exploit

Post-exploitation client libraries. Each subdirectory implements a client for one AI service family.

### common

Shared HTTP helpers used by all exploit clients.

- `NormalizeTarget(raw string) string` -- normalize URL (add scheme, strip trailing slash)
- `NewHTTPClient(timeout) (*http.Client, error)` -- create client via `runtimehttp`
- `NewHTTPClientWithOptions(opts) (*http.Client, error)` -- with full transport options
- `ParseHeaderFlags(values []string) (http.Header, error)` -- parse `Key: Value` flag format
- `DoJSON(client, req, &result) error` -- execute request, decode JSON response

### ollama

Ollama LLM API client.

- `NewClient(ctx, baseURL, timeout) (*Client, error)` / `NewClientWithHeaders(ctx, baseURL, timeout, headers) (*Client, error)`
- Read: `Ping`, `Version`, `ListModels`, `ShowModel`, `ListRunning`, `Generate`, `Enumerate`
- Write: `CreateModel`, `CopyModel`, `DeleteModel`
- Utility: `ExtractSystemPrompt(modelfile string) string`, `ShowResponse.SystemPrompt() string` (prefers `System` field over Modelfile parsing)

### vectordb

Multi-provider vector database client supporting ChromaDB, Weaviate, Qdrant, Milvus, and pgvector.

- `NewProviderClient(ctx, provider, target, timeout, headers) (ProviderClient, error)`
- **ProviderClient interface**: `ProviderName`, `ServiceVersion`, `ListCollectionsInfo`, `ExtractDocuments`
- **InjectableProvider interface**: `InjectDocument(collection, payload, metadata, count)`
- **MetadataInjectableProvider interface**: `InjectAndVerifyMetadata(collection, key, payload)`
- ChromaDB-specific: `SearchSensitive`, `SearchSensitiveDocuments`, `DefaultSensitivePatterns` (27 patterns)
- ChromaDB collection listing: tenant/database-aware fallback for 0.6.x compatibility
- Milvus: REST API v2.4+ on port 19530 (`/v2/vectordb/collections/list`, `/v2/vectordb/entities/query`)
- pgvector: PostgreSQL wire protocol via `pgx/v5`, table introspection, vector column detection
- Shared types: `Document` (ID, Content, Metadata), `CollectionInfo` (ID, Name, Count)

### jupyter

Jupyter Notebook API client with WebSocket kernel execution.

- `NewClient(ctx, baseURL, token, timeout, extraHeaders) (*Client, error)`
- Read: `ServerStatus`, `ListKernels`, `ListNotebooks`, `ReadNotebook`
- Write: `Execute(kernelID, code string)` -- via WebSocket shell channel

### mcp

MCP (Model Context Protocol) JSON-RPC client.

- `NewClient(ctx, baseURL, timeout, headers) (*Client, error)`
- Remote: `Initialize`, `ListTools`, `ListPrompts`, `ListResources`, `CallTool`, `Poison`
- Local: `LoadConfig`, `ExtractCredentialEnv`, `FindToolCollisions`, `AnalyzeLocalServer`
- Classification: `ClassifyTool`, `ClassifyToolDetailed`, `SelectTool`, `InferTransport`
- Inspector: `ProbeInspector`

### openaicompat

Generic OpenAI-compatible API client.

- `NewClient(ctx, baseURL, timeout, headers) (*Client, error)`
- Read: `ListModels`, `ValidateInference`, `PromptExtract`, `AuthSweep`
- Write: `Throughput`, `ProxyTest`
- Scoring: `HighValueModel`, `ModelValueScore`, `IsCoherentResponse`, `ScoreInferenceResponse`

### ray

Ray Dashboard API client.

- `NewClient(ctx, baseURL, timeout, headers) (*Client, error)`
- Read: `DashboardInfo`, `ListJobs` (handles both array and object formats), `JobDetails`
- Write: `SubmitJob`
- `Job` struct includes `RuntimeEnv` and `Metadata` for credential extraction from `env_vars`
- Utility: `HarmlessRuntimeEnv`, `ParseRuntimeEnv`

### mlflow

MLflow Tracking API client.

- `NewClient(ctx, baseURL, timeout, headers) (*Client, error)`
- Read: `ServerInfo` (root path + `/health`), `ListExperiments`, `ListRuns`, `ListArtifacts`, `ListRegisteredModels` (GET-first, POST fallback), `ListModelVersions`, `DownloadArtifact`

### gradio

Gradio API client.

- `NewClient(ctx, baseURL, timeout, headers) (*Client, error)`
- Read: `Config`, `Predict`, `DownloadFile`
- Write: `QueueProbe`, `UploadFile`, `ServeProbe`

### bentoml

BentoML model serving client.

- `NewClient(ctx, baseURL, timeout, headers) (*Client, error)`
- Read: `Enumerate`, `ListRoutes`, `Metrics`
- Write: `Predict`

### triton

NVIDIA Triton Inference Server client (KFServing v2 protocol).

- `NewClient(ctx, baseURL, timeout, headers) (*Client, error)`
- Read: `Enumerate`, `ListModels`, `ModelDetail`, `ModelConfigDetail`, `RepositoryIndex`, `SHMProbe`
- Write: `Infer`, `LoadModel`, `UnloadModel`

### torchserve

PyTorch TorchServe client (management + inference + metrics APIs).

- `NewClient(ctx, baseURL, timeout, headers) (*Client, error)`
- Read: `Enumerate`, `ListModels`, `ModelDetail`, `Metrics`
- Write: `Predict`, `Register`, `Scale`, `Unregister`

---

## pkg/report

Unified finding schema.

### Key Types

**`Finding`** -- the atomic output unit shared across all modules.

- See [Finding Schema](../output/finding-schema.md) for complete field documentation.

**`FindingCollection`** -- wraps findings for JSON output.

- `EngagementID`, `StartTime`, `EndTime`, `Findings`
- `NewCollection()`, `Add(Finding)`, `ToJSON()`, `Stats()`

### Constants

- Severity: `SeverityCritical`, `SeverityHigh`, `SeverityMedium`, `SeverityLow`, `SeverityInfo`
- Sources: `SourceFileDiscovery`, `SourceFingerprint`, `SourceVulnCheck`, `SourceOllama`, `SourceVectorDB`, `SourceMCP`, `SourceJupyter`, `SourceOpenAICompat`, `SourceRay`, `SourceMLflow`, `SourceGradio`, `SourceBentoML`, `SourceTriton`, `SourceTorchServe`, `SourceCredential`

---

## internal/config

Runtime configuration.

**`Config`** -- holds all runtime settings populated from CLI flags.

- Global: `OutputFile`, `Format`, `Verbose`, `Stealth`, `Concurrency`, `Timeout`, `Proxy`, `Insecure`, `ForceExploit`
- Discovery: `ScanPaths`, `ExcludePaths`, `RulesDir`
- Network: `Targets`, `Ports`, `MaxHosts`, `TemplatesDir`, `Tags`, `Severities`

`DefaultConfig()` returns sensible defaults including the standard AI port list and directory exclusions.

`HTTPOptions()` converts config into `runtimehttp.Options` for HTTP client creation.

---

## internal/output

Output formatting layer implementing the `Writer` interface.

**`Writer` interface:**

```go
type Writer interface {
    WriteFinding(f report.Finding) error
    WriteHeader() error
    WriteFooter(stats map[string]int) error
    Close() error
}
```

| Implementation | Behavior |
|---|---|
| `ConsoleWriter` | Color-coded severity badges, metadata context, workflow recommendations, evidence previews. Banner shown only on interactive TTY. |
| `JSONWriter` | Buffers all findings, writes complete `FindingCollection` JSON on `WriteFooter()`. |
| `JSONLWriter` | Streams one JSON object per line as findings arrive. |

---

## internal/runtimehttp

HTTP transport layer with security and OPSEC features.

**`Options`** -- transport configuration.

- `Timeout`, `ProxyURL`, `Insecure`, `Stealth`

**Transport features:**

- Proxy: HTTP, HTTPS, and SOCKS5 support for both HTTP clients and WebSocket dialers
- TLS: `InsecureSkipVerify` when `--insecure` is set
- Stealth: `stealthRoundTripper` wraps the base transport with User-Agent rotation (10 browser strings covering Chrome, Firefox, Edge, Safari, and Opera across macOS, Windows, and Linux) and 1-5 second jitter per request
- Default UA: fingerprint probe requests set a default browser User-Agent even without stealth mode
- Redirect: Follows up to 3 redirects

**Functions:**

- `NewClient(opts) (*http.Client, error)`
- `NewTransport(opts) (http.RoundTripper, error)`
- `NewWebsocketDialer(opts) (*websocket.Dialer, error)`
- `LimitRedirects(max int) func(*http.Request, []*http.Request) error` -- reusable redirect policy
