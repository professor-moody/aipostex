# Network Discovery

The `discover network` command fingerprints AI services using HTTP-based probes, then optionally runs vulnerability templates against discoveries.

## How Fingerprinting Works

For each host:port combination:

1. **TCP connect** -- verify the port is open
2. **HTTP probes** -- send HTTP requests matching known AI service patterns
3. **HTTPS fallback** -- ports 443, 8443, 9443 prefer HTTPS; others try HTTP first
4. **Multi-result** -- all services above the minimum specificity threshold (30) are returned. Port-affinity ordering runs port-matched probes first. A specificity-100 match short-circuits the remaining probes.

Each service has one or more `HTTPProbe` definitions with:

- HTTP method and path
- Expected status code and/or body content
- `MatchBodyNot` -- reject if body contains this substring (reduces false positives)
- `MatchHeader` -- match response header values (case-insensitive)
- `VersionRegex` -- extract version from response body (first capture group)
- Specificity score (1-100) -- higher means more confident

When multiple services match on the same host:port, all are returned. When 3+ distinct services match on a single port, results are flagged as `proxy_likely` (likely behind a reverse proxy).

## Detected Services

aipostex detects more than two dozen AI services out of the box:

| Service | Default Port | Probes | Specificity | Version |
|---|---|---|---|---|
| **Ollama** | 11434 | `GET /` (body: "Ollama is running"), `GET /api/tags` | Medium-High | -- |
| **ChromaDB** | 8000 | `GET /api/v2/heartbeat`, `GET /api/v1/heartbeat` | High | -- |
| **vLLM** | 8000 | `GET /v1/models`, `GET /health` | Medium | -- |
| **LiteLLM** | 4000 | `GET /health`, `GET /v1/models` | Medium | -- |
| **LM Studio** | 1234 | `GET /v1/models` | Medium | -- |
| **LocalAI** | 8080 | `GET /v1/models`, `GET /readyz` | Medium | -- |
| **Weaviate** | 8080 | `GET /v1/meta`, `GET /v1/schema` | High | Extracted via regex |
| **Qdrant** | 6333 | `GET /collections`, `GET /` | High | -- |
| **Jupyter** | 8888 | `GET /api`, `GET /` | Medium-High | -- |
| **MLflow** | 5000 | `GET /api/2.0/mlflow/experiments/search`, `GET /api/2.0/mlflow/registered-models/search`, `GET /` (body: "OK") | High | -- |
| **Gradio** | 7860 | `GET /info`, `GET /` | Medium-High | Extracted via regex |
| **Streamlit** | 8501 | `GET /_stcore/health` | High | -- |
| **Ray** | 8265 | `GET /api/version` | High | Extracted via regex |
| **Open WebUI** | 3000 | `GET /` | Low | -- |
| **MCP SSE** | 3000 | `POST /message` (JSON-RPC initialize) | High | -- |
| **MCP Inspector** | 6274 | `GET /`, `GET /api/servers`, `GET /api/tools` | High | -- |
| **MCPJam Inspector** | 6274 | `GET /`, `GET /api/servers` | High | -- |
| **OpenAI-Compatible** | 8000 | `GET /v1/models` | Low (generic) | -- |

!!! note
    When multiple services share ports (e.g., vLLM and ChromaDB on 8000, or LocalAI and Weaviate on 8080), the service-specific probes with higher specificity disambiguate.

## Default Port List

When `--ports` is not specified, these ports are probed:

```
   80   443  8443  11434  8000  4000  8080  1234  6333
 8888  7860  8501   5000  8265  3000  6274
```

Ports 80, 443, and 8443 are included to detect AI services behind reverse proxies. When 3+ distinct services match on a single port, results are flagged `proxy_likely` and an explicit warning is emitted during the scan to alert the operator.

## CIDR Expansion

The `--target` flag accepts CIDR notation:

```bash
./aipostex discover network --target 10.0.0.0/24     # 254 hosts
./aipostex discover network --target 10.0.0.0/16     # 65534 hosts
./aipostex discover network --target 10.0.0.0/8      # too many without --max-hosts 0
```

The `--max-hosts` guardrail (default 65536) prevents accidentally scanning huge ranges. Set to `0` to disable. Large IPv6 CIDRs (63+ host bits) are rejected before expansion to prevent integer overflow. Overlapping CIDRs are deduplicated before the host count is validated.

URL-format targets (e.g., `http://10.0.0.1:8000`) are normalized before CIDR expansion -- the scheme is stripped, the host is used for host processing, and any port in the URL is merged into the port scan list.

Individual hosts and multiple targets are also supported:

```bash
./aipostex discover network --target 10.0.0.5
./aipostex discover network --target 10.0.0.0/24 --target 192.168.1.0/24
```

## Auto-Scan

By default, `discover network` runs vulnerability templates against discovered services (`--auto-scan=true`). This:

1. Maps discovered services to relevant template tags (see table below)
2. Loads and filters templates
3. Executes matching templates against each discovered service URL
4. Deduplicates results

When `--tags` is provided, user-specified tags replace the auto-detected service tags entirely. Only templates matching the user-provided tags will run, regardless of which services were discovered.

To fingerprint only (no template scanning):

```bash
./aipostex discover network --target 10.0.0.0/24 --auto-scan=false
```

## Service-to-Tag Mapping

Discovered services are mapped to template tags for auto-scan filtering:

| Detected Service | Template Tags |
|---|---|
| ollama | `ollama` |
| chromadb | `chromadb`, `vectordb` |
| weaviate | `weaviate`, `vectordb` |
| qdrant | `qdrant`, `vectordb` |
| jupyter | `jupyter` |
| mcp-sse | `mcp` |
| mcp-inspector | `mcp` |
| vllm | `vllm`, `openai` |
| litellm | `openai` |
| localai | `openai` |
| lmstudio | `openai` |
| openai-compatible | `openai` |
| ray | `ray` |
| mlflow | `mlflow` |
| gradio | `gradio` |

## Deduplication

Fingerprint results are deduplicated per URL+service, with all services per port preserved. Multi-result scanning means each host:port can return multiple detected services.

Vulnerability findings from auto-scan are further deduplicated using the standard finding deduplication (by source, template ID, target, title, severity).

## Workflow Output

For each discovered service, `discover network` generates workflow recommendations grouped by host:port. Read-only commands appear first, followed by gated commands:

```
── Next Actions ────────────────────────────────────────────

  10.0.0.5:11434
    aipostex ollama --target http://10.0.0.5:11434 enum
    aipostex ollama --target http://10.0.0.5:11434 prompts
    aipostex ollama --target http://10.0.0.5:11434 show --model <model>

  10.0.0.6:8000
    aipostex vectordb --target http://10.0.0.6:8000 --type chromadb enum
    aipostex vectordb --target http://10.0.0.6:8000 --type chromadb search-sensitive

  Gated (require --force-exploit):
    aipostex ollama --target http://10.0.0.5:11434 poison ...
```

In console mode, findings are also grouped by host with detected service names in each host header, sorted by severity (critical first). Fingerprint `INFO` findings are folded into the host header rather than displayed individually.

These recommendations are also preserved in `metadata.workflow` on the corresponding findings in JSON/JSONL output.
