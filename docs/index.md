# aipostex

**AI Infrastructure Offensive Security Framework**

aipostex is a single-binary Go tool for discovering, assessing, and exploiting AI infrastructure. Built for penetration testers, red teams, and adversary emulation operators, it combines YAML-based vulnerability scanning, file scanning, and deep post-exploitation capabilities across the AI service landscape.

---

## What It Does

<div class="grid cards" markdown>

-   **Vulnerability Scanning**

    131 YAML vulnerability templates (85 detection, 46 exploit) targeting AI-specific misconfigurations and advisories across Ollama, MCP, A2A, Kubernetes, Jupyter, Ray, MLflow, Gradio, BentoML, Triton, TorchServe, vLLM, LangChain, and more.

-   **File Discovery**

    File scanning for AI artifacts such as API keys, MCP configs, model files, vector database data, and fine-tuning datasets.

-   **Network Fingerprinting**

    30 HTTP-based service probes detecting AI services on a network with automatic template matching and CIDR range scanning.

-   **Post-Exploitation**

    20 dedicated exploit modules covering Ollama, vector databases (ChromaDB, Weaviate, Qdrant, Milvus, pgvector), Jupyter, MCP, OpenAI-compatible APIs, LiteLLM, Ray, MLflow, Gradio, BentoML, Triton, TorchServe, HuggingFace TGI/TEI, TensorFlow Serving, Kubeflow, W&B, A2A agents, Kubernetes API servers, and the model/agent layer — bespoke `/chat` agents, black-box RAG apps, and behavioral model fingerprinting.

</div>

## Quick Start

```bash
# Build
make build

# Discover AI services on a network
./aipostex discover network --target 10.0.0.0/24

# Scan a target for vulnerabilities
./aipostex scan targets --target http://127.0.0.1:11434

# Scan files for AI credentials and artifacts
./aipostex discover files --path /tmp/loot

# Enumerate an Ollama instance
./aipostex ollama --target http://127.0.0.1:11434 enum
```

See the [Quickstart guide](getting-started/quickstart.md) for a full walkthrough.

## Key Design Principles

**Operator progression** -- Discovery commands hand off into concrete follow-on commands. `discover network` finds services, attaches module-specific next steps, and the operator walks a discovery-to-proof chain.

**Safe by default** -- Scans run in `detect` mode, executing only passive detection templates. Active exploitation templates (SSRF, command injection, inference) require explicit `--mode full`. State-changing exploit module actions require `--force-exploit`. The operator is always in control.

**Single binary** -- Templates and discovery rules are embedded. No external files required. Custom templates and rules layer on top via `--templates-dir` and `--rules-dir`.

**OPSEC-aware** -- Built-in stealth mode with request jitter, User-Agent rotation, concurrency caps, and full proxy support (HTTP/HTTPS/SOCKS5).

## Current Status

aipostex includes scanning, file discovery, reporting, and 20 exploit modules with staged workflow guidance. Advisory coverage includes 24 CVE-specific templates, 2 GHSA templates, and 1 TRA template across MCP, Ollama, MLflow, Gradio, Ray, vLLM, LangChain, and related AI infrastructure. See the [Coverage Matrix](development/coverage.md) for the full breakdown.

| Category | Commands |
|---|---|
| Workflow CLI | `discover network`, `discover files`, `scan targets`, `assess network`, `report render`, `report summary`, `report graph`, `engagement merge`, `engagement bundle`, `serve` (run aipostex as an MCP server) |
| Templates | `templates list`, `templates info` |
| Ollama | `enum`, `prompts`, `generate`, `show`, `running`, `copy`, `create`, `delete`, `poison`, `poison-verify`, `exfiltrate` |
| Vector DBs | `enum`, `extract`, `search-sensitive`, `inject`, `metadata-inject`, `rag-verify` |
| Jupyter | `enum`, `kernels`, `notebooks`, `read-notebook`, `exec`, `start-kernel`, `reverse-shell-proof`, `pip-proof`, `persist`, `revshell` |
| MCP | `analyze`, `config-hijack`, `enum`, `poison`, `env-extract`, `chain` |
| OpenAI-Compatible | `auth-sweep`, `enum`, `validate-inference`, `prompt-extract`, `tool-enum`, `prompt-test`, `throughput`, `proxy-test`, `generate`, `litellm-probe` |
| LiteLLM | `enum`, `config-extract`, `budget-probe`, `proxy-chain`, `key-gen` |
| Ray | `enum`, `jobs`, `job-logs`, `job-artifacts`, `submit`, `runtime-env`, `pip-inject`, `cluster-info`, `beacon` |
| MLflow | `enum`, `experiments`, `runs`, `artifacts`, `registry`, `model-versions`, `model-artifacts`, `download-artifact`, `bulk-download`, `upload-artifact`, `tamper-proof`, `swap-model`, `hook` |
| Gradio | `enum`, `predict`, `queue-probe`, `upload-file`, `download-file`, `file-chain`, `serve-probe` |
| BentoML | `enum`, `routes`, `predict`, `metrics` |
| Triton | `enum`, `models`, `model-config`, `infer`, `model-load`, `model-unload`, `shm-probe` |
| TorchServe | `enum`, `models`, `predict`, `register`, `scale`, `unregister`, `metrics` |
| HuggingFace TGI/TEI | `enum`, `models`, `metrics`, `model-download`, `generate`, `embed` |
| TF Serving | `enum`, `models`, `metadata`, `predict`, `metrics` |
| Kubeflow | `enum`, `pipelines`, `runs`, `experiments`, `notebooks`, `run-pipeline` |
| W&B | `enum`, `projects`, `runs`, `artifacts`, `secrets` |
| A2A | `enum`, `skills`, `auth-probe`, `msg-integrity`, `sender-spoof`, `delegate-probe`, `card-spoof`, `task-send`, `task-status`, `task-cancel`, `stream-probe`, `push-hijack`, `mcp-pivot`, `scrape-loop`, `tool-inject`, `replay`, `register` |
| Kubernetes | `rbac-probe`, `access-review`, `enum`, `secret-read`, `artifact-read`, `pod-exec`, `sa-loot`, `persist` |
| Agent (bespoke `/chat`) | `probe`, `enum`, `extract`, `fingerprint`, `inject`, `guardrail` |
| RAG (black-box) | `query`, `map`, `poison` |

### Deferred

- `validate` (finding validation)
- SQLite output format

<div class="apx-dc" markdown="0">
  <span class="apx-dc-txt">✦ As seen at DEF&nbsp;CON&nbsp;34 · Red&nbsp;Team&nbsp;Village ✦</span>
</div>
<style>
.apx-dc { text-align: center; margin: 2.4rem 0 .4rem; }
.apx-dc-txt {
  display: inline-block;
  font-weight: 700;
  font-size: clamp(.72rem, 1.7vw, .95rem);
  letter-spacing: .09em;
  text-transform: uppercase;
  background: linear-gradient(90deg,#a855f7,#8b5cf6,#6366f1,#3b82f6,#06b6d4,#3b82f6,#6366f1,#8b5cf6,#a855f7);
  background-size: 300% auto;
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  -webkit-text-fill-color: transparent;
  animation: apx-dc-shim 7s linear infinite;
  opacity: .9;
}
@keyframes apx-dc-shim { to { background-position: 300% center; } }
@media (prefers-reduced-motion: reduce) { .apx-dc-txt { animation: none; background-position: 50% center; } }
</style>
