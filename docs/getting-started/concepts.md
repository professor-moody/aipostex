# Core Concepts

## Findings

A **Finding** is the atomic unit of output. Every scan result, discovery match, fingerprint detection, and exploit result produces one or more findings. Findings share a common schema across all modules:

```json
{
  "id": "f-a1b2c3d4e5f6",
  "timestamp": "2025-01-15T10:30:00Z",
  "source": "ollama",
  "target": "http://10.0.0.5:11434",
  "title": "Ollama Unauthenticated - 3 Models Exposed",
  "severity": "high",
  "description": "...",
  "remediation": "...",
  "evidence": "...",
  "tags": ["ollama", "auth"],
  "metadata": { ... }
}
```

Severity levels: `critical`, `high`, `medium`, `low`, `info`.

Source values identify which module generated the finding: `vulncheck`, `file-discovery`, `fingerprint`, `ollama`, `vectordb`, `jupyter`, `mcp`, `openai-compat`, `ray`, `mlflow`, `gradio`, `bentoml`, `triton`, `torchserve`, `credential`.

See [Finding Schema](../output/finding-schema.md) for the complete field reference.

## Templates

**Templates** are YAML files that define HTTP-based vulnerability checks. They follow a detect-then-check pattern:

1. **Detect** -- optional HTTP probe to confirm the target is the expected service
2. **Checks** -- one or more HTTP requests with matchers and extractors
3. **Finding** -- the output finding when matchers succeed, with variable interpolation from extractors

Templates are embedded in the binary. Operators can layer additional templates via `--templates-dir`.

See [Template Format](../vuln-templates/format.md) for the schema reference.

## Discovery Rules

**Discovery rules** are YAML files that define filesystem scanning patterns for AI artifacts. Each rule specifies file patterns, path patterns, and content patterns (regex) to match:

- API keys (OpenAI, Anthropic, Hugging Face, AWS, etc.)
- MCP configurations (Claude Desktop, VS Code, Cursor)
- Local LLM artifacts (GGUF models, Ollama configs, Docker AI)
- Vector database data (ChromaDB, FAISS, Weaviate, Qdrant)
- Fine-tuning datasets and RAG configurations

Rules are embedded in the binary. Operators can add custom rules via `--rules-dir`.

See [Rule Format](../rules/format.md) for the schema reference.

## Workflow Plans

**Workflow plans** are structured follow-on guidance attached to findings. When a discovery or enumeration command finds something actionable, the finding includes concrete next-step commands.

Workflow plans use the **same kill-chain stages as finding metadata** (`recon → access → impact → own`) — each plan/recommendation is tagged with the phase it advances toward:

| Stage | Purpose |
|---|---|
| **recon** | Identify reachable AI surfaces; enumerate |
| **access** | Correlate assets to exploit paths; sweep/pivot credentials |
| **impact** | Validate access / prove exploitation |
| **own** | Demonstrate takeover with state-changing operations |

Each recommendation in a workflow plan includes:

- **command** -- the exact aipostex command to run next
- **rationale** -- why this step matters
- **gated** -- whether the command requires `--force-exploit`
- **priority** -- ordering hint (lower = run first)

Read-only recommendations always appear before gated ones.

## Stage and What Landed

Every finding carries two axes describing what an operator actually got. Neither is a
subjective "grade" — both are set from observed behavior, and the tool never claims more
than it saw. *It answered ≠ you own it.*

**`stage`** — the kill-chain position the finding reached:

| Stage | Meaning |
|---|---|
| `recon` | A surface was found or fingerprinted (services, endpoints, versions) |
| `access` | The target accepted or processed our input (submitted, correlated) |
| `impact` | Exploitation was proven against the target |
| `own` | The target is takeover-capable — full control demonstrated |

**`landed`** — what actually landed on the target (found → read → ran → owned):

| Landed | Meaning |
|---|---|
| `reachable` | Service responds to probes; presence confirmed |
| `influenced` | Input was accepted / behavior observably changed, but no readback yet |
| `read-confirmed` | Data was successfully read from the target (config, models, files) |
| `execution-confirmed` | Code or commands executed on the target |
| `takeover-capable` | Full control of the service is demonstrably possible |

!!! note "One vocabulary, two uses"
    The finding `stage` above (`recon → access → impact → own`) is the kill-chain
    position a *result* reached. [Workflow Plans](#workflow-plans) use the **same**
    stages to mark the phase a *next command* advances toward — same words, so the two
    never read as different taxonomies.

## Scan Modes

The `--mode` flag controls which vulnerability templates execute during scanning:

| Mode | Default | Detection Templates | Exploit Templates |
|---|---|---|---|
| `detect` | Yes | Runs (85 templates) | Skipped |
| `full` | No | Runs (85 templates) | Runs (46 templates) |

**Detection templates** perform passive checks: authentication probes, version disclosure, config enumeration, tool listing. They never send exploitation payloads.

**Exploit templates** actively validate vulnerabilities: command injection via MCP tools, SSRF to internal services, path traversal file reads, unauthenticated inference, terminal creation, job submission, artifact exfiltration, and data extraction. They only run when explicitly opted in via `--mode full`.

This separation ensures operators can safely assess AI infrastructure without modifying target state, then escalate to active exploitation when authorized.

## JSON and JSONL Inputs

Most post-processing commands accept either a full engagement JSON document or newline-delimited JSONL findings:

- `engagement merge`
- `report summary`
- `report render`
- `report graph`
- `engagement bundle`

This lets operators stream long-running scans to JSONL, then feed the results directly into reporting and analysis commands without an extra conversion step.

## Credential Chain-Loading

When `discover network` or `assess network` produces findings that contain credentials (Jupyter tokens, OpenAI API keys, HF tokens, Anthropic keys, bearer tokens), those credentials are automatically extracted and injected into workflow recommendations. This closes the gap between discovery and exploitation: instead of manually copying tokens into follow-on commands, the workflow suggestions include the discovered credential values.

Supported credential types:

- Jupyter tokens (from URL query params or evidence text)
- OpenAI API keys (`sk-...` pattern)
- Hugging Face tokens (`hf_...` pattern)
- Anthropic API keys (`sk-ant-...` pattern)
- Bearer tokens
- Generic API keys

## Force-Exploit Gating

aipostex separates read-only operations from state-changing or high-noise operations using the `--force-exploit` flag:

- **Ungated** (no flag needed): enumeration, listing, reading, extraction, fingerprinting
- **Gated** (requires `--force-exploit`): model creation/deletion/poisoning, code execution, file uploads, throughput testing, proxy validation

This ensures operators never accidentally modify target state during passive reconnaissance.

## Operator Console

The **operator console** is the tool's manual-interaction primitive: at any reachable stage the operator can drive a service **by hand**, authenticated or unauthenticated, instead of relying on the dedicated module verbs. Two commands:

- [`request`](../cli/request.md) — one arbitrary HTTP operation issued through the tool (top-level `aipostex request METHOD PATH-OR-URL`, or a per-module `request` verb). The response is captured as a finding and mined for loot. A bare request is honest and modest: Info severity, `landed` `read-confirmed` on a 2xx / `reachable` otherwise, `stage` `access`/`recon` — it never claims `impact` or `own`.
- [`shell`](../cli/shell.md) — an interactive REPL: LLM chat, a Jupyter kernel Python REPL, an MCP tool-caller, or an A2A task console. On exit the session's responses are mined for credentials.

The console is **manual**: the operator drives every request and every turn. There is no automated chaining between stages. The execution shells (`jupyter`/`mcp`/`a2a`) are gated behind `--force-exploit`; the LLM chat shell and read `request`s are ungated. Kubernetes has no in-tool shell — its interactive channel is `kubectl`, handed off as a kubeconfig in the dossier's `manual/` folder. Secrets are never redacted.

## Output Contract

- **stdout** -- findings output (console, JSON, or JSONL)
- **stderr** -- progress, warnings, blocked-exploit messages, summaries, and Next Actions guidance
- **Ctrl+C** -- cleanly cancels in-flight work and preserves findings already written
