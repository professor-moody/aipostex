# Safety Model

aipostex enforces a clear boundary between read-only operations and state-changing actions through the `--force-exploit` gating mechanism.

## Principle

- **Read-only** commands run without restriction: enumeration, listing, reading, extraction, fingerprinting, passive analysis
- **State-changing** commands require explicit `--force-exploit`: model creation/deletion/poisoning, code execution, file uploads, throughput testing, proxy validation, queue probing

The operator never accidentally modifies target state during passive reconnaissance.

## Gated Actions by Module

### Ollama

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only enumeration |
| `prompts` | No | Read-only prompt extraction |
| `generate` | No | Read-only inference |
| `show` | No | Read-only metadata |
| `running` | No | Read-only status |
| `exfiltrate` | No | Read-only model weight download probing |
| `poison-verify` | No | Read-only behavioral confirmation that a poisoned model's injected prompt took effect |
| `copy` | **Yes** | Duplicates a model on the target |
| `create` | **Yes** | Creates a new model on the target |
| `delete` | **Yes** | Removes a model from the target |
| `poison` | **Yes** | Creates a modified model with injected system prompt |

### Vector Databases

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only collection listing |
| `extract` | No | Read-only document extraction |
| `search-sensitive` | No | Read-only pattern search |
| `inject` | **Yes** | Injects a document into a vector collection |
| `metadata-inject` | **Yes** | Injects and verifies metadata on a collection |

### Jupyter

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only server metadata |
| `kernels` | No | Read-only kernel listing |
| `notebooks` | No | Read-only notebook listing |
| `read-notebook` | No | Read-only notebook content |
| `exec` | **Yes** | Executes arbitrary code in a kernel |
| `start-kernel` | **Yes** | Creates a new kernel on the server |
| `reverse-shell-proof` | **Yes** | Outbound socket proof via kernel |
| `pip-proof` | **Yes** | Pip install proof via kernel |

### MCP

| Command | Gated | Impact |
|---|---|---|
| `analyze` | No | Local config file analysis |
| `enum` | No | Remote tool enumeration |
| `env-extract` | No | Read-only environment variable extraction |
| `config-hijack` | **Yes** | Writes a hijacked MCP client config (persistence), confirmed by re-read |
| `poison` (generic) | **Yes** | Sends manipulative payloads |
| `poison` (ssrf-cloud) | **Yes** | SSRF to cloud metadata endpoints |
| `poison` (cmd-inject) | **Yes** | Command injection payloads |
| `poison` (path-traversal) | **Yes** | Path traversal payloads |
| `poison` (type-field) | **Yes** | Full-schema type field poisoning |
| `poison` (default-value) | **Yes** | Full-schema default value injection |
| `poison` (example-inject) | **Yes** | Full-schema example injection |
| `poison` (error-message) | **Yes** | Full-schema error message injection |
| `poison` (enum-poison) | **Yes** | Full-schema enum poisoning |
| `chain` | **Yes** | Automated credential exfiltration kill chain |

### OpenAI-Compatible

| Command | Gated | Impact |
|---|---|---|
| `auth-sweep` | No | Passive auth pattern testing |
| `enum` | No | Read-only model listing |
| `validate-inference` | No | Single inference request |
| `prompt-extract` | No | Single inference request |
| `tool-enum` | No | Read-only tool and injection capability probe |
| `prompt-test` | No | Read-only prompt injection and jailbreak probe |
| `throughput` | **Yes** | Multiple concurrent inference requests |
| `proxy-test` | **Yes** | Validates proxied inference |

### Ray

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only dashboard metadata |
| `jobs` | No | Read-only job listing |
| `job-logs` | No | Read-only log reading |
| `job-artifacts` | No | Read-only artifact listing |
| `submit` | **Yes** | Submits a job for execution |
| `runtime-env` | **Yes** | Validates runtime environment submission |
| `pip-inject` | **Yes** | Runtime env pip injection |
| `beacon` | **Yes** | Submits a persistence beacon job; `own` only on an observed callback |
| `cluster-info` | No | Read-only cluster resource information |

### Kubernetes

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only resource enumeration |
| `rbac-probe` | No | Read-only anonymous/auth reachability probe |
| `access-review` | No | Read-only `SelfSubjectRulesReview` of the current identity |
| `secret-read` | **Yes** | Reads Secret material (credentials) |
| `artifact-read` | **Yes** | Reads model/pipeline artifact material |
| `pod-exec` | **Yes** | Executes a command in a pod |
| `sa-loot` | **Yes** | Exec-steals a service-account token and measures the write delta |
| `persist` | **Yes** | Deploys a bounded persistence workload |

### MLflow

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only server metadata |
| `experiments` | No | Read-only experiment listing |
| `runs` | No | Read-only run listing |
| `artifacts` | No | Read-only artifact listing |
| `registry` | No | Read-only model registry |
| `model-versions` | No | Read-only model versions |
| `model-artifacts` | No | Read-only model-version artifact listing/read |
| `download-artifact` | No | Read-only artifact download |
| `bulk-download` | **Yes** | Recursive capped artifact download (model-material read) |
| `upload-artifact` | **Yes** | Bounded write to the proxied-artifact store, confirmed by read-back |
| `tamper-proof` | **Yes** | Creates experiment/run as write-access proof |
| `swap-model` | **Yes** | Registers a new model version pointing at an operator source |
| `hook` | **Yes** | Writes a model-version hook URL tag; confirms downstream callback |

### BentoML

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only service enumeration |
| `routes` | No | Read-only route listing |
| `metrics` | No | Read-only metrics |
| `predict` | **Yes** | Sends inference request to model |

### Triton

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only model enumeration |
| `model-detail` | No | Read-only model metadata |
| `model-config` | No | Read-only model configuration |
| `repo-index` | No | Read-only repository index |
| `shm-probe` | No | Read-only shared memory probe |
| `infer` | **Yes** | Sends inference request to model |
| `load-model` | **Yes** | Loads a model into the server |
| `unload-model` | **Yes** | Unloads a model from the server |

### TorchServe

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only model enumeration |
| `model-detail` | No | Read-only model metadata |
| `metrics` | No | Read-only metrics |
| `predict` | **Yes** | Sends inference request to model |
| `register` | **Yes** | Registers a new model |
| `scale` | **Yes** | Scales model workers |
| `unregister` | **Yes** | Removes a model |

### Gradio

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only config discovery |
| `predict` | No | Single prediction call |
| `download-file` | No | Read-only file download |
| `file-chain` | No | Read-only path correlation |
| `queue-probe` | **Yes** | Queue-backed execution probe |
| `upload-file` | **Yes** | Uploads a file to the server |
| `serve-probe` | **Yes** | Validates file serve paths |

### LiteLLM

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only proxy/model discovery |
| `config-extract` | No | Read-only backend config read |
| `budget-probe` | No | Read-only budget/key metadata |
| `proxy-chain` | No | Relay reachability + inference-reality probe (read) |
| `key-gen` | **Yes** | Mints an admin API key (a write; influenced) |

### HuggingFace (TGI/TEI)

| Command | Gated | Impact |
|---|---|---|
| `enum` | No | Read-only fingerprint/discovery |
| `models` | No | Read-only model listing |
| `metrics` | No | Read-only metrics scrape |
| `model-download` | **Yes** | Bounded model-material download (READ) |
| `generate` | **Yes** | Prompted inference (probe-gated) |
| `embed` | **Yes** | Embedding inference |

### TF Serving

| Command | Gated | Impact |
|---|---|---|
| `enum`, `models`, `metadata`, `metrics` | No | Read-only status/metadata |
| `predict` | **Yes** | Inference (probe-gated) |

### Kubeflow

| Command | Gated | Impact |
|---|---|---|
| `enum`, `pipelines`, `runs`, `experiments`, `notebooks` | No | Read-only pipeline/run/notebook enumeration |
| `run-pipeline` | **Yes** | Submits a pipeline run (a write) |

### A2A

| Command | Gated | Impact |
|---|---|---|
| `enum`, `skills`, `auth-probe`, `task-status` | No | Read-only agent-card / skill / task discovery |
| `card-spoof`, `sender-spoof`, `msg-integrity`, `delegate-probe`, `push-hijack`, `tool-inject`, `replay`, `task-send`, `task-cancel`, `scrape-loop`, `stream-probe`, `mcp-pivot` | **Yes** | Submit/spoof/replay against the agent |

### W&B

| Command | Gated | Impact |
|---|---|---|
| `enum`, `projects`, `runs`, `artifacts`, `secrets` | No | Read-only GraphQL enumeration (all reads) |

## Operator Console

The [operator console](../cli/request.md) (`request` and `shell`) follows the same gating boundary as the module verbs:

| Console action | Gated | Rationale |
|---|---|---|
| `request` — safe method (GET/HEAD/OPTIONS) | No | A read: graded read-confirmed on 2xx, Info severity, never claims impact. |
| `request` — unsafe method (POST/PUT/PATCH/DELETE) | **Yes** | A state-changing call is a mutation: gated behind `--force-exploit`, `mutating:true`, graded impact/influenced (the tool cannot verify the downstream effect). |
| `shell` — LLM chat (`ollama`, `openai-compat`, `litellm`, `huggingface`) | No | Inference is not a mutation. |
| `shell` — Jupyter kernel | **Yes** | Executes arbitrary Python in a kernel. |
| `shell` — MCP tool-caller | **Yes** | Invokes MCP tools (may mutate or execute). |
| `shell` — A2A task console | **Yes** | Submits tasks to the agent. |

The **execution** shells (`jupyter`, `mcp`, `a2a`) require `--force-exploit`, consistent with every other mutating action. The LLM chat shell and read `request`s are ungated. See [`shell`](../cli/shell.md#safety-gating) for details.

## Scan Modes (Template Safety)

aipostex uses two independent safety axes. The `--mode` flag controls which vulnerability **templates** run; `--force-exploit` controls which CLI **commands** run.

| Axis | Controls | Default | Override |
|---|---|---|---|
| `--mode` | YAML template engine | `detect` (detection templates only) | `--mode full` adds exploit templates |
| `--force-exploit` | CLI exploit subcommands | Off (gated commands blocked) | `--force-exploit` unlocks state-changing commands |

### Detection mode (default)

```bash
./aipostex discover network --target 10.0.0.0/24
```

Only **detection** templates execute: auth probes, version disclosure, config exposure, tool enumeration. No exploitation payloads are sent. The console shows:

```
[*] Mode: Detection Only (no exploitation templates)
[*] Loaded built-in templates (detection + exploit split shown at runtime)
```

### Full mode

```bash
./aipostex discover network --target 10.0.0.0/24 --mode full
```

All templates execute, including **exploit** templates: command injection, SSRF, path traversal, file reads, unauthenticated inference, terminal creation, job submission, artifact exfiltration, and data extraction. The console shows:

```
[*] Mode: Full Assessment (detection + exploitation)
```

### Key distinction

`--mode full` and `--force-exploit` are independent. An operator can run `--mode full` to execute exploit templates (confirming SSRF, RCE) without passing `--force-exploit` (which would unlock commands like `ollama poison` or `jupyter exec`). Conversely, `--force-exploit` does not affect which templates run.

## Default Scan Behavior

The `scan targets` and `discover network` commands stay low-noise by default:

- Only passive HTTP probes are used for fingerprinting
- Vulnerability templates in `detect` mode use read-only checks (GET requests, status checks)
- Exploit templates (SSRF, command injection, path traversal, inference abuse) are skipped unless `--mode full` is specified
- No state-changing exploit commands run unless `--force-exploit` is passed

## Runtime Guardrails

| Guardrail | Default | Flag |
|---|---|---|
| Max hosts for CIDR expansion | 65536 | `--max-hosts` (0 = no limit) |
| Stealth concurrency cap | Off | `--stealth` (caps to 1 worker) |
| File scanner concurrency | Off | `--stealth` (caps to 1 worker) |

## Enforcement

Gating is enforced at the CLI layer by `requireForceExploit()` in `cmd/aipostex/exploit_common.go`. When a gated command is called without `--force-exploit`, the operator sees:

```
[x] --force-exploit is required for this action.
    This operation may modify target state or generate significant traffic.
    Re-run with --force-exploit to confirm.
```
