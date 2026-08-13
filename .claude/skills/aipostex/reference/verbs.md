# aipostex verb reference

The complete command inventory, generated from the command tree and held in step
with it by a test. **Gated** verbs mutate a target or drive execution and refuse to
run without `--force-exploit`; everything else is read-only.

Regenerate with `AIPOSTEX_UPDATE_SKILL=1 go test ./cmd/aipostex/ -run TestSkillReference`.

**28 command groups · 201 verbs · 83 gated**

## `a2a`

Enumerate and exploit Agent-to-Agent (A2A) protocol endpoints

| Verb | Gated | What it does |
|---|---|---|
| `auth-probe` | no | Check whether advertised authentication is actually enforced |
| `card-spoof` | **yes** | Test whether the agent fetches/trusts a caller-supplied agent card (requires --force-exploit) |
| `delegate-probe` | **yes** | Test whether the agent delegates to a caller-supplied peer (requires --force-exploit) |
| `enum` | no | Fetch and parse the public A2A agent card |
| `mcp-pivot` | **yes** | Cross-protocol probe: drive A2A task into MCP-backed tool (requires --force-exploit) |
| `msg-integrity` | **yes** | Test whether the agent verifies message integrity (requires --force-exploit) |
| `push-hijack` | **yes** | Register a canary A2A task webhook (requires --force-exploit) |
| `register` | **yes** | Register a rogue agent with an orchestrator's registry (requires --force-exploit) |
| `replay` | **yes** | Replay a message to test deterministic or stateless behavior (requires --force-exploit) |
| `scrape-loop` | **yes** | Continuous task submission loop for data exfiltration (requires --force-exploit) |
| `sender-spoof` | **yes** | Forge a self-asserted sender identity and detect if behavior depends on it (requires --force-exploit) |
| `shell` | **yes** | Interactive A2A task console (operator console) |
| `skills` | no | Enumerate advertised agent skills with I/O modes |
| `stream-probe` | **yes** | Subscribe to an A2A streaming message/task (requires --force-exploit) |
| `task-cancel` | **yes** | Cancel an A2A task (requires --force-exploit) |
| `task-send` | **yes** | Submit an unauthenticated A2A message/task (requires --force-exploit) |
| `task-status` | no | Poll A2A task state |
| `tool-inject` | **yes** | Inject a tool call via task message to test blind forwarding (requires --force-exploit) |

## `agent`

Attack bespoke LLM agent apps (custom /chat endpoints): fingerprint, enumerate, extract, inject, guardrail

| Verb | Gated | What it does |
|---|---|---|
| `crescendo` | no | Multi-turn (crescendo) prompt injection: escalate across turns to beat a per-message guardrail |
| `enum` | no | Ask the agent to describe its tools and capabilities |
| `extract` | no | Extract the system prompt/config, running an output-filter-bypass matrix |
| `fingerprint` | no | Behaviorally fingerprint the model family behind the agent |
| `fragment` | no | Cross-turn fragmentation: split the injected token across turns to evade a content filter |
| `guardrail` | no | Profile the agent's defensive posture (secret-disclosure / override / jailbreak / over-refusal) |
| `inject` | no | Test direct prompt-injection resistance with an input-filter-bypass matrix |
| `probe` | no | Send a benign message to confirm the agent is reachable and capture its reply |
| `session-probe` | no | Sample the agent's session identifiers and check whether they are predictable (guessable) |

## `assess`

Run full assessment workflows

| Verb | Gated | What it does |
|---|---|---|
| `network` | no | Full assessment: discover, scan, and enumerate AI services |

## `bentoml`

Enumerate and exploit BentoML services

| Verb | Gated | What it does |
|---|---|---|
| `enum` | no | Enumerate BentoML service metadata |
| `metrics` | no | Extract Prometheus metrics from BentoML |
| `predict` | **yes** | Send a prediction request to a BentoML endpoint |
| `routes` | no | List prediction endpoints from OpenAPI spec |

## `discover`

Discover AI services and artifacts

| Verb | Gated | What it does |
|---|---|---|
| `files` | no | Scan file system for AI artifacts and credentials |
| `network` | no | Scan network for AI services and auto-run vulnerability templates |

## `engagement`

Combine and package engagement artifacts

| Verb | Gated | What it does |
|---|---|---|
| `bundle` | no | Package an engagement into a self-contained zip archive |
| `merge` | no | Merge multiple engagement JSON files into a single output |

## `gradio`

Enumerate and probe Gradio apps

| Verb | Gated | What it does |
|---|---|---|
| `download-file` | no | Download a bounded file reference |
| `enum` | no | Enumerate Gradio config and endpoints |
| `file-chain` | no | Drive a discovered Gradio file handle through a bounded read chain |
| `predict` | no | Call a bounded Gradio prediction surface |
| `queue-probe` | **yes** | Run a bounded queue-backed execution probe |
| `serve-probe` | **yes** | Validate bounded re-serve or alternate file-read paths for a Gradio handle |
| `upload-file` | **yes** | Probe the global Gradio /upload surface with a tiny operator-marked file |

## `huggingface`

Enumerate and exploit HuggingFace TGI/TEI inference servers

| Verb | Gated | What it does |
|---|---|---|
| `embed` | **yes** | Send an embedding request to a TEI server (gated) |
| `enum` | no | Enumerate HuggingFace TGI/TEI service type and model info |
| `generate` | **yes** | Send a text generation request to a TGI server (gated) |
| `metrics` | no | Extract Prometheus metrics from the /metrics endpoint |
| `model-download` | **yes** | Download bounded model files from Hub-compatible storage (gated) |
| `models` | no | List models served by a TGI instance via /v1/models |
| `request` | conditional | Issue an arbitrary HTTP request to the huggingface target (operator console) |
| `shell` | **yes** | Interactive chat REPL against the huggingface model (operator console) |

## `jupyter`

Enumerate and exploit Jupyter servers

| Verb | Gated | What it does |
|---|---|---|
| `enum` | no | Enumerate Jupyter server metadata |
| `exec` | **yes** | Execute code in an existing kernel |
| `kernels` | no | List active kernels |
| `notebooks` | no | List notebook files |
| `persist` | **yes** | Install persistent access via a Jupyter startup script |
| `pip-proof` | **yes** | Prove pip install capability via kernel |
| `read-notebook` | no | Read a notebook by path |
| `reverse-shell-proof` | **yes** | Prove outbound socket capability via kernel |
| `revshell` | **yes** | Deploy a real reverse shell via kernel (requires --force-exploit) |
| `shell` | **yes** | Interactive Python REPL on a Jupyter kernel (operator console) |
| `start-kernel` | **yes** | Start a new kernel |

## `k8s`

Enumerate and exploit Kubernetes AI-workload clusters

| Verb | Gated | What it does |
|---|---|---|
| `access-review` | no | Map what the current identity is authorized to do (SelfSubjectRulesReview) |
| `artifact-read` | **yes** | Harvest model-artifact locations from cluster metadata (requires --force-exploit) |
| `enum` | no | Enumerate Kubernetes workloads and custom resources |
| `persist` | **yes** | Deploy a bounded persistence workload with the current/stolen identity (requires --force-exploit) |
| `pod-exec` | **yes** | Execute a command inside a pod (requires --force-exploit) |
| `rbac-probe` | no | Assess anonymous / unauthenticated API access |
| `sa-loot` | **yes** | Steal a pod's service-account token and escalate to its identity (requires --force-exploit) |
| `secret-read` | **yes** | Exfiltrate and decode Secrets from a namespace (requires --force-exploit) |

## `kubeflow`

Enumerate and exploit Kubeflow Pipelines API

| Verb | Gated | What it does |
|---|---|---|
| `enum` | no | Enumerate Kubeflow Pipelines API reachability and version |
| `experiments` | no | List experiments |
| `notebooks` | no | List Kubeflow Notebooks in a namespace |
| `pipelines` | no | List accessible ML pipelines |
| `run-pipeline` | **yes** | Create a new pipeline run (gated) |
| `runs` | no | List pipeline runs |

## `listen`

Start a callback listener (webhook, TCP, or DNS canary)

| Verb | Gated | What it does |
|---|---|---|
| `dns` | **yes** | Start a DNS canary listener for lookup callbacks |
| `tcp` | **yes** | Start a raw TCP listener for reverse shells |
| `webhook` | **yes** | Start an HTTP webhook listener for POST callbacks |

## `litellm`

Enumerate and exploit LiteLLM proxy servers

| Verb | Gated | What it does |
|---|---|---|
| `budget-probe` | no | Enumerate spend limits and usage information |
| `config-extract` | no | Extract configuration keys from health and model-info endpoints |
| `enum` | no | Enumerate models and backend topology |
| `key-gen` | **yes** | Generate a persistent backdoor API key via the admin API |
| `proxy-chain` | no | Trace inference through the proxy to identify backend providers |
| `request` | conditional | Issue an arbitrary HTTP request to the litellm target (operator console) |
| `shell` | **yes** | Interactive chat REPL against the litellm model (operator console) |

## `mcp`

Analyze and exploit MCP servers

| Verb | Gated | What it does |
|---|---|---|
| `analyze` | no | Analyze a local MCP config file |
| `auth` | no | Probe the MCP endpoint's authorization posture (OAuth) |
| `chain` | **yes** | Automated multi-step credential exfiltration kill chain |
| `complete` | no | Enumerate argument values through completion/complete |
| `config-hijack` | **yes** | Write a hijacked MCP server entry into a local config |
| `elicitation` | **yes** | Probe for server->client elicitation phishing (requires --force-exploit) |
| `enum` | no | Enumerate a remote MCP HTTP or SSE endpoint |
| `env-extract` | no | Extract environment variables from MCP server processes |
| `logging` | **yes** | Raise the server log level and capture leaked log output (requires --force-exploit) |
| `poison` | **yes** | Send an MCP exploit probe |
| `roots` | **yes** | Probe for server->client filesystem-roots harvesting (requires --force-exploit) |
| `sampling` | **yes** | Probe for server->client sampling abuse (requires --force-exploit) |
| `sandbox-escape` | **yes** | Probe an MCP filesystem tool for a path-based sandbox escape (requires --force-exploit) |
| `shell` | **yes** | Interactive MCP tool-caller (operator console) |
| `ssti` | **yes** | Probe an MCP rendering/formatting tool for server-side template injection (requires --force-exploit) |
| `subscribe` | **yes** | Establish a resources/subscribe push channel (requires --force-exploit) |

## `mlflow`

Enumerate and extract data from MLflow servers

| Verb | Gated | What it does |
|---|---|---|
| `artifacts` | no | List a bounded artifact tree for a run |
| `bulk-download` | **yes** | Recursively download capped artifacts from a run or model version |
| `download-artifact` | no | Download a bounded artifact path from a run |
| `enum` | no | Enumerate MLflow tracking metadata |
| `experiments` | no | List experiments and bounded run counts |
| `hook` | **yes** | Install a model-version hook URL through MLflow registry metadata |
| `model-artifacts` | no | Pivot from a model version into bounded artifact paths |
| `model-versions` | no | Enumerate MLflow model versions for a registered model |
| `registry` | no | Enumerate exposed MLflow registry models |
| `request` | conditional | Issue an arbitrary HTTP request to the mlflow target (operator console) |
| `runs` | no | List visible runs for an experiment |
| `swap-model` | **yes** | Register a new model version pointing to an attacker-controlled artifact source |
| `tamper-proof` | **yes** | Prove write access by creating an experiment, run, and parameter |
| `upload-artifact` | **yes** | Write an artifact to the MLflow proxied-artifact store (requires --force-exploit) |

## `ollama`

Enumerate and exploit Ollama instances

| Verb | Gated | What it does |
|---|---|---|
| `copy` | **yes** | Copy a model |
| `create` | **yes** | Create a model from a payload |
| `delete` | **yes** | Delete a model |
| `enum` | no | Full enumeration of the Ollama service |
| `exfiltrate` | **yes** | Download bounded model weight blob chunks |
| `generate` | no | Execute inference on a target model |
| `poison` | **yes** | Create a modified model from a base model |
| `poison-verify` | no | Confirm a poisoned model's injected system prompt changed its behavior |
| `prompts` | no | Extract system prompts from all models |
| `request` | conditional | Issue an arbitrary HTTP request to the ollama target (operator console) |
| `running` | no | List currently loaded models |
| `shell` | **yes** | Interactive chat REPL against the ollama model (operator console) |
| `show` | no | Show detailed metadata for a model |

## `openai-compat`

Enumerate and validate generic OpenAI-compatible inference endpoints

| Verb | Gated | What it does |
|---|---|---|
| `auth-sweep` | no | Classify weak-auth acceptance on the endpoint |
| `enum` | no | Enumerate exposed models and normalized model metadata |
| `fingerprint` | no | Behaviorally fingerprint the underlying model family (identity, contradiction, knowledge-cutoff) |
| `generate` | **yes** | Send an operator-supplied prompt to an OpenAI-compatible model |
| `litellm-probe` | no | Probe LiteLLM-specific health, readiness, and model-info endpoints |
| `prompt-extract` | no | Run a bounded hidden-instruction extraction attempt |
| `prompt-test` | no | Probe prompt injection and jailbreak resistance with read-only prompts |
| `proxy-test` | **yes** | Prove the endpoint can proxy inference |
| `request` | conditional | Issue an arbitrary HTTP request to the openai-compat target (operator console) |
| `shell` | **yes** | Interactive chat REPL against the openai-compat model (operator console) |
| `throughput` | **yes** | Measure bounded inference throughput |
| `tool-enum` | no | Enumerate function/tool calling capabilities and test for tool injection |
| `validate-inference` | no | Validate that the endpoint returns coherent inference output |

## `rag`

Attack black-box RAG apps through /query + /ingest (citation recon, KB mapping, ingestion poisoning)

| Verb | Gated | What it does |
|---|---|---|
| `map` | no | Map the knowledge base via a recon-query battery, flagging documents that leak secrets |
| `poison` | **yes** | Ingest a document and verify surfacing + injection compliance (ingestion / indirect prompt injection) |
| `query` | no | Send one query and surface the answer + source citations (and any leaked secrets) |

## `ray`

Enumerate and exploit Ray dashboards

| Verb | Gated | What it does |
|---|---|---|
| `beacon` | **yes** | Submit a beacon job that calls back to --callback-url on interval (requires --force-exploit) |
| `cluster-info` | **yes** | Exfiltrate cluster resource and node information |
| `enum` | no | Enumerate Ray dashboard metadata |
| `job-artifacts` | no | Extract bounded artifact or log references from a Ray job |
| `job-logs` | no | Read bounded job detail or logs for a Ray job |
| `jobs` | no | List visible Ray jobs |
| `pip-inject` | **yes** | Prove pip injection via runtime_env |
| `request` | conditional | Issue an arbitrary HTTP request to the ray target (operator console) |
| `runtime-env` | **yes** | Validate bounded runtime_env submission or injection surfaces |
| `submit` | **yes** | Submit a bounded exploit job |

## `report`

Render and analyze engagement outputs

| Verb | Gated | What it does |
|---|---|---|
| `graph` | no | Generate a finding correlation graph from engagement data |
| `render` | no | Generate an engagement report from findings |
| `summary` | no | Generate an executive summary from engagement JSON files |
| `view` | no | Inspect raw findings, evidence, credentials, and generated commands |

## `scan`

Run targeted vulnerability scanning workflows

| Verb | Gated | What it does |
|---|---|---|
| `targets` | no | Run vulnerability templates against AI/MCP targets |

## `sessions`

Manage engagement sessions

| Verb | Gated | What it does |
|---|---|---|
| `export` | no | Export findings scoped to a session |
| `list` | no | List all sessions |
| `notes` | no | Set or append notes on a session |
| `prune` | no | Delete stopped sessions that captured no findings |
| `show` | no | Show details for a session |
| `start` | no | Start a new engagement session |
| `stop` | no | Stop an active session |

## `templates`

List and inspect vulnerability templates

| Verb | Gated | What it does |
|---|---|---|
| `info` | no | Show detailed information for a vulnerability template |
| `lint` | no | Lint vulnerability templates for safety and advisory metadata |
| `list` | no | List available vulnerability templates |

## `tfserving`

Enumerate and exploit TensorFlow Serving endpoints

| Verb | Gated | What it does |
|---|---|---|
| `enum` | no | Enumerate TF Serving reachability and metrics |
| `metadata` | no | Extract model signature and tensor specs |
| `metrics` | no | Extract Prometheus metrics |
| `models` | no | Probe for served models by name |
| `predict` | **yes** | Send an inference request to a model |

## `torchserve`

Enumerate and exploit TorchServe model servers

| Verb | Gated | What it does |
|---|---|---|
| `enum` | no | Enumerate TorchServe models and health |
| `metrics` | no | Extract metrics from TorchServe metrics API |
| `models` | no | Get detailed model information |
| `predict` | **yes** | Send a prediction request via the inference API |
| `register` | **yes** | Attempt to register a model from URL (SSRF/RCE vector) |
| `scale` | **yes** | Scale model workers to prove management write access |
| `unregister` | **yes** | Unregister a model to prove destructive access |

## `triton`

Enumerate and exploit Triton Inference Server

| Verb | Gated | What it does |
|---|---|---|
| `enum` | no | Enumerate Triton server metadata |
| `infer` | **yes** | Send an inference request to a model |
| `model-config` | no | Get detailed model configuration |
| `model-load` | **yes** | Attempt to load a model from the repository |
| `model-unload` | **yes** | Attempt to unload a model |
| `models` | no | List all loaded models |
| `shm-probe` | no | Probe shared memory regions (IPC vulnerability chain) |

## `vectordb`

Enumerate and extract data from vector databases

| Verb | Gated | What it does |
|---|---|---|
| `enum` | no | Enumerate collections and object counts |
| `extract` | no | Extract records from a collection |
| `inject` | **yes** | Inject crafted documents into a vector store (RAG poisoning test) |
| `metadata-inject` | **yes** | Test metadata field injection in vector stores |
| `rag-verify` | **yes** | End-to-end RAG poisoning proof: inject into vectordb, verify via LLM |
| `request` | conditional | Issue an arbitrary HTTP request to the vectordb target (operator console) |
| `search-sensitive` | no | Search extracted records for sensitive data patterns |

## `wandb`

Enumerate and extract data from Weights & Biases servers

| Verb | Gated | What it does |
|---|---|---|
| `artifacts` | no | List artifacts for a project |
| `enum` | no | Enumerate W&B server metadata and viewer identity |
| `projects` | no | List projects for an entity |
| `runs` | no | List runs for a project |
| `secrets` | no | Scan run configs and summaries for embedded credentials |

