# Coverage & Roadmap

## Current Coverage Matrix

| Service | Implemented | Next Additions | Later-Phase |
|---|---|---|---|
| **Ollama** | Enum, prompts (System field + Modelfile parsing), generate, show, running, copy/create/delete/poison, **capped weight exfiltration** | Better value scoring, model tamper validation | Resource exhaustion |
| **OpenAI-Compatible** (vLLM, LiteLLM, LocalAI, LM Studio) | auth-sweep, enum, validate-inference, prompt-extract, tool-enum, prompt-test, throughput, proxy-test, litellm-probe; scan/template coverage; **explicit model-inventory + prompt-injection + weak-auth/tool-injection templates** | Provider-specific first-class modules, deeper LiteLLM, multimodal SSRF/media-fetch proof paths | Campaign-style reporting |
| **ChromaDB** | Enum (tenant/database-aware fallback), extract, sensitive search (27 patterns), unauth template | Better value scoring | Mutating abuse, snapshot exports |
| **Qdrant** | Enum, extract, sensitive search, unauth template | Better cluster/detail enrichment | Snapshot export, destructive workflows |
| **Weaviate** | Enum, extract, sensitive search, unauth template | Better schema/GraphQL enrichment | Backup/export abuse, cluster ops |
| **Milvus** | Enum, extract, sensitive search, inject, metadata-inject, unauth template | Deeper schema introspection | Partition/index manipulation |
| **pgvector** | Enum (table introspection), extract, sensitive search, inject, metadata-inject | Column-level sensitive scanning | SQL injection chaining |
| **BentoML** | Enum, routes (OpenAPI parsing with schema-shaped predict follow-ons), predict with input-dependent inference verification, metrics; 3 vuln templates | Runner/model versioning and pickle/custom runner evidence | Custom runner exploitation |
| **NVIDIA Triton** | Enum, models, model-config, infer, **model-load with post-load inference verification**, model-unload, shm-probe (CVE-2025-23319/23320/23334); 7 vuln templates | Broader repository manipulation | Full IPC exploitation chain |
| **TorchServe** | Enum, models, predict, register (ShellTorch SSRF + named handler execution verification), scale, unregister, metrics; 5 vuln templates | MAR metadata extraction | Full ShellTorch RCE chain |
| **TensorFlow Serving** | Enum, model probing, metadata/signature extraction, **signature-shaped prediction follow-ons**, predict with input-dependent inference verification, metrics; 3 vuln templates | Model version drift and SavedModel provenance | Deeper deployment correlation |
| **Jupyter** | Enum, kernels, notebooks (**--mine-secrets** cell mining), read-notebook, exec, **start-kernel, reverse-shell-proof, pip-proof**; auth/terminal templates; **kernelspec + contents-read templates** | Extension/config enrichment | Broader notebook environment takeover |
| **MCP** | Analyze, config-hijack (guarded local config write + parser verification), enum (tools/prompts/resources + **resource templates**, `--read` retrieves resource bodies and prompt templates), poison (9 modes: generic/ssrf-cloud/cmd-inject/path-traversal + 5 schema poison modes), **env-extract** (credential probing), **shell** (interactive tool-caller, `--force-exploit`), **sandbox-escape** (path-prefix bypass, CVE-2025-53109/-53110 class), **ssti** (unsandboxed template evaluation), **chain** (credential kill chain), **sampling / elicitation / roots** (server→client abuse: client LLM, user phishing, filesystem-roots harvesting), **complete** (completion-based value enumeration), **logging** (setLevel + pushed log capture), **subscribe** (resource push channel), **auth** (enforcement, OAuth metadata discovery, open dynamic client registration); **HTTP + stdio transport**; config variants; capability classification; remote URL correlation; 20 vuln templates covering unauth access, inspector exposure, DNS rebinding, session leakage, SSRF, RCE CVEs (Inspector, Figma, K8s, mcp-remote, Filesystem MCP), and server-specific detection (Neo4j, Vet, MS Learn) | Deeper multi-step poison automation, richer inspector-to-remote exploitation | Automated credential chaining (deferred) |
| **Ray** | Dashboard enum, jobs (array + object formats, runtime_env/env_vars extraction), job-logs, job-artifacts, submit, runtime-env, **pip-inject, cluster-info, beacon persistence**; unauth templates; **cluster-status + log-exposure templates** | Better cluster-state enrichment | Broader cluster takeover workflows |
| **MLflow** | Tracking enum (root + /health), experiments, runs, registry (GET-first), model-versions, model-artifacts, artifact-tree, artifact reads, **bulk-download** (capped recursive artifact exfil), **tamper-proof** (experiment/run/param creation), **swap-model** (registry version mutation), **hook** (model-version hook tag + controller callback confirmation); unauth templates; **registry-surface template** | Serving/load verification for registry mutations | Deeper artifact and registry exploitation |
| **Gradio** | Config enum, endpoint discovery, predict, queue/upload proofs, file reads, file-chain, serve-probe; exposed-surface templates; **file-capable surface template** | Better route-specific exploit chaining, richer handle parsing | Deeper upload/read/serve exploit coverage |
| **LiteLLM** | Enum (readiness/health/models/model-info), config-extract (per-model `litellm_params` incl. embedded credentials), budget-probe (spend/TPM/RPM), proxy-chain (upstream provider topology + `api_base`), **key-gen** (gated virtual-key minting), `request`/`shell` operator console | Richer provider-credential correlation | Cross-provider abuse chaining |
| **Kubernetes** | rbac-probe (anonymous posture classification), access-review (`SelfSubjectRulesReview`), enum (workloads + ML custom resources, `--all-namespaces`), **secret-read** (base64-decoded to plaintext), artifact-read (model locations from ConfigMaps/InferenceServices), **pod-exec** (in-pod RCE over the API server exec stream), **sa-loot** (service-account token theft + re-auth + privilege-escalation detection), **persist** (self-healing workload) | Broader CRD coverage across serving stacks | Cluster-wide takeover workflows |
| **A2A** | Agent-card enum, skills, task-send/status/cancel, auth-probe (is advertised auth enforced), **msg-integrity**, **sender-spoof**, **delegate-probe** (confused deputy), **card-spoof**, **push-hijack**, replay, register (rogue agent), stream-probe, tool-inject, scrape-loop, mcp-pivot, shell; 14 templates | Deeper multi-agent mesh mapping | Full mesh compromise chains |
| **Agent (bespoke)** | Probe, enum (conversational tool discovery), **extract** (system prompt/config/credentials with an output-filter-bypass matrix), **inject** (input-filter-bypass matrix), **crescendo** (multi-turn escalation), **fragment** (cross-turn token splitting), **session-probe** (session-id predictability), **guardrail** (secret-disclosure / override / jailbreak / over-refusal profile), **fingerprint** (behavioral model-family attribution) | Broader transport auto-detection | Automated multi-agent injection chains |
| **RAG (black-box)** | Query (answer + source citations), **map** (recon-query battery over the knowledge base, flagging documents that leak secrets), **poison** (attacker-document ingestion + surfacing/compliance verification) | Retrieval-ranking manipulation | Persistent corpus compromise |
| **HuggingFace** | Enum (TGI/TEI auto-detect, model id/version), models, metrics, generate, embed, **model-download** (capped chunked retrieval from Hub-compatible storage), `request`/`shell` | Broader serving-stack detection | Weight-level supply-chain work |
| **Kubeflow** | Enum (API reachability + version, v1beta1/v2beta1), pipelines (definitions + parameters), runs, experiments, notebooks, **run-pipeline** (gated pipeline-run injection) | Artifact-store pivoting | Pipeline supply-chain compromise |
| **Weights & Biases** | Enum (server metadata + authenticated viewer identity), projects, runs, artifacts, **secrets** (credential scan over run configs and summaries) | Artifact-lineage correlation | Cross-project data exfiltration |

Fingerprinting now distinguishes `confirmed`, `suspected`, and `ambiguous` matches. Generic probes are preserved where useful, but weak-only hits are downgraded instead of being presented as authoritative service identity. Ambiguous or proxy-like ports are no longer skipped during network assessment: aipostex expands template coverage across each plausible HTTP service identity and marks resulting findings with `fingerprint_status=ambiguous`, `coverage_expanded=true`, `candidate_services`, and `identity_confidence=ambiguous`. Clear non-HTTP identities such as PostgreSQL/pgvector are preserved for module enumeration, but HTTP templates are not sprayed at those ports; the output records an informational skip instead.

## Template Coverage

Templates are classified by `info.type` in each YAML: **detection** (default) or **exploit**. Totals below are from `pkg/vulncheck/templates/**/*.yaml` (embedded at build time). The `--mode` flag controls which run: `detect` (default, safe) runs only detection templates; `full` runs all templates including active exploitation.

| Category | Templates | Detection | Exploit | Severity Range |
|---|---|---|---|---|
| MCP | 23 | 16 | 7 | Critical, High, Medium |
| A2A | 14 | 2 | 12 | High, Medium |
| NVIDIA Triton | 8 | 6 | 2 | Critical, High, Medium |
| Vector DBs | 7 | 4 | 3 | High |
| LangChain / LangServe | 7 | 5 | 2 | Critical, High, Medium |
| Ray | 6 | 4 | 2 | Critical, High, Medium |
| Ollama | 6 | 5 | 1 | Critical, High, Medium, Info |
| Hugging Face | 6 | 4 | 2 | Critical, High, Medium |
| Jupyter | 6 | 4 | 2 | Critical, High, Medium |
| Gradio | 6 | 4 | 2 | Critical, High, Medium |
| TorchServe | 5 | 3 | 2 | Critical, High, Medium |
| OpenAI-Compatible | 5 | 1 | 4 | Critical, High |
| MLflow | 5 | 3 | 2 | Critical, High, Medium |
| BentoML | 4 | 4 | 0 | High, Medium, Info |
| vLLM | 4 | 4 | 0 | Critical, High |
| Weights & Biases | 3 | 3 | 0 | High, Medium |
| TensorFlow Serving | 3 | 2 | 1 | High, Medium |
| Kubeflow | 3 | 3 | 0 | High |
| Kubernetes | 3 | 2 | 1 | Critical, High, Medium |
| Campaign | 3 | 2 | 1 | High |
| LiteLLM | 2 | 2 | 0 | High |
| Streamlit | 2 | 2 | 0 | High, Medium |
| **Total** | **131** | **85** | **46** | |

## Discovery Rule Coverage

| Rule Pack | Rules | Category |
|---|---|---|
| api_keys.yaml | 17 | AI credentials (OpenAI, Anthropic, HF, Google, Cohere, Replicate, Mistral, Groq, AWS, Pinecone, GitHub, Slack, Jira, Brave, LangChain, WandB, Azure OpenAI) |
| mcp_configs.yaml | 5 | MCP configuration files |
| local_llm.yaml | 9 | Local LLM artifacts (Ollama, GGUF, SafeTensors, pickle, PyTorch, ONNX, LM Studio, Docker AI, Ollama env) |
| vectordb_rag.yaml | 9 | Vector DB, RAG configs, training data, notebooks, LLMjacking indicators |
| core_assessment.yaml | 9 | Fine-tuning data (manifests, CSV, HF dataset files), Arrow/TFRecord, RAG pipelines, LLMjacking, DB connection strings, LangChain RAG config |
| **Total** | **49** | |

## Operator console

Alongside the module verbs, two commands let an operator drive a service **by hand**
at any reachable stage — authenticated or unauthenticated. This is manual
interaction only: the operator issues every request/turn, and there is **no**
automated chaining (that is explicitly deferred). Captured responses are mined for
credentials into the loot index; nothing is redacted. Full reference:
[`request`](../cli/request.md), [`shell`](../cli/shell.md).

| Command | What it does | Modules |
|---|---|---|
| `request` | One-shot arbitrary HTTP operation issued through the tool; response captured and mined for loot. Honest and modest — Info severity, `landed` read-confirmed (2xx) / reachable (non-2xx), `stage` access/recon; never claims impact/own from a bare request. | Top-level `aipostex request METHOD PATH-OR-URL`, plus a per-module `request` verb on **mlflow, ray, ollama, openai-compat, litellm, vectordb, huggingface** |
| `shell` | Interactive REPL holding a session; on exit the session's responses are mined for credentials. Four shells: **LLM chat** (`ollama`/`openai-compat`/`litellm`/`huggingface`, ungated), **Jupyter kernel** Python REPL, **MCP tool-caller**, **A2A task console**. The execution shells (jupyter/mcp/a2a) require `--force-exploit`. | `<module> shell` |

Kubernetes has no in-tool shell: its interactive channel is `kubectl`, handed off as
a kubeconfig by the dossier's `manual/` folder.

## Lab harness parity

End-to-end checks against the live lab live in the companion repo [aipostex-lab](https://github.com/professor-moody/aipostex-lab) script `lab-scripts/attack-box/verify-aipostex.sh`.

**Automated there (operator / active / contract layers):** `discover network`, `discover files`, `assess network` (unless `AIPOSTEX_SKIP_ASSESS=1`), `scan targets`, `mcp` (analyze, config-hijack, enum, stdio, poison), `openai-compat`, `ray`, `mlflow`, `gradio`, `ollama`, `vectordb` (enum, extract, **search-sensitive**), `jupyter` (including `notebooks --mine-secrets`, read-notebook, gated proofs), BentoML, Triton, TorchServe (including register-plus-handler verification), and TF Serving (including signature-shaped predict guidance and input-dependent inference verification).

**Not driven by that harness (manual, scoring-only, or optional layers):** `templates`, `report`, `engagement`, `model-scan`, top-level `litellm` (LiteLLM is still exercised via `openai-compat litellm-probe`), and MCP `env-extract` (no deterministic assertions in the default script). The operator console (`request` / `shell`) is manual-driven and is likewise not asserted by the default script.

## Current Gaps

These features are still planned or intentionally deferred:

| Feature | Status | Description |
|---|---|---|
| `validate` | Deferred | Finding validation and confidence scoring |
| SQLite output | Deferred | Database output format for querying |
| Additional transports | Deferred | More transport coverage beyond current HTTP and MCP stdio support |
| Resumable jobs | Deferred | Long-running job orchestration and resume |
| Deeper provider-specific workflows | Planned | More service-specific exploit depth where generic coverage is not enough |
| Model supply chain validation | Partial | `model-scan` CLI with directory excludes, size cap, GGUF handling; extend signals as needed |
| Cloud AI service probing | Planned | SageMaker, Bedrock, Vertex AI, Azure OpenAI endpoint discovery |
| Campaign-style reporting | Deferred | Bizarre Bazaar-style resale-risk summaries and commercial-abuse packaging wait until provider-specific module depth is stronger |

## Build Plan Phases

The project follows a phased build plan:

1. **Correctness** -- assessment loop hardening, deduplication, summaries (done)
2. **MCP Expansion** -- deeper MCP coverage, poison modes, capability classification (done)
3. **OpenAI-Compatible** -- generic inference validation, auth sweep, tool enumeration, prompt testing, throughput (done)
4. **Runtime/OPSEC** -- proxy, stealth, embed, signal handling, guardrails (done)
5. **Service Backlog** -- Ray, MLflow, Gradio depth modules (done)
6. **Lab/Release** -- CI/CD, documentation, release packaging, lab validation at 91.8% (done)

## MITRE ATLAS Mapping

Templates reference MITRE ATLAS techniques where applicable:

| Technique | Coverage |
|---|---|
| AML.T0049 (Exploit Public-Facing Application) | Ollama, MCP, vector DBs, Jupyter, Ray, MLflow, Gradio, OpenAI-compat, vLLM, LangChain |
| AML.T0034 (Cost Harvesting) | OpenAI-compat throughput, Ollama generate, HF TGI inference, HF TEI embedding |
| AML.T0040 (ML Model Inference API Access) | Ollama, OpenAI-compat validate-inference, HF TGI, HF TEI, LangServe chain invoke |
