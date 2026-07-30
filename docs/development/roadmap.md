# Offensive Capability Roadmap

This roadmap is the active expansion plan for aipostex after the v1.x module
baseline. It is capability-led: the goal is to add things an operator can use
directly in an engagement, not to over-package campaign narratives before the
core modules are deeper.

The roadmap prioritizes:

1. Better service coverage.
2. Deeper enumeration.
3. Stronger exploit proof paths.
4. Credential, artifact, and infrastructure pivots.
5. Better "what next?" UX and richer raw evidence.

Campaign-style reporting, including Bizarre Bazaar resale-risk summaries, is
explicitly deferred until the core service modules are deeper.

## Recently shipped

- **Operator console (`request` / `shell`).** Manual by-hand interaction with a
  service at any reachable stage, authed or unauthed. `request` issues a one-shot
  arbitrary HTTP operation through the tool (top-level, plus a per-module verb on
  mlflow/ray/ollama/openai-compat/litellm/vectordb/huggingface); `shell` holds an
  interactive session (LLM chat, Jupyter kernel, MCP tool-caller, A2A task console).
  Captured responses feed the credential index on exit. See
  [`request`](../cli/request.md) and [`shell`](../cli/shell.md).
- **Follow-on completeness (in progress).** Every exploit verb should emit accurate
  kill-chain next-actions — the toolwide realization of **P0-UX-01** (operator
  next-action board). Phase 1 shipped: the a2a offensive verbs (card-spoof,
  push-hijack, msg-integrity, sender-spoof, replay, delegate-probe, auth-probe) now
  chain to the existing a2a verb that deepens the same weakness (a HIGH/
  takeover-capable finding is no longer a dead end). Fanning out across all modules,
  building the missing post-exploitation verbs (persistence / own-depth / serving-own,
  the deferred Phase B/C/D) as the chains require.
- **Post-exploitation persistence (started, Phase D).** `k8s persist` deploys a
  bounded, benign, self-healing workload (a labelled busybox canary) with the
  current or stolen identity and confirms the cluster runs it — honest
  `takeover-capable` on a Running pod, `influenced` when accepted-but-not-running,
  and a clean `reachable` "not achieved" when the identity can't create workloads.
  The first of the deferred Phase-D persistence verbs; extends the k8s kill-chain
  past pod-exec/sa-loot.
- **MLflow own-depth (started, Phase B).** `bulk-download` recursively downloads
  capped artifacts from a run or registered model version and emits ordinary
  findings for each artifact read. It proves artifact exfiltration, not served
  model execution; serving/load verification remains a separate gap.
- **HuggingFace own-depth (started, Phase B).** `model-download` resolves a served
  TGI/TEI model ID and performs capped Hub-compatible model file reads. It reports
  `reachable` with zero bytes when Hub storage/DNS is unavailable and only escalates
  to `takeover-capable` when weight/checkpoint bytes are actually read.
- **Automated credential chaining is explicitly deferred.** The console is manual
  interaction only — the operator drives every request/turn. Auto-walking a chain
  across services is out of scope for now, not a near-term item.

## Research anchors

| Source | Operational takeaway | Roadmap impact |
|---|---|---|
| [Operation Bizarre Bazaar / LLMjacking](https://www.pillar.security/blog/operation-bizarre-bazaar-first-attributed-llmjacking-campaign-with-commercial-marketplace-monetization) | Exposed LLM and MCP endpoints are scanned, validated, and monetized at scale. Attackers care about unauthenticated OpenAI-compatible APIs, Ollama, MCP, model quality, and usable inference. | Keep LLMjacking coverage, but prioritize better endpoint enumeration and proof quality over campaign packaging. |
| [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/) | Prompt injection, sensitive disclosure, supply chain, data/model poisoning, excessive agency, vector weaknesses, and unbounded consumption remain durable categories. | Use OWASP as a coverage checklist across modules, not as the organizing structure. |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Agentic systems add risk around autonomous planning, tool use, identity, and multi-step workflows. | Deepen MCP/A2A, tool registries, delegation, memory/session exposure, and agent identity tests. |
| [CSA ATLAS agentic gap analysis](https://labs.cloudsecurityalliance.org/agentic/csa-research-note-atlas-agentic-gap-analysis-20260327/) | Agent-to-agent lateral movement, tool-chain poisoning, orchestrator hijack, credential relay, memory persistence, and MCP pivoting are not fully covered by classic AI taxonomies. | Add agentic gap coverage as explicit backlog items. |
| [ShadowRay 2.0](https://www.oligo.security/blog/shadowray-2-0-attackers-turn-ai-against-itself-in-global-campaign-that-hijacks-ai-into-self-propagating-botnet) | Ray clusters remain a high-value AI infrastructure target for compute abuse, credential theft, and propagation. | Keep Ray, Kubernetes, and ML-control-plane chains high priority. |
| [LMDeploy rapid exploitation / AI-infra SSRF](https://www.sysdig.com/blog/cve-2026-33626-how-attackers-exploited-lmdeploy-llm-inference-engines-in-12-hours) | Inference-framework SSRF and media fetch bugs are exploited quickly and unlock metadata, Redis/MySQL, internal admin ports, and cloud credentials. | Make multimodal URL fetch and inference SSRF first-class checks for LMDeploy, vLLM, SGLang, and OpenAI-compatible services. |

## Planning rules

- Keep the existing professional offensive posture. Do not add a new safety-gate
  philosophy as part of this roadmap.
- Preserve raw evidence. Presentation can improve, but evidence should remain
  complete in machine-readable outputs.
- Prefer first-class modules when the operator needs guided enum-to-proof
  workflows. Templates are enough only for simple request/response checks.
- Exploit findings must be honest about what landed: reachable, influenced,
  read-confirmed, execution-confirmed, or takeover-capable — never over-claiming.
- Every first-class module needs mocked client tests, CLI tests, docs examples,
  output schema checks, and a lab validation path before it is considered done.

## Current capability matrix

| Surface | Current coverage | Main gap | Priority |
|---|---|---|---|
| Ollama | First-class module, prompts, generate, model operations, capped weight exfiltration, templates. | Better model value scoring, model tamper validation, and cost/resource exposure. | P1 |
| OpenAI-compatible | First-class generic module with auth sweep, enum, inference validation, prompt/tool tests, throughput, proxy tests, LiteLLM probe. | Provider-specific divergence for vLLM, LMDeploy, SGLang, LocalAI, LM Studio, and multimodal SSRF. | P0 |
| vLLM | Template coverage and OpenAI-compatible generic coverage. | No first-class module for config, adapters, LoRA, tokenizer/model metadata, metrics, SSRF, or provider-specific exploit flow. | P0 |
| LMDeploy | No first-class module. | Multimodal URL SSRF, OpenAI-compatible enum, `/v1/chat/completions` media fetch behavior, metrics, model metadata. | P0 |
| SGLang | No first-class module. | Runtime-specific routes, model metadata, OpenAI-compatible behavior, metrics, SSRF/media fetch checks. | P0 |
| LocalAI / LM Studio | Fingerprint and generic OpenAI-compatible coverage. | Dedicated enum and local-model metadata flows; clearer next actions after discovery. | P1 |
| LiteLLM | First-class module exists, plus generic OpenAI-compatible probe. | Needs deeper admin/config/key exposure, provider routing, team/user/budget surfaces, and credential chaining. | P0 |
| MCP | Strong first-class module with analyze, config-hijack, enum, poison, env extraction, chain, HTTP/stdio, templates. | Deeper tool-chain poisoning, registry trust, memory/session exposure, credential relay, and inspector-to-remote automation. | P0 |
| A2A | First-class module and many exploit templates. | Deeper multi-agent delegation, card trust, memory/session leakage, and cross-agent relay evidence. | P0 |
| Vector DBs / RAG | ChromaDB, Weaviate, Qdrant, Milvus, pgvector enum/extract/search/inject paths. | Schema graphing, tenant awareness, backup/snapshot exposure, sensitive embedding search, and poison persistence reporting. | P1 |
| Jupyter | First-class enum, notebooks, cell secret mining, read, kernel exec, proof commands. | Extension/config enrichment, environment inventory, notebook-to-cloud credential chain. | P1 |
| Ray | Deep module for dashboard, jobs, logs, artifacts, submit, runtime env, pip injection, cluster info. | Better cluster-state enrichment, job dependency graphing, cloud credential inventory, GPU/cost impact. | P0 |
| MLflow | Deep module for tracking, runs, registry, artifacts, model versions, capped bulk artifact download, tamper proof, registry version mutation, and controller-confirmed hook metadata. | Serving/load verification for registry mutations, model package provenance. | P1 |
| Kubeflow | First-class module for API enum, pipelines, runs, experiments, notebooks, run creation. | Pipeline spec secret mining, notebook/pod pivots, artifact stores, KServe/Seldon links. | P1 |
| Kubernetes AI workloads | First-class kube-apiserver module with RBAC, secret read, artifact read, exec, SA loot. | KServe/Seldon/Kubeflow CRD graphing, GPU nodes, model-serving workload lineage, kubelet/cloud pivots. | P1 |
| W&B | First-class enum/projects/runs/artifacts/secrets. | Deeper artifact/model lineage, token scope inference, reportable training-data exposure. | P2 |
| Hugging Face TGI/TEI | First-class module and templates, including bounded Hub-compatible model file download. | Model abuse details, cache path enrichment, and value scoring. | P1 |
| BentoML | First-class enum/routes/predict/metrics, including OpenAPI schema-shaped predict follow-ons and input-dependent inference verification. | Runner/model versioning and pickle/custom runner exposure. | P2 |
| Triton | First-class enum/models/config/infer/load/unload/shm, including model-load plus post-load inference verification. | Broader repository manipulation, ensemble graphing, deeper IPC exposure validation. | P1 |
| TorchServe | First-class enum/models/predict/register/scale/unregister/metrics, including register-plus-handler execution verification. | MAR metadata extraction, deeper ShellTorch-style chain evidence. | P1 |
| TensorFlow Serving | First-class enum/model metadata/signature/metrics/infer, including signature-driven payload generation and input-dependent inference verification. | Model version drift and SavedModel provenance. | P2 |
| LangChain / LangServe | Template coverage. | No first-class module for playground/schema/routes, memory exposure, chain invoke, callback/tool surfaces. | P0 |
| Streamlit | Template coverage. | No first-class module for app metadata, file/config exposure, component endpoints, secrets.toml hints. | P2 |
| Cloud AI / identity | File rules and some credential chain suggestions. | Bedrock, SageMaker, Vertex AI, Azure OpenAI/ML endpoint discovery, IAM role exposure, key scope validation. | P1 |
| Model supply chain | `model-scan` for pickle/PyTorch/ONNX/TF/Keras/GGUF risks. | Provenance, model-card/config risk, HF cache/package scan, external data, unsafe loader chain evidence. | P1 |
| UX / workflow | Workflow metadata, report view, graph, dossier, docs, next actions, operator console (`request`/`shell`). | Better operator task board, module gap hints, evidence navigation, chain status, and lab validation markers. | P0 |
| Campaign packaging | Some Bizarre Bazaar-style templates and generic LLMjacking validation. | Full resale-risk/campaign summary mode. | Deferred |

## Priority lanes

### P0: Next operational depth

These items should be prioritized before campaign packaging or broad platform
work.

| ID | Capability | Deliverable |
|---|---|---|
| P0-INF-01 | First-class `vllm` module | Dedicated enum, models, metrics, adapters/LoRA, tokenizer/config metadata, inference proof, multimodal URL fetch probe, OpenAI-compatible auth divergence. |
| P0-INF-02 | First-class `lmdeploy` module | OpenAI-compatible enum, VLM media URL SSRF checks, model metadata, metrics, inference proof, internal network probe evidence. |
| P0-INF-03 | First-class `sglang` module | Runtime detection, model metadata, metrics, OpenAI-compatible enum, media fetch/SSRF checks, inference proof. |
| P0-LITE-01 | LiteLLM depth | Admin/config extraction, provider routing graph, team/user/budget enum, key generation where supported, credential chain outputs. |
| P0-AGENT-01 | MCP tool-chain poisoning | Detect and prove malicious tool descriptions, tool shadowing, schema hidden-instruction channels, and registry trust failures. |
| P0-AGENT-02 | MCP/A2A credential relay | Capture cases where one agent/tool leaks or relays credentials into another tool, task, prompt, resource, or callback. |
| P0-A2A-01 | A2A delegation depth | Multi-step delegation probes, card trust validation, memory/session leakage, sender identity abuse, and status/history scraping. |
| P0-RAY-01 | Ray cluster enrichment | Job dependency graph, runtime env package inventory, GPU/CPU resource summary, cloud credential hints, artifact lineage. |
| P0-UX-01 | Operator next-action board | A report/view mode that groups findings into concrete chains along the kill-chain: recon -> access -> impact -> own (discovery, credential-loading, enumeration, artifact collection). |

### P1: High-value expansion after P0

| ID | Capability | Deliverable |
|---|---|---|
| P1-LANG-01 | First-class LangServe/LangChain module | Routes/playground/schema enum, chain invoke, memory exposure, callback/tool surfaces, prompt/template extraction. |
| P1-VDB-01 | Vector schema graphing | Collection/class/table schema graph, tenant/database context, embedding dimensions, indexes, row/object counts, sensitivity hints. |
| P1-VDB-02 | Snapshot and backup exposure | Qdrant snapshots, Weaviate backups, Chroma persistence paths, Milvus backup/index metadata, pgvector dump hints. |
| P1-RAG-01 | Sensitive embedding search | Operator-supplied query embedding or text-to-query workflows to find semantically sensitive documents beyond regex. |
| P1-K8S-01 | AI workload graph | KServe, Seldon, Kubeflow, Ray, Triton, TorchServe, BentoML, GPU node, service account, and artifact-store correlation. |
| P1-MLFLOW-01 | Model registry chain | Model version -> source artifact -> environment file -> dependency risk -> serving target follow-ons. |
| P1-MODEL-01 | Model package provenance | Scan model cards, configs, manifests, HF cache metadata, external data references, unsafe loaders, and declared remote code. |
| P1-CLOUD-01 | Cloud AI identity probes | Bedrock, SageMaker, Vertex AI, Azure OpenAI/ML endpoint discovery and credential scope checks where the operator supplies credentials. |
| P1-HF-01 | HF TGI/TEI enrichment | Served model value, embedding dimensions, generation limits, cache path hints, and follow-on scoring around downloaded configs/weights. |

### P2: Breadth and adjacent platforms

| ID | Capability | Deliverable |
|---|---|---|
| P2-STREAM-01 | First-class Streamlit module | App metadata, config exposure, file/component endpoints, secrets hints, form/action enumeration. |
| P2-FLOW-01 | Flowise / Dify / n8n-AI | Fingerprints, unauth enum, workflow/credential exposure, tool/node graph extraction. |
| P2-OBS-01 | LangSmith / LangFuse / prompt observability | Trace, prompt, completion, evaluation-data exposure templates and modules if coverage warrants it. |
| P2-SERVE-01 | KServe / Seldon first-class coverage | K8s CRD-aware enum, inference endpoint mapping, model artifact URI extraction, predict proof. |
| P2-BENTO-01 | BentoML runner depth | Runner/model version inventory and pickle/custom runner risk evidence after route-specific payload generation. |
| P2-TF-01 | TF Serving version drift | Version drift reporting and SavedModel provenance after signature-driven payload generation. |
| P2-WANDB-01 | W&B lineage | Training run -> artifact -> model/dataset lineage, token scope hints, secrets evidence grouping. |

### Deferred: Campaign packaging

Campaign-style packaged reporting should wait until the module depth above is
stronger.

| ID | Capability | Defer until |
|---|---|---|
| D-CAMP-01 | Bizarre Bazaar-style campaign summary | vLLM, LMDeploy, SGLang, LiteLLM, MCP, and A2A depth are in place. |
| D-CAMP-02 | Resale-risk scoring | Model value, throughput, auth acceptance, and cost exposure are reliable across provider-specific modules. |
| D-CAMP-03 | Commercial-abuse narrative report | The operator next-action board already captures concrete chains and evidence. |

## Epic details

### Inference servers and gateways

Build dedicated modules when generic OpenAI-compatible behavior hides important
runtime differences.

Required first-class module shape:

- `enum`: service identity, version, model inventory, auth behavior, metrics hints.
- `models`: model names, aliases, tokenizer/config metadata, context limits,
  multimodal support, adapters/LoRA where available.
- `metrics`: Prometheus or runtime metrics with request counts, latency, model
  names, GPU/CPU hints, and cost/value indicators.
- `validate-inference`: one bounded request with coherent response scoring.
- `media-fetch-probe`: operator-supplied URL probe for multimodal SSRF-style
  fetch behavior, with explicit evidence for fetched/not-fetched.
- `config`: runtime-specific config and environment exposure where a service
  exposes it.
- `workflow`: next actions from discovered model IDs, auth patterns, metrics,
  and SSRF/media-fetch results.

Initial target order:

1. `vllm`
2. `lmdeploy`
3. `sglang`
4. `localai`
5. LM Studio
6. LiteLLM depth as a gateway/control-plane module

### Agentic, MCP, and A2A

The unique value of aipostex is not just endpoint scanning; it is showing how
agentic systems can be turned into chains.

Backlog themes:

- Tool poisoning through descriptions, schemas, hidden instructions, examples,
  and metadata.
- Tool shadowing and registry trust failures.
- MCP server compromise as a pivot to file systems, databases, cloud metadata,
  Kubernetes, and internal APIs.
- A2A delegation abuse, sender identity confusion, decorative signatures, push
  callback hijack, and task-history leakage.
- Cross-session memory persistence and memory leakage.
- Credential relay through agent-to-agent or tool-to-tool workflows.

Acceptance standard:

- Findings must name the agent/tool/resource involved.
- Evidence must include the tool/schema/prompt/resource field that carried the
  control or secret.
- Follow-on commands must preserve discovered identifiers such as tool names,
  task IDs, card URLs, resources, prompts, and server aliases.

### RAG and vector stores

RAG coverage should move from "can read documents" toward "can map and influence
retrieval behavior."

Backlog themes:

- Schema graphing across ChromaDB, Weaviate, Qdrant, Milvus, and pgvector.
- Tenant, database, class, collection, table, partition, shard, and index
  awareness.
- Sensitive embedding search using operator-provided query text or embeddings.
- Snapshot, backup, dump, and persistence exposure.
- Poison persistence and retrieval verification.
- Metadata injection and source-field trust testing.
- End-to-end RAG verification when an LLM endpoint can be paired with a vector
  store.

### ML control planes

Control-plane modules should connect jobs, artifacts, registries, notebooks,
secrets, workloads, and cloud identity.

Backlog themes:

- Ray job/runtime/package/resource graphing.
- MLflow registry-to-artifact-to-serving chain; bulk registry-to-artifact download and controller-confirmed hook metadata are built, served load/execution verification remains.
- Kubeflow pipeline specs, run parameters, notebook pivots, and artifact stores.
- Kubernetes AI workload graphing with KServe/Seldon/Kubeflow/Ray/Triton links.
- W&B run/artifact/model lineage.
- GPU/cost impact reporting based on observed resource metadata, not estimates
  when the target does not expose resource data.

### Model and supply chain

`model-scan` should become the local artifact counterpart to network scanning.

Backlog themes:

- HF cache and snapshot scan.
- Model card/config/manifests with remote-code and unsafe-loader indicators.
- ONNX external data and custom ops with better path evidence.
- Keras/TensorFlow Lambda and Python op evidence.
- PyTorch pickle and `trust_remote_code` style risk correlation.
- Model package provenance: hash, source URI, license, declared architecture,
  referenced files, and suspicious scripts.
- Reproducible evidence bundle for model-risk findings.

### Cloud AI and identity

Cloud AI work should be credential-aware and operator-driven. It should avoid
pretending unauthenticated internet probes can honestly enumerate provider APIs.

Backlog themes:

- AWS Bedrock model/provider enum with supplied credentials.
- SageMaker endpoints, notebooks, training jobs, model packages, and endpoint
  configs.
- Vertex AI endpoints, models, datasets, and service-account exposure.
- Azure OpenAI / Azure ML deployments and key/identity scope checks.
- API gateway and AI gateway inventory when gateway credentials are supplied.
- IAM role and cloud metadata pivots from AI-serving hosts when evidence is
  available through Ray/Kubernetes/SSRF chains.

### UX and operator workflow

UX work should make the existing evidence more usable without hiding raw data.

Backlog themes:

- A `report view --chains` or equivalent operator board grouping evidence into
  attack paths.
- Chain state labels: candidate, reachable, credentialed, read-confirmed,
  accepted, execution-confirmed, landed.
- Module gap hints: if discovery finds a service only covered by templates, show
  the best module or planned first-class workflow.
- Evidence navigation: jump from report summary to raw finding ID, target,
  credential, artifact, task ID, model, collection, or run.
- Lab validation markers in docs: mocked, lab-validated, live-product validated,
  or template-only.
- Better command examples generated from actual metadata rather than generic
  placeholders.

## Testing and acceptance

Every first-class module must include:

- Client tests using `httptest` or protocol-specific mocks.
- CLI tests for required flags, output writing, stage/landed metadata, and failure
  behavior.
- Output schema checks for JSON/JSONL metadata fields.
- Workflow recommendation tests for discovered identifiers.
- Documentation examples under `docs/modules/`.
- At least one lab validation plan, even if the service is not in the default
  lab yet.

Every exploit-depth item must include:

- Evidence that the effect landed, or a finding that clearly says accepted,
  submitted, reachable, or unconfirmed.
- A failure-path test where the target rejects the action.
- No claims based only on HTTP 200 when the API has a structured error body.
- Raw evidence preservation in JSON/JSONL.

Every research-backed item must include:

- A source link, or a note that the item came from repo-internal coverage gaps.
- A clear distinction between observed abuse, framework coverage, and
  speculative future work.

## Documentation requirements

For each completed roadmap item:

- Update the module docs.
- Update the coverage matrix.
- Add examples that show the intended operator flow.
- State whether the feature is mocked-only, lab-validated, or live-product
  validated.
- Keep campaign packaging references deferred unless the item directly improves
  endpoint enumeration, proof quality, or exploit chaining.

## Non-goals for the current roadmap

- Do not prioritize Bizarre Bazaar-style packaged reports ahead of module depth.
- Do not add a new safety-gate or scope-control framework beyond existing
  conventions.
- Do not redact raw evidence by default.
- Do not build broad SaaS credential validation unless the operator supplies
  credentials and the result is useful inside an authorized assessment.
- Do not add new first-class modules that only wrap one simple HTTP template;
  keep those as templates until guided workflow depth is justified.
