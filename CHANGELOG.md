# Changelog

All notable changes to aipostex are documented in this file.

## [v1.12.0] — 2026-08-13

**Examples that are guaranteed to run.**

### Fixed

- **Three `vectordb` examples were unrunnable.** They used a `--provider` flag that does not
  exist — the flag is `--type` — and `--help` rendered them happily. The previous check
  confirmed only that the *subcommand* resolved, but a wrong flag fails just as hard at the
  prompt as a wrong verb.

### Added

- **Example validation.** Every command's `Example` block is now walked, resolved through
  cobra (examples routinely place flags before the subcommand), and checked so that every long
  flag it uses actually exists on the resolved command. 319 example invocations are validated
  on each test run, so a documented command that could not run fails the build.

## [v1.11.0] — 2026-08-13

**A single source of truth for module identity, enforced by tests.**

### Added

- **Typed source registry** (`pkg/report/registry.go`) — every finding source is declared once,
  with its kind (module / operator / infrastructure), the CLI command that emits it, its
  documentation page, and its capability-matrix label. Module identity was previously implied by
  agreement between the Source constants, the display-key map, the published JSON schema, the
  module docs, the capability matrix, and the command tree, with nothing enforcing that they
  agreed.
- **Consistency tests** that bind every one of those sites back to the registry: each Source
  constant must be registered, the published schema enum must match it exactly, and every module
  must have its docs page, its display keys, a capability-matrix row, and a command actually
  registered on the root command. Each invariant was verified by introducing the drift it targets
  and confirming the test fails.

### Fixed

- **The capability matrix was missing eight modules** — `litellm`, `k8s`, `a2a`, `agent`, `rag`,
  `huggingface`, `kubeflow`, and `wandb` had shipped without ever being listed on the page a
  reader consults to learn what the tool covers. Rows are written from each module's real verb
  set.
- Two files had reached `main` unformatted because the lint job never checked formatting. Both
  are gofmt'd and `gofmt` is now enabled in `.golangci.yml`.

## [v1.10.0] — 2026-08-13

**The remaining MCP protocol surfaces + a documented CLI** — completes MCP coverage and gives
every command a real explanation.

### Added

- **`mcp roots`** (gated) — detects a server harvesting the *client* machine's filesystem layout
  via a server-initiated `roots/list`. The third server→client abuse primitive, alongside
  `sampling` and `elicitation`. Medium, `access`/`influenced`: aipostex advertises the capability
  but never answers, so no path is disclosed.
- **`mcp complete`** — enumerates server-side values through `completion/complete`. A server that
  answers completions discloses account ids, ticket numbers, usernames, and paths that no
  `resources/list` or `prompts/list` call exposes. Medium, `access`/`read-confirmed`.
- **`mcp logging`** (gated) — raises the server's verbosity with `logging/setLevel`, then captures
  the `notifications/message` output it pushes to a connected client. An accepted level change is
  `influenced`; a captured log is `read-confirmed`, and any secret in it reaches the credential
  index.
- **`mcp subscribe`** (gated) — establishes a `resources/subscribe` push channel, a standing read
  on a resource that needs no repeated polling. Accepted => `influenced`; a pushed update is never
  claimed unless observed, and servers that do not implement the method are reported honestly.
- **Resource templates** — `Client.ListResourceTemplates` (`resources/templates/list`).
  `resources/list` omits parameterized resources, so an entire templated data surface
  (`records://customers/{account_id}`) was invisible to enumeration. `enum` now lists templates and
  `complete` probes their arguments.

### Changed

- **Every command now documents itself.** 82 commands carried only a one-line `Short`, so `--help`
  named a verb without saying what it does or why the result matters. Each now has a `Long`
  covering what it does, what the returned data is worth to an operator, and whether it is
  read-only or gated — across a2a, agent, bentoml, gradio, huggingface, jupyter, k8s, kubeflow,
  litellm, mlflow, ollama, openai-compat, rag, ray, tfserving, torchserve, triton, vectordb, wandb,
  sessions, templates, version, and the six top-level workflow groups (which also gained examples).
  220 non-hidden commands, none missing an explanation.
- `docs/modules/mcp.md` documents the `--level`, `--uri`, and `--tool` flags; the coverage matrix
  now reflects the module's full verb set.

## [v1.9.0] — 2026-08-13

**MCP elicitation phishing + authorization probing** — completes the server→client abuse coverage
and adds an OAuth posture check.

### Added

- **`mcp elicitation`** (gated) — detects server→client elicitation phishing. Advertises the
  `elicitation` capability, invokes each tool (or `--tool`), and captures a server-initiated
  `elicitation/create` request — a malicious server prompting the connected client's USER for input
  mid-tool-call (credential phishing / unintended-approval injection), invisible to a `tools/list`
  enumeration. High, `access`/`influenced`: the server's behavior is confirmed, but aipostex never
  answers, so no user is actually prompted.
- **`mcp auth`** — probes the endpoint's authorization posture with no token. (1) **Enforcement** —
  an unauthenticated `initialize`; if accepted, the endpoint is anonymously reachable and its tools
  callable by anyone (Medium, `access`/`read-confirmed`); if rejected, the `WWW-Authenticate`
  challenge is captured. (2) **Discovery** — fetches the RFC 9728 protected-resource and RFC 8414
  authorization-server metadata, enumerating issuer, endpoints, scopes, and any registration
  endpoint. (3) **Open registration** — `--force-exploit` submits an unauthenticated RFC 7591 client
  registration; a minted `client_id` means open DCR (High, `access`/`influenced`), an attacker can
  self-provision OAuth clients.

## [v1.8.0] — 2026-08-12

**MCP data retrieval + sampling-abuse probe** — the MCP module now retrieves what it enumerates,
and detects a server that turns the client's own model against it.

### Added

- **`mcp enum --read`** — beyond listing, RETRIEVES each resource (`resources/read`) and prompt
  (`prompts/get`), graded `access`/`read-confirmed`. Required prompt arguments are filled with a
  probe value so retrieval succeeds. Evidence is unredacted, so credential-bearing resource data
  and server-supplied prompt injections surface into the credential index.
- **`mcp sampling`** (gated) — probes for server→client sampling abuse. Advertises the `sampling`
  client capability, invokes each tool (or `--tool`), and captures a server-initiated
  `sampling/createMessage` request — a malicious server driving the connected client's LLM
  (context exfiltration or free-proxy abuse), which a `tools/list` enumeration cannot see. Over
  Streamable HTTP the request rides the standalone GET event stream, so the probe watches that
  stream alongside the tool call. Graded High, `access`/`influenced`: the server's behavior is
  confirmed, but aipostex never answers the request, so victim-client compliance is not claimed.

## [v1.7.1] — 2026-08-12

**Honesty & correctness fixes** (from an external review; grading truthfulness).

### Fixed

- **Proof-level default no longer over-claims.** A `vulncheck` template check that declares
  neither `stage` nor `landed` is now graded at the conservative honesty floor
  `recon`/`reachable` — it is never inferred up to `impact`/`takeover-capable` (exploit) or
  `impact`/`read-confirmed` (detection) from the template's classification. A bare `2xx` is
  not takeover. Templates that read/execute/take over must declare their earned grade.
- **Finding IDs are unique per target.** `vulncheck` IDs were `template-check` (not
  per-target), so the same check against two hosts collided and the dossier's
  `evidence/<ID>.txt` overwrote. IDs now include a deterministic target discriminator.
- **Model fingerprint wording.** "verified by dated-event recall" → "observed dated
  knowledge" — RAG/tool access can supply recent facts and a model can misreport, so the
  cutoff bracket is a heuristic, not proof.
- **`agent session-probe`** detects a constant/shared session ID (same every request) — the
  worst case — instead of mislabeling a long constant token as opaque/secure.
- `finding-schema.json`: added the missing `agent` and `rag` finding sources.

## [v1.7.0] — 2026-08-12

**Advanced prompt-injection tradecraft + the threat-model view** — deepens the model/agent
layer with multi-turn techniques and turns findings into a threat-model deliverable.

### Added

- **`agent crescendo`** — multi-turn (crescendo) prompt injection. Fires a single-shot control,
  then walks a conversation ladder (rapport → capability priming → format priming → objective),
  sending the growing transcript each turn so a stateless `/chat` agent still gets full context.
  Beats a per-message input filter a single shot cannot; graded `impact`/`influenced` when the
  ramp emits the marker (High when the direct ask was refused).
- **`agent fragment`** — cross-turn fragmentation. Splits the injected token across turns, then a
  trigger turn reassembles it — evades a per-message content filter that scans for the intact token.
- **`agent session-probe`** — samples the agent's session identifiers and classifies the scheme
  (uuid / sequential / timestamp / short / opaque). Predictable schemes (a cross-session
  enumeration precondition) are flagged; UUID/opaque are the honest negative. Detects prefixed
  sequences (`review-1001`, `chat_42`).
- **`report view --threat-model`** — a threat-model deliverable built entirely from the honest
  `stage`/`landed` metadata: kill-chain coverage (furthest reach per target), crown jewels
  (deepest `landed` levels), and a curated MITRE ATLAS-aligned tactic mapping (specific `AML.T####`
  ids attached only where high-confidence — nothing fabricated).

## [v1.6.0] — 2026-08-12

**The model & agent layer** — extends aipostex past infrastructure recon into the model,
agent-conversation, and RAG layer, with honest landed/stage grading throughout.

### Added

- **`agent` module** — attack a bespoke `/chat` app over a configurable transport: `probe`, `enum`,
  `extract` (output-filter bypass), `fingerprint`, `inject` (input-filter-bypass matrix), `guardrail`.
- **`rag` module** — black-box RAG apps: citation recon, KB enumeration, and `poison --obey-marker`
  to verify *indirect* prompt injection (retrieved **and** obeyed).
- **`openai-compat fingerprint` + `internal/modelfingerprint`** — behavioral model attribution
  (identity, contradiction de-masking, knowledge-cutoff) that survives an identity-masking system prompt.
- **`serve` + serving verbs** gated by an input-differential reality probe (`internal/inferenceprobe`):
  a distinct input must yield a distinct output to earn `execution-confirmed`, else `influenced`.
- **`a2a register`** and **`mcp` sandbox-escape / SSTI** verbs; next-action guidance wired into the dossier/report.

## [v1.4.0] — 2026-07-03

**Operator output & the engagement dossier** — turns raw findings into a legible, handoff-ready
operator surface: one shared table grammar across every module, a real credential index, and a
dossier export.

### Added

- **Operator dossier** — `report view --format dossier -o <dir>` writes a handoff directory (findings,
  credentials in JSON/CSV/TXT, ready-to-run commands, per-finding evidence, and a native `manual/`
  handoff). `dossier` is also accepted as a `--format` value; `report view` gained a `--service` alias.
- **`report view --chains`** — an attack-board view that reconstructs the find → loot → chain narrative
  and shows where a chain reached vs. where it hit a gap.
- **Width-aware console output** — `--width`, `--no-banner`, and `--quiet`; a single shared table +
  framed-summary grammar across all modules; a dedicated credentials block with intact values.
- **Next-Actions completeness** — discovered identifiers are filled into follow-on commands, with no
  placeholder emitted where the id is already known.

### Changed

- Output overhaul: full-width tables, a folded Summary block, one-line Next Actions, ANSI-aware
  packing, and pretty default JSON.

### Fixed

- Credential index completeness — capture all Slack webhooks / GitHub PATs / DB-URI credentials per
  finding (not just the first); intact credential values in evidence; honest proof metadata and
  accurate proof strengths; consistent flags/help across modules.

## [v1.3.0] — 2026-06-30

Kubernetes **in-cluster lateral movement** — deepens the `k8s` module from read-on-one-apiserver into proven traversal of identities and namespaces within a single cluster.

### Added

- **`k8s access-review`** — `SelfSubjectRulesReview` maps the current identity's real authorization; `read-confirmed` when it self-reviews, honest `reachable` when it cannot (e.g. `system:anonymous` → 403).
- **`k8s sa-loot`** (`--force-exploit`) — exec-steal a pod's mounted service-account token, re-authenticate as that identity, and report a **measured** privilege delta. Write capability is measured with a non-persisting dry-run create (`?dryRun=All`) that runs the full authorization chain without touching etcd, so it works for any identity including `system:anonymous`; escalation is claimed only when the stolen identity can write where the foothold cannot (no-privilege-gain / read-only / delta-unconfirmed otherwise).
- **`--all-namespaces` / `-A`** on `k8s enum` and `k8s secret-read` — one identity reaching every namespace it can, with correct per-namespace attribution.
- `pkg/exploit/k8s/lateral.go`: `SelfSubjectRulesReview`, `CanCreate` (dry-run write-probe), `ReadServiceAccountToken`, and a `WithBearerToken` re-auth seam.

### Documentation

- `docs/modules/k8s.md` reframed: single apiserver, now traverses identities + namespaces *within* the cluster; cross-cluster/mesh, kubelet `:10250` pivot, cloud-metadata SSRF, and hostPath escape stay out of scope (not honestly provable on single-node k3s).
- DEF CON 34 RTV deck review (`docs/conference/defcon-34-deck-review.md`) and synced template/module stats across `README.md` and the docs site (131 templates / 85 detection / 46 exploit, 18 modules).

## [v1.2.0] — 2026-06-30

Kubernetes AI-workload module + A2A listener-confirmed probes.

### Added

- **`k8s` exploit module** — `rbac-probe`, `enum`, `secret-read`, `artifact-read`, `pod-exec` probing a kube-apiserver directly (no client-go). `pod-exec` runs over a `v5.channel.k8s.io` WebSocket and claims `exploited` only on real stdout (non-zero exit = execution-confirmed; stderr-only/truncated = reachable). kube-apiserver fingerprint + 3 anon-access vulncheck templates. Validated against a real k3s vuln/secure fixture (anon enum → secret exfil → in-pod RCE).
- **A2A out-of-band listener confirmation** — `card-spoof` / `push-hijack` accept an `http` `--callback-url` with a per-run nonce; only a real inbound callback (nonce-correlated) upgrades `influenced → exploited`. 5 new `a2a-exploit` templates (008–012), validated fire-on-vuln / quiet-on-secure.

### Documentation

- New `docs/modules/k8s.md`; completed the A2A module page and the home-page module table.

## [v1.1.0] — 2026-06-30

A2A offensive primitives, output-quality fixes, and a validated multi-estate lab.

### Added

- **A2A offensive verbs** — `auth-probe`, `msg-integrity`, `sender-spoof`, `delegate-probe`, `card-spoof`, proof-carrying via `applyProofMetadata`, live-validated against a real a2a-sdk agent (vuln vs. hardened). Fixed a verb crash against an auth-enforcing agent — a 4xx/5xx is now treated as a not-weak signal, not a transport abort.

### Changed

- Findings sort severity-descending (critical first) across all exploit modules.
- `vectordb search-sensitive` collapses overlapping match windows; `wandb enum` treats `/healthz` as a liveness probe (no bogus `version=ready!`).
- **Multi-estate lab** — `GROUP_ID`-parameterized Proxmox deploy validated live (3 isolated estates, ~99s parallel reset-wave).

## [v1.0.0] — 2026-06-29

First stable release. Highlights since v0.10.0:

### Added

- **RRR honesty model** — findings graded by proof strength (reachable / credential-gated read / execution), with a no-credential control probe and inference-reality probes so credential replays and inference aren't over-claimed.
- **Real MCP-transport template executor** + schema-aware `env-extract` + a `/mcp` fingerprint probe.
- **Single exploit gate** — `--force-exploit` governs all mutating/destructive actions (the `--confirm-destructive` double-gate was removed).

### Changed

- **Template honesty audit** — 50+ over-claims across the embedded corpus corrected to detection.

### Documentation

- Lab-validated guided credential chain (Ray → MLflow → HF TGI) and an in-depth RTV workshop demo.

## [v0.10.0] — 2026-04-14

HuggingFace TGI/TEI exploit module, Kubeflow Pipelines exploit module, and full `assess network` integration for both.

### Added

- **HuggingFace TGI/TEI exploit module** (`pkg/exploit/huggingface/`, `cmd/aipostex/huggingface.go`):
  - Auto-detects TGI vs TEI from `/info` response (`model_type` key presence)
  - `enum` — identify service type, model ID, version, and limits; emits workflow plan
  - `models` — list models served via `/v1/models` (TGI)
  - `metrics` — retrieve Prometheus metrics from `/metrics`
  - `generate` — send text generation request to `/generate`; requires `--force-exploit`
  - `embed` — send embedding request to `/embed`; requires `--force-exploit`
  - `SourceHuggingFace` added to `pkg/report/finding.go`
  - 8 client tests (`pkg/exploit/huggingface/client_test.go`), 4 CLI tests (`cmd/aipostex/huggingface_test.go`)

- **Kubeflow Pipelines exploit module** (`pkg/exploit/kubeflow/`, `cmd/aipostex/kubeflow.go`):
  - `enum` — probe `/pipeline/api/v1beta1/pipelines` with dashboard fallback; detect API version
  - `pipelines` — list pipelines with parameters
  - `runs` — list pipeline runs with status and pipeline correlation
  - `experiments` — list experiments
  - `notebooks` — list Kubeflow Notebooks in a namespace
  - `run-pipeline` — create a new pipeline run; requires `--force-exploit`
  - `SourceKubeflow` added to `pkg/report/finding.go`
  - 7 client tests (`pkg/exploit/kubeflow/client_test.go`), 4 CLI tests (`cmd/aipostex/kubeflow_test.go`)

- **`assess network` integration for HuggingFace and Kubeflow**:
  - `scan_all.go`: `runScanAllHuggingFaceEnum` (dispatched on `"hf-tgi"`, `"hf-tei"`) and `runScanAllKubeflowEnum` (dispatched on `"kubeflow"`)
  - `workflow.go`: 5-step workflow plans for both `"hf-tgi"/"hf-tei"` and `"kubeflow"`
  - `scan_network.go`: `"kubeflow"` added to `tagsToService` and `serviceToTags` maps (HF already present)
  - `credchain/autochain.go`: `hf-token` case upgraded from `openai-compat enum` to `huggingface enum`

### Documentation

- `docs/modules/huggingface.md` — new HuggingFace TGI/TEI module documentation
- `docs/modules/kubeflow.md` — new Kubeflow Pipelines module documentation

## [v0.9.0] — 2026-04-12

TensorFlow Serving exploit module, three MCP prompt-injection templates, `model-scan` expansion to TF/Keras/ONNX custom-op formats, and full `assess network` integration for TF Serving.

### Added

- **TensorFlow Serving (`tfserving`) exploit module** (`pkg/exploit/tfserving/`, `cmd/aipostex/tfserving.go`):
  - `enum` — probe server reachability via structured JSON error responses; detect Prometheus metrics endpoint
  - `models` — discover served model names by probing common names against `/v1/models/<name>`
  - `metadata` — retrieve model signature definitions and tensor shape specs from `/v1/models/<name>/metadata`
  - `metrics` — scrape Prometheus metrics from `/monitoring/prometheus/metrics`
  - `predict` — send an inference request to `/v1/models/<name>:predict`; requires `--force-exploit`
  - `Source: SourceTFServing` added to `pkg/report/finding.go`
  - Full test coverage: `pkg/exploit/tfserving/client_test.go` (9 tests), `cmd/aipostex/tfserving_test.go` (6 tests)

- **`assess network` integration for TF Serving** (`cmd/aipostex/scan_all.go`, `workflow.go`, `scan_network.go`):
  - `scan_all.go`: `runScanAllTFServingEnum` dispatched on fingerprint service `"tfserving"`
  - `workflow.go`: `buildScanNetworkWorkflowPlanInner` emits 5-step `tfserving` workflow plan
  - `scan_network.go`: `"tfserving"` added to both `tagsToService` and `serviceToTags` maps

- **3 new MCP prompt-injection templates** (123 total; 65 detection, 58 exploit):
  - `mcp-detect-015` — unauthenticated MCP resource listing (read-only detection)
  - `mcp-exploit-001` — MCP tool-call injection via crafted `params.arguments`
  - `mcp-exploit-002` — MCP prompt injection via tool description field

- **`model-scan` format expansion** (`pkg/modelscan/scanner.go`):
  - `.pb` (TensorFlow SavedModel): scans protobuf graph for Python function ops; emits `tf-python-op` (critical) or `model-format` (info)
  - `.h5` (Keras HDF5): validates HDF5 magic; scans for `"class_name":"Lambda"` — emits `keras-lambda-layer` (high)
  - `.keras` (Keras 3.x zip): opens zip, scans `config.json` for Lambda layers — emits `keras-lambda-layer` (high)
  - ONNX deep scan: `onnx-custom-op` (high) for non-standard operator domains; `onnx-external-data` (medium) for external tensor references
  - 9 new test cases in `pkg/modelscan/scanner_test.go`

### Documentation

- `docs/modules/tfserving.md` — new TF Serving module documentation
- `docs/modules/wandb.md` — new W&B module documentation (module added in v0.8.0, docs missing)
- `docs/modules/model-scan.md` — extended risk types table with `.pb`, `.h5`, `.keras`, ONNX custom-op and external-data risks

---

## [v0.8.0] — 2026-04-12

Six expansion phases adding two new exploit modules, session enhancements, credchain
wiring, nine new CVE templates (120 total), and full lab harness coverage.

### Added

- **Weights & Biases (`wandb`) exploit module** (`pkg/exploit/wandb/`, `cmd/aipostex/wandb.go`):
  - `enum` — health-check and viewer reachability, emits entity/username metadata
  - `projects` — list all projects for an entity, surfaces project metadata
  - `runs` — enumerate runs for a project including parameter configs and metrics
  - `artifacts` — list artifact versions by type (model, dataset) for a project
  - `secrets` — mine run configs for planted credentials using 6 regex patterns and 9 sensitive key names; requires `--force-exploit`
  - Credchain: discovered W&B API keys suggest `wandb enum`, `wandb projects`; OpenAI/Anthropic/HF keys trigger cross-module chain steps
  - Default port 8444; `Source: SourceWandB` added to `finding.go`

- **A2A `tool-inject` and `replay` subcommands** (`cmd/aipostex/a2a.go`):
  - `tool-inject` — scans multi-turn task histories for `tool_use` parts that call privileged tools (`read_file`, `execute_command`, `fetch_url`, `run_query`); extracts tool inputs as evidence; requires `--force-exploit`
  - `replay` — replays all completed task credential sequences and validates them against the POX oracle; requires `--force-exploit`
  - A2A client extended with `ListTasks`, `GetTask`, and credential-extraction helpers

- **VectorDB `rag-verify`** (`cmd/aipostex/vectordb.go`, `pkg/exploit/vectordb/inject.go`):
  - Injects a canary document into a collection then queries it back to prove end-to-end RAG poisoning susceptibility; requires `--force-exploit`
  - Emits `proof_stage: exploited` findings with injection and retrieval evidence

- **Session `export`** (`cmd/aipostex/sessions.go`, `internal/session/session.go`):
  - `session export` command streams all findings from the active or named session as a JSON envelope; supports `--format json/jsonl`
  - `session notes` subcommand for annotating the active session with free-text operator notes
  - `Session.Notes` field added to the persisted session struct

- **Credchain wiring** (`internal/credchain/autochain.go`):
  - W&B API key → `wandb enum --target <t>`, `wandb projects --entity <entity>`
  - LiteLLM master key → `litellm enum --target <t>`, `litellm config-extract --target <t>`
  - Ray dashboard token → `ray enum --target <t>`, `ray jobs --target <t>`

- **9 new CVE templates** (120 total; 64 detection, 56 exploit):
  - `cve-2025-27520-bentoml-rce-pickle` — BentoML pickle deserialization via unauthenticated predict endpoint
  - `cve-2025-32434-pytorch-rce-weights-only` — PyTorch `weights_only=False` RCE via crafted model weights
  - `cve-2025-34028-commvault-ssrf-rce` — Commvault pre-auth SSRF leading to RCE
  - `cve-2025-27607-jupyter-proxy-rfd` — Jupyter Server Proxy reflected file download
  - `cve-2025-1974-ingress-nginx-rce` — Ingress-NGINX admission controller RCE (Kubeflow vector)
  - `cve-2025-3248-langflow-rce` — Langflow unauthenticated code execution via `/api/v1/run`
  - `cve-2025-47241-litellm-ssrf` — LiteLLM SSRF via custom provider `api_base` parameter
  - `cve-2025-23242-triton-log-poisoning-rce` — Triton Inference Server log poisoning RCE
  - `cve-2025-29014-vllm-rce-mooncake` — vLLM Mooncake distributed KV-cache RCE

### Changed

- `session export` now supports `--format` (json/jsonl); previously only emitted console output
- A2A `enum` now reports seeded task count in `metadata.task_count` alongside `skill_count`

---

## [v0.7.1] — 2026-04-04

### Fixed
- **Milvus API-level error handling**: All Milvus REST client methods now check the application-level `code`/`message` fields in HTTP 200 responses. Previously, a non-zero `code` (e.g., authentication failure, invalid collection) was silently treated as success.
- **Milvus partial extraction signaling**: `ExtractDocuments` now returns accumulated rows *with* an error when page 2+ fails, instead of silently truncating. CLI commands (`search-sensitive`, `extract`) surface these partial failures in the summary.
- **Milvus injection error propagation**: `InsertEntities` and `InjectAndVerifyMetadata` now propagate API-level failures instead of reporting success on HTTP 200 with non-zero error codes.
- **MCP streamable-HTTP SSE support**: The MCP HTTP client now accepts `text/event-stream` responses from streamable-HTTP servers. Requests include `Accept: application/json, text/event-stream`, and SSE bodies are parsed to extract embedded JSON-RPC payloads.
- **MCP mixed-case URL normalization**: `NewClient` and `normalizeInspectorBase` now correctly handle mixed-case `/SSE` and `/Message` suffixes during URL normalization, using length-based slicing instead of `strings.TrimSuffix`.
- **VectorDB `search-sensitive` empty filter**: The `--collection` flag now errors when the filter matches nothing, preventing false-negative scans that silently skip all collections.

### Documentation
- Updated module docs for Ollama, Jupyter, Ray, MLflow, MCP, and Vector DBs to reflect all current subcommands.
- Added missing subcommand documentation: Ollama `exfiltrate`, Jupyter `start-kernel`/`reverse-shell-proof`/`pip-proof`, Ray `pip-inject`/`cluster-info`, MLflow `tamper-proof`.
- Corrected subcommand counts in module index.
- Updated architecture docs to reflect current template count and provider coverage.

---

## [v0.7.0] — 2026-04-04

Major version bump reflecting cumulative maturity: 12 exploit modules, 109 YAML templates
(64 detection, 45 exploit), 30 HTTP probes, 8 output formats, model-scan, full report
pipeline, and four rounds of Tier 2 review hardening (A/B/C/D-series).

This release consolidates all work from v0.1.0 through v0.2.0 into a single baseline
suitable for production engagement use.

### Highlights
- **12 exploit modules**: Ollama, Jupyter, MCP, OpenAI-Compatible, LiteLLM, Ray, MLflow, Gradio, Vector DBs (ChromaDB/Weaviate/Qdrant/Milvus/pgvector), BentoML, Triton, TorchServe
- **109 YAML templates** across 21 service categories (64 detection, 45 exploit, 19 CVE-specific)
- **30 HTTP fingerprint probes** covering 20+ AI service families
- **8 output formats**: Console, JSON, JSONL, CSV, HTML, SARIF, Markdown, PDF
- **`model-scan`**: Local model file analysis for pickle/PyTorch deserialization risk
- **Report pipeline**: `report render`, `report summary`, `report graph`, `engagement bundle`
- **Credential chain-loading**: Auto-extraction and workflow suggestion from discovered credentials
- **OPSEC controls**: Stealth mode, User-Agent rotation, TLS fingerprint randomization, proxy support
- **Tier 2 review hardening**: Four rounds (A/B/C/D-series) of correctness, reliability, and output accuracy fixes

---

## [v0.2.0] — 2026-04-03

### Added
- **`model-scan` command**: Bounded directory scan for risky model artifacts (pickle/PyTorch/ONNX, etc.) with size limits and ignore patterns.
- **BentoML and Weights & Biases surfaces**: Fingerprinting, `scan network` tagging, templates, and workflow hints where applicable.
- **LiteLLM dedicated module**: `litellm enum`, `config-extract`, `budget-probe`, `proxy-chain` for deep LiteLLM proxy assessment with credential discovery and health endpoint scanning.
- **Jupyter `notebooks --mine-secrets`**: Recursively discovers `.ipynb` paths under the Jupyter root (not only top-level listings) before mining; OpenAI `sk-proj-*` keys are matched alongside long classic `sk-*` secrets.
- **Template count**: 109 templates (64 detection, 45 exploit) across 21 service categories — up from 104.
- **TorchServe management probe**: New fingerprint probe for port 8081 management API.
- **Per-family template test coverage**: All 109 embedded templates validated at load time; 12 new per-family `LoadTemplate` + `Validate()` tests covering BentoML, W&B, Streamlit, LiteLLM, Kubeflow, TFServing, TorchServe, Triton, vLLM, VectorDB, Gradio (exploits), and HuggingFace (exploits).

### Fixed
- **Gradio queue probe**: Tries `/gradio_api/queue/join` and `/gradio_api/queue/status` when legacy `/queue/*` returns 404 (Gradio 5.x).
- **Gradio predict queue polling**: `predict` now detects queue-backed endpoints (`event_id`/`hash` responses) and polls `queue/data` for completed results instead of returning the raw event response.
- **`mlflow model-artifacts`**: Populates finding evidence so contract-style checks see `metadata.evidence` after output annotation. Now also extracts sensitive params/tags from the resolved run.
- **MLflow `enum`**: Now extracts sensitive params/tags for each enumerated run (not just the `runs` subcommand).
- **MLflow `secrets.go`**: Added `redis://`, `postgres://`, `amqp://`, PagerDuty, Anthropic, and infrastructure hostname patterns.
- **Jupyter XSRF**: POST operations (`start-kernel`, etc.) now acquire and send `_xsrf` tokens automatically via cookie jar.
- **Jupyter output mining**: `MineNotebookSecrets` now scans cell `outputs` (stream, execute_result, display_data) in addition to `source`. Added Snowflake connection string pattern.
- **Jupyter `ReadNotebook`**: Now appends `?content=1&type=notebook` to ensure full notebook content is returned.
- **HTML report**: Severity badge text normalized via `NormalizeSeverity`.
- **SARIF output**: Finding metadata round-trip — `finding_id`, `source`, `template_id`, `cvss`, and full metadata now populate `properties`.
- **Markdown output**: Expanded table with `ID`, `Source`, `CVSS` columns; per-finding detail blocks; hardened `mdEscape`.
- **CSV output**: `csvMetaString` fallback for non-string metadata values.
- **VectorDB `search-sensitive`**: Added `--exclude-collections` flag and collection-name heuristics to suppress false positives from public/documentation collections.
- **Auto-chain semantics**: `bearer-token` and `api-key` now generate distinct follow-up commands; `hf-token` uses bearer semantics.
- **`--auto-chain` flag text**: Clarified that the flag generates suggestions, not automatic execution.
- **Display keys**: Added `proof_stage`/`proof_strength` to VectorDB, Gradio, and MLflow source display keys.

### Notes
- Lab harness: `verify-aipostex.sh` should invoke `gradio queue-probe` with `--api-name`, `--input-json`, and `--force-exploit` (see aipostex-lab repo).

## [v0.1.2] — 2026-04-02

### Added
- **Jupyter cell secret mining**: `read-notebook` now regex-scans notebook cells for API keys (OpenAI, Anthropic, HuggingFace, AWS), connection strings (PostgreSQL, MySQL, MongoDB, Redis), and generic credential patterns. Each match is emitted as a separate finding with `proof_strength: read-confirmed`.
- **MLflow sensitive parameter extraction**: `runs` command now flags sensitive parameter names (password, secret, token, key) and parameter values containing S3/GCS/Azure URIs, connection strings, or embedded API keys. Extracted secrets are emitted as additional high-severity findings.
- **Model file discovery rules**: Added `.pkl`, `.pt`, `.pth`, `.bin` (pickle/PyTorch deserialization risk), `.onnx` (model interchange), `.arrow`, `.tfrecord`/`.tfrecords` (training data exposure) to file discovery rules.
- **Streamlit detection templates**: Two new templates — `streamlit-auth-001-unauthenticated-app` (unauthenticated access + config exposure) and `streamlit-enum-001-health-metadata` (health endpoint, message origins, stream endpoint metadata disclosure).
- Template count: **104** (60 detection, 44 exploit) across **20** categories.

### Fixed
- No functional changes; all new features are additive.

## [v0.1.1] — 2026-03-28

### Added
- 5 exploit-mode templates across Ollama, Jupyter, OpenAI-compatible, and MCP categories.
- 9 new file discovery rules for credentials, training data, RAG configs, and LLMjacking indicators.
- Lab validation coverage: 91.8% (112/122 planted findings).

## [v0.1.0] — 2026-03-25

### Added
- Initial release with discovery → scanning → exploitation pipeline.
- `discover network` and `discover files` commands for AI infrastructure reconnaissance.
- `scan targets` with YAML-based vulnerability templates (88 templates across 18 categories).
- `assess network` full-assessment orchestrator.
- Exploit modules: Ollama, Jupyter, MCP, OpenAI-compatible, Ray, MLflow, Gradio, ChromaDB, Weaviate, Qdrant.
- `openai-compat` with auth-sweep, litellm-probe, prompt-test, and tool-enum subcommands.
- Credential chain-loading: automatic extraction and injection of discovered credentials.
- Proof strength classification on all findings.
- OPSEC controls: User-Agent rotation, TLS fingerprint randomization, jitter, concurrency caps.
- Output formats: JSON, JSONL, CSV, Markdown table.
- `engagement merge` for combining findings across runs.
- `report summary` for executive and technical report generation.
- MkDocs documentation site.
- CI/CD with GitHub Actions (lint, test, build, docs deploy, tag-driven release).

### Security
- All mutating/exploit actions gated behind `--force-exploit` flag.
- `--mode full` required for exploit templates during scanning.
