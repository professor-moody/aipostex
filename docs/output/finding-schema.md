# Finding Schema

Every aipostex output -- from file discovery to exploit modules -- produces `report.Finding` structs with this schema.

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique finding identifier (e.g., `f-a1b2c3d4e5f6`) |
| `timestamp` | ISO 8601 | Yes | When the finding was produced |
| `source` | string | Yes | Module that generated the finding |
| `template_id` | string | No | Template ID (vulncheck findings only) |
| `target` | string | Yes | Target URL, host, or file path |
| `title` | string | Yes | Finding headline |
| `severity` | string | Yes | Severity level |
| `cvss` | float | No | CVSS score |
| `description` | string | Yes | Detailed description |
| `remediation` | string | No | Recommended fix |
| `evidence` | string | No | Evidence supporting the finding |
| `tags` | string[] | No | Filterable tags |
| `references` | string[] | No | Reference URLs |
| `metadata` | object | No | Source-specific structured metadata |

## Source Values

The `source` field identifies which module generated the finding:

| Source | Description |
|---|---|
| `file-discovery` | `discover files` filesystem scanner |
| `fingerprint` | `discover network` service detection |
| `vulncheck` | `scan targets` / `discover network` template engine |
| `ollama` | Ollama exploit module |
| `vectordb` | Vector database exploit module |
| `jupyter` | Jupyter exploit module |
| `mcp` | MCP exploit module |
| `openai-compat` | OpenAI-compatible exploit module |
| `ray` | Ray exploit module |
| `mlflow` | MLflow exploit module |
| `gradio` | Gradio exploit module |
| `litellm` | LiteLLM proxy exploit module |
| `huggingface` | HuggingFace TGI/Hub exploit module |
| `bentoml` | BentoML exploit module |
| `triton` | Triton Inference Server exploit module |
| `torchserve` | TorchServe exploit module |
| `tfserving` | TensorFlow Serving exploit module |
| `kubeflow` | Kubeflow exploit module |
| `wandb` | Weights & Biases exploit module |
| `a2a` | Agent-to-Agent (A2A) exploit module |
| `k8s` | Kubernetes exploit module |
| `credential` | Credential extraction |

## Severity Levels

| Level | Color (Console) | Usage |
|---|---|---|
| `critical` | White on red | Remote code execution, SSRF to cloud metadata, complete takeover |
| `high` | White on bright red | Unauthenticated API access, credential exposure, model enumeration |
| `medium` | Black on yellow | Information disclosure, config exposure, partial access |
| `low` | White on blue | Minor information leakage, version disclosure |
| `info` | White on gray | Informational findings, service detection, version info |

## Metadata

The `metadata` field is a flexible map that varies by source module. Common keys include:

### Exploit Module Metadata

| Key | Description |
|---|---|
| `module` | Module name (e.g., `ollama`, `vectordb`) |
| `action` | Subcommand that produced the finding |
| `mutating` | Whether the action modified target state |
| `provider` | Service provider (for vectordb: `chromadb`, `weaviate`, `qdrant`) |
| `model` | Model name |
| `version` | Service version |
| `collection` | Collection name |
| `kernel` | Kernel ID |
| `tool` | MCP tool name |
| `endpoint` | API endpoint |
| `path` | File or artifact path |
| `job_id` | Ray job ID |
| `experiment` | MLflow experiment |
| `run_id` | MLflow run ID |
| `artifact_path` | MLflow artifact path |
| `fn_index` | Gradio function index |

### Scan Mode Metadata

| Key | Description |
|---|---|
| `scan_mode` | The scan mode that was active when the finding was produced: `detect` or `full` |

### Stage & Landed Metadata

Every finding carries two axes describing what an operator actually got. Both are set from
observed behavior — the tool never claims more than it saw.

| Key | Description |
|---|---|
| `stage` | Kill-chain position: `recon`, `access`, `impact`, `own` |
| `landed` | What actually landed on the target (see table below) |
| `chain_source` | What triggered the chain (e.g., `discover network`, `enum`) |
| `capability_labels` | Classified capabilities (e.g., `fetch`, `exec`, `file`) |

#### `stage` Values

| Value | Meaning |
|---|---|
| `recon` | A surface was found or fingerprinted (services, endpoints, versions) |
| `access` | The target accepted or processed our input (submitted, correlated) |
| `impact` | Exploitation was proven against the target |
| `own` | The target is takeover-capable — full control demonstrated |

#### `landed` Values

| Value | Meaning |
|---|---|
| `reachable` | Endpoint responded; service presence confirmed |
| `influenced` | Input was accepted and reflected/processed by the target; no readback yet |
| `read-confirmed` | Data was read from the target (config, models, files) |
| `execution-confirmed` | Arbitrary code or command execution achieved |
| `takeover-capable` | Full system or service takeover possible |

!!! note "Auto-badge behavior"
    All `vulncheck` findings (template-based) automatically receive `stage: impact` and an appropriate `landed`. Detection templates get `read-confirmed`; exploit templates get `execution-confirmed`. If the template already sets explicit `stage`/`landed`, the explicit values are preserved. Findings with auto-set metadata also receive auto-generated evidence containing the HTTP request and response details.

### Auth & Scoring Metadata (openai-compat)

| Key | Description |
|---|---|
| `acceptance_class` | Auth pattern classification |
| `auth_pattern` | Specific auth pattern tested |
| `coherence_score` | Inference output quality score |
| `rate_limit_signal` | Rate limiting detection |
| `throughput_score` | Throughput test result |
| `value_score` | Model value assessment |

### Fingerprint Metadata

| Key | Description |
|---|---|
| `service` | Detected service name |
| `host` | Target hostname |
| `port` | Target port |
| `port_state` | Port inventory state (currently `open`) |
| `fingerprint_status` | Port-level fingerprint summary: `confirmed`, `suspected`, `ambiguous`, `candidate`, or `unidentified` |
| `specificity` | Legacy per-probe strength score (1-100), retained for compatibility |
| `confidence` | Final operator-facing confidence tier: `high`, `medium`, or `low` |
| `match_kind` | Final classification: `confirmed`, `suspected`, or `ambiguous` |
| `version` | Detected service version (when available) |
| `proxy_likely` | Whether the service appears behind a reverse proxy (3+ services on same port) |
| `timed_out` | Whether the per-port fingerprint budget expired before the probe plan finished |
| `incomplete` | Whether the open-port observation is partial/incomplete |
| `candidate_services` | Service candidates that matched some evidence but did not survive final classification |
| `matched_probes` | Ordered list of matched probe paths that produced the fingerprint |
| `ambiguity_reason` | Why the fingerprint was downgraded (for example `generic_match_only`, `proxy_likely`) |
| `coverage_expanded` | Vulnerability templates were intentionally run across plausible identities for an ambiguous/proxy-like port |
| `identity_confidence` | Confidence attached to a template finding after fingerprint expansion, such as `ambiguous` |
| `skip_reason` | Why a discovered service was skipped for one phase, such as `http-template-incompatible` for non-HTTP ports |

`specificity` is kept so older tooling does not break, but the preferred operator interpretation is:

- `port_state` and `fingerprint_status` tell you whether the port was open and how far fingerprinting got.
- `match_kind` tells you whether the fingerprint is treated as confirmed, weak/suspected, or ambiguous.
- `confidence` reflects the final confidence after probe strength, corroboration, default-port alignment, and multi-service overlap are considered.
- `candidate_services`, `matched_probes`, `timed_out`, and `ambiguity_reason` explain why a port stayed partially identified or was downgraded.
- `coverage_expanded=true` means the finding is useful coverage, but the service identity is intentionally labeled as uncertain rather than authoritative.

### Deduplication Metadata

| Key | Description |
|---|---|
| `dedupe_count` | Number of duplicate findings collapsed into this one |

### Workflow and Evidence Metadata

See [Workflow Metadata](workflow-metadata.md) for the `workflow` and `evidence` metadata structures.

## JSON Example

```json
{
  "id": "f-a1b2c3d4e5f6",
  "timestamp": "2025-01-15T10:30:01Z",
  "source": "ollama",
  "target": "http://10.0.0.5:11434",
  "title": "Ollama Enumeration - 3 models, version 0.1.44",
  "severity": "high",
  "description": "Ollama instance enumerated without authentication.",
  "remediation": "Enable authentication via reverse proxy.",
  "evidence": "{\"models\": [\"llama3\", \"mistral\", \"codellama\"], ...}",
  "tags": ["ollama", "enum"],
  "metadata": {
    "module": "ollama",
    "action": "enum",
    "model": "llama3",
    "version": "0.1.44",
    "stage": "impact",
    "landed": "read-confirmed",
    "workflow": {
      "recommendations": [
        {
          "command": "aipostex ollama --target http://10.0.0.5:11434 prompts",
          "rationale": "Extract system prompts from discovered models",
          "gated": false,
          "priority": 10
        }
      ]
    }
  }
}
```

## FindingCollection Wrapper (JSON format)

When using `--format json`, findings are wrapped in a collection:

```json
{
  "engagement_id": "eng-a1b2c3d4e5f6",
  "start_time": "2025-01-15T10:30:00Z",
  "end_time": "2025-01-15T10:30:05Z",
  "findings": [ ... ]
}
```

The `engagement_id` is a random hex string prefixed with `eng-`, generated once per command invocation.
