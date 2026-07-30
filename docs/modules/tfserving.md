# TF Serving

Enumerate and exploit TensorFlow Serving REST API instances.

## Overview

The `tfserving` module targets the TensorFlow Serving SavedModel REST API. It probes for server reachability via structured error responses, enumerates model status and metadata, and tests inference operations. TF Serving does not expose a model list endpoint, so the `models` subcommand probes common model names to discover what is served. When `metadata` exposes a signature, aipostex derives a concrete example prediction payload and emits a gated follow-on command using the discovered model name.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Probe server reachability and detect metrics endpoint |
| `models` | Discover served models by probing common model names |
| `metadata` | Retrieve model signature definitions and tensor specs; emit a shape-aware `predict` follow-on when possible |
| `metrics` | Retrieve Prometheus metrics from the monitoring endpoint |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `predict` | Send an inference request to a model |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | TF Serving URL (default port 8501) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--model` | For `metadata`, `predict` | Model name |
| `--version` | No | Model version (predict only; defaults to latest) |
| `--payload` | For `predict` | JSON inference payload |

## Key Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/models` | GET | Reachability probe (returns 404 JSON for unknown model — confirms server presence) |
| `/v1/models/<name>` | GET | Model version status and state |
| `/v1/models/<name>/metadata` | GET | Model signature definitions and tensor specs |
| `/v1/models/<name>:predict` | POST | Model inference (latest version) |
| `/v1/models/<name>/versions/<ver>:predict` | POST | Model inference (specific version) |
| `/monitoring/prometheus/metrics` | GET | Prometheus metrics |

## Reachability Detection

TF Serving returns a structured JSON error body for 404 responses (e.g. `{"code":5,"message":"Servable not found..."}`). The `enum` subcommand exploits this to confirm server presence even when no models are known in advance.

## What each `landed` level means here

`landed` records what actually landed on the target for each finding. The TF Serving module reaches these levels:

| `landed` | What produces it in tfserving |
|---|---|
| `reachable` | `enum` (server presence via the structured 404 probe), `models` (models discovered by name probing), `metadata` (signature/tensor-spec disclosure plus generated payload guidance), `metrics` (Prometheus data), and `predict` when the endpoint responds but output does not vary with a mutated input. |
| `execution-confirmed` | `predict` when the inference reality probe confirms real, input-dependent inference (output varies for distinct inputs). |

This module has no intermediate `read-confirmed` or `influenced` step and does not reach `takeover-capable`. `metadata` is deliberately capped at `reachable`: it confirms a model is exposed but is neither a credential-gated read nor real inference. A `predict` whose response does not vary with a mutated input stays at `reachable` rather than over-claiming execution.

## Examples

```bash
# Probe for server reachability
./aipostex tfserving --target http://127.0.0.1:8501 enum

# Discover served models (probes common names)
./aipostex tfserving --target http://127.0.0.1:8501 models

# Get model metadata and signature
./aipostex tfserving --target http://127.0.0.1:8501 metadata --model acme-fraud-scorer

# Get Prometheus metrics
./aipostex tfserving --target http://127.0.0.1:8501 metrics

# Test inference (gated)
./aipostex tfserving --target http://127.0.0.1:8501 predict \
  --model acme-fraud-scorer \
  --payload '{"instances":[[0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0,1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8,1.9,2.0,2.1,2.2,2.3,2.4,2.5,2.6,2.7,2.8,2.9,3.0,3.1,3.2]]}' \
  --force-exploit
```

## Workflow Progression

```
discover network (discovers TF Serving on :8501)
  -> tfserving enum (reachability, metrics probe)
    -> tfserving models (model inventory via name probing)
    -> tfserving metadata --model <name> (signature definitions + concrete payload follow-on)
    -> tfserving metrics (Prometheus data)
    -> tfserving predict --model <name> (inference test, gated)
```
