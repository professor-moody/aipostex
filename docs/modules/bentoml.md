# BentoML

Enumerate and exploit BentoML model serving services.

## Overview

The `bentoml` module targets BentoML services that expose REST APIs for model inference. It discovers service metadata, parses OpenAPI specs for prediction endpoints, derives concrete example payloads from request schemas, tests inference access, and extracts Prometheus metrics.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Enumerate service metadata, health, and API routes |
| `routes` | Parse OpenAPI spec for all prediction endpoints with input schemas and emit schema-shaped `predict` follow-ons |
| `metrics` | Retrieve Prometheus metrics (request counts, latency, model performance) |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `predict` | Send a prediction request to test inference access |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | BentoML service URL (default port 3000) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--endpoint` | For `predict` | Prediction endpoint path (default: `/`) |
| `--payload` | For `predict` | JSON payload for prediction |

## What each `landed` level means here

`landed` records what actually landed on the target for each finding. The BentoML module reaches these levels:

| `landed` | What produces it in bentoml |
|---|---|
| `reachable` | `enum` (service metadata and health), `routes` (prediction endpoints parsed from the OpenAPI spec plus generated payload guidance), `metrics` (Prometheus data), and `predict` when the endpoint responds but output does not vary with a mutated input. |
| `execution-confirmed` | `predict` when the inference reality probe confirms input-dependent inference — output varies for distinct inputs, so the handler ran input-dependent code rather than returning a canned fixture (it does not warrant real ML-model semantics). |

This module has no intermediate `read-confirmed` or `influenced` step and does not reach `takeover-capable`. A `predict` whose response does not vary with a mutated input stays at `reachable` rather than over-claiming execution.

## Examples

```bash
# Enumerate service metadata
./aipostex bentoml --target http://127.0.0.1:3000 enum

# List all prediction routes from OpenAPI spec
./aipostex bentoml --target http://127.0.0.1:3000 routes

# Extract Prometheus metrics
./aipostex bentoml --target http://127.0.0.1:3000 metrics

# Test inference access (gated)
./aipostex bentoml --target http://127.0.0.1:3000 predict \
  --endpoint /predict --payload '{"text":"aipostex-sample"}' --force-exploit
```

## Key Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Service metadata (name, version) |
| `/healthz` | GET | Health check |
| `/docs.json` | GET | OpenAPI specification |
| `/metrics` | GET | Prometheus metrics |
| `/<endpoint>` | POST | Prediction endpoints (from OpenAPI spec) |

## Workflow Progression

```
discover network (discovers BentoML on :3000)
  -> bentoml enum (service metadata, routes)
    -> bentoml routes (detailed endpoint discovery + concrete payload follow-ons)
    -> bentoml metrics (operational data)
    -> bentoml predict --endpoint <route> (inference test, gated)
```
