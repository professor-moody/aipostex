# Triton Inference Server

Enumerate and exploit NVIDIA Triton Inference Server instances.

## Overview

The `triton` module targets the Triton Inference Server REST API (KFServing v2 protocol). It discovers server metadata, lists loaded models with their configurations, probes for shared memory vulnerabilities (CVE-2025-23319/23320/23334), and tests inference and model lifecycle operations.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Server metadata, health status, and extensions |
| `models` | List all loaded models with detailed metadata |
| `model-config` | Detailed model configuration (instance groups, scheduling, optimization) |
| `shm-probe` | Probe shared memory regions for IPC vulnerability chain (CVE-2025-23319/23320/23334) |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `infer` | Send inference request to a model |
| `model-load` | Load a model from the repository (proves model injection surface) |
| `model-unload` | Unload a model (proves destructive model lifecycle access) |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | Triton HTTP API URL (default port 8000) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--model` | For `model-config`, `infer`, `model-load`, `model-unload` | Model name |
| `--payload` | For `infer`; optional for `model-load` | JSON inference payload. On `model-load`, invokes the model after load to verify it became inferable. |

## Key Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/v2` | GET | Server metadata (name, version, extensions) |
| `/v2/health/ready` | GET | Readiness probe |
| `/v2/health/live` | GET | Liveness probe |
| `/v2/models` | GET | List all loaded models |
| `/v2/models/<name>` | GET | Model metadata (inputs, outputs, platform) |
| `/v2/models/<name>/config` | GET | Detailed model configuration |
| `/v2/models/<name>/infer` | POST | Model inference |
| `/v2/repository/index` | POST | Model repository listing |
| `/v2/repository/models/<name>/load` | POST | Load model from repository |
| `/v2/repository/models/<name>/unload` | POST | Unload model |
| `/v2/systemsharedmemory/status` | GET | System shared memory regions |
| `/v2/cudasharedmemory/status` | GET | CUDA shared memory regions |

## SHM Probe (IPC Vulnerability Chain)

The `shm-probe` subcommand checks for the Wiz-discovered IPC vulnerability chain affecting Triton:

- **CVE-2025-23319** -- shared memory region manipulation
- **CVE-2025-23320** -- CUDA shared memory corruption
- **CVE-2025-23334** -- IPC exploitation for code execution

If shared memory status endpoints expose region data (names, keys, offsets, byte sizes), it indicates the IPC attack surface is accessible.

## What each `landed` level means here

`landed` records what actually landed on the target for each finding. The Triton module reaches these levels:

| `landed` | What produces it in triton |
|---|---|
| `reachable` | `enum` (server metadata/health), `models` and `model-config` (model inventory and config disclosure), `shm-probe` (exposed shared-memory regions), and any gated write whose request did not succeed. |
| `influenced` | `model-load` / `model-unload` when Triton accepts the lifecycle request but no post-load inference verification is performed. |
| `execution-confirmed` | `infer` when the inference reality probe confirms input-dependent handler execution (output varies for distinct inputs); `model-load` when `--payload` is supplied and the same input-differential probe confirms the loaded model returns input-dependent output — a bare 2xx with a static prediction stays `influenced`. |

This module has no `read-confirmed` step and does not reach `takeover-capable`: reads (`models`, `model-config`, `shm-probe`) stay at `reachable` (detection), lifecycle writes without verification stay `influenced`, and `model-load` reaches `own/execution-confirmed` only when the repository model is loaded and then answers through the inference API. Note the inference-reality gate on standalone `infer` — a canned/fixture response that does not vary with input stays at `reachable` rather than over-claiming execution.

## Examples

```bash
# Enumerate server metadata
./aipostex triton --target http://127.0.0.1:8000 enum

# List loaded models
./aipostex triton --target http://127.0.0.1:8000 models

# Get detailed model config
./aipostex triton --target http://127.0.0.1:8000 model-config --model resnet50

# Probe shared memory (IPC vuln chain)
./aipostex triton --target http://127.0.0.1:8000 shm-probe

# Test inference (gated)
./aipostex triton --target http://127.0.0.1:8000 infer \
  --model resnet50 --payload '{"inputs":[]}' --force-exploit

# Load a model from repository (gated)
./aipostex triton --target http://127.0.0.1:8000 model-load \
  --model test --force-exploit

# Load and verify the repository model is inferable (gated)
./aipostex triton --target http://127.0.0.1:8000 model-load \
  --model test --payload '{"inputs":[]}' --force-exploit
```

## Workflow Progression

```
discover network (discovers Triton on :8000)
  -> triton enum (server metadata, health)
    -> triton models (loaded model inventory)
    -> triton model-config --model <name> (detailed config)
    -> triton shm-probe (IPC vulnerability assessment)
    -> triton infer --model <name> (inference test, gated)
    -> triton model-load --model <name> (model injection, gated)
    -> triton model-load --model <name> --payload <json> (load + inference verification, gated)
```
