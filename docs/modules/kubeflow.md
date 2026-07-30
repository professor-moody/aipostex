# Kubeflow

Enumerate and exploit Kubeflow Pipelines API instances.

## Overview

The `kubeflow` module targets the Kubeflow Pipelines REST API (`/pipeline/api/v1beta1/`). It enumerates pipelines, runs, and experiments, lists Kubeflow Notebooks, and tests unauthenticated pipeline run creation. Kubeflow Pipelines is commonly deployed on shared ML platforms with misconfigured authentication, enabling direct API access to production ML workflows.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Probe API reachability and detect API version |
| `pipelines` | List accessible ML pipelines and their parameters |
| `runs` | List pipeline runs with status and pipeline correlation |
| `experiments` | List experiments |
| `notebooks` | List Kubeflow Notebooks in a namespace |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `run-pipeline` | Inject a new pipeline run via the Pipelines API |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | Kubeflow URL (default port 8080) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--namespace` | No | Kubernetes namespace for notebook listing (default: `kubeflow`) |
| `--pipeline-id` | For `run-pipeline` | Pipeline ID to execute |
| `--experiment-id` | No | Experiment ID for the new run |
| `--run-name` | For `run-pipeline` | Name for the new run |
| `--param` | No | Pipeline parameters as `key=value` pairs. Repeatable. |

## Key Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/pipeline/api/v1beta1/pipelines` | GET | List pipelines (page_size=50, sort by created_at) |
| `/pipeline/api/v1beta1/runs` | GET | List runs |
| `/pipeline/api/v1beta1/runs` | POST | Create a new run (gated) |
| `/pipeline/api/v1beta1/experiments` | GET | List experiments |
| `/notebook/api/namespaces/{ns}/notebooks` | GET | List Kubeflow Notebooks |
| `/pipeline/` | GET | Dashboard fallback — used as reachability probe when v1beta1 is unavailable |

## Reachability Detection

The `enum` subcommand first probes `GET /pipeline/api/v1beta1/pipelines?page_size=1`. If that returns an error, it falls back to `GET /pipeline/` to confirm dashboard reachability. A successful API probe sets `APIVersion=v1beta1`.

## What each `landed` level means here

The `landed` axis records what actually landed on the target. Every kubeflow finding lands at `reachable`: the module confirms unauthenticated access to the Pipelines API and reads its inventory (pipelines, runs, experiments, notebooks) and even plaintext secrets from pipeline parameters, but it does not currently emit a stronger `landed` level — `run-pipeline` submits a run rather than confirming downstream execution.

| `landed` | What produces it in kubeflow |
|---|---|
| `reachable` | Every subcommand — `enum` (API reachable, version detected), `pipelines` / `runs` / `experiments` / `notebooks` (inventory read, sensitive pipeline params surfaced as credentials), and `run-pipeline` (a run injected via the API) |

## Examples

```bash
# Enumerate API reachability
aipostex kubeflow --target http://10.0.0.30:8080 enum

# List ML pipelines and parameters
aipostex kubeflow --target http://10.0.0.30:8080 pipelines

# List pipeline run history
aipostex kubeflow --target http://10.0.0.30:8080 runs

# List experiments
aipostex kubeflow --target http://10.0.0.30:8080 experiments

# List Kubeflow Notebooks in a namespace
aipostex kubeflow --target http://10.0.0.30:8080 notebooks --namespace kubeflow

# Inject a pipeline run (gated)
aipostex kubeflow --target http://10.0.0.30:8080 \
  run-pipeline --pipeline-id <pipeline-id> --run-name injected \
  --param learning_rate=0.1 --force-exploit
```

## Workflow Progression

```
discover network (discovers Kubeflow on :8080)
  -> kubeflow enum (API version, reachability)
    -> kubeflow pipelines (pipeline inventory and parameters)
    -> kubeflow runs (run history and status)
    -> kubeflow experiments (experiment listing)
    -> kubeflow notebooks (notebook inventory)
    -> kubeflow run-pipeline (pipeline run injection, gated)
```

## Vulnerability Templates

| Template | Tags | Description |
|---|---|---|
| `kubeflow-dashboard-unauth` | `kubeflow` | Unauthenticated Kubeflow dashboard access |
| `kubeflow-enum-001-pipeline-access` | `kubeflow`, `mlops`, `pipeline` | Unauthenticated pipeline/experiment enumeration (read) |
