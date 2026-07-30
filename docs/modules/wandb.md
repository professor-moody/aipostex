# Weights & Biases (W&B)

Enumerate and extract data from Weights & Biases server instances.

## Overview

The `wandb` module targets self-hosted Weights & Biases (`wandb server`) deployments and the public `api.wandb.ai` endpoint. It enumerates server metadata and viewer identity via the GraphQL API, lists projects and runs for a given entity, inventories model artifacts, and scans run configs and summaries for embedded credentials (API keys, tokens, AWS secrets).

W&B servers that lack authentication or use weak shared API keys expose full training history, hyperparameters, and any secrets logged during training runs.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Enumerate W&B server metadata and authenticated viewer identity |
| `projects` | List projects for an entity |
| `runs` | List runs for a project |
| `artifacts` | List artifacts for a project |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `secrets` | Scan run configs and summaries for embedded credentials |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | W&B server URL (e.g. `http://wandb.corp:8080` or `https://api.wandb.ai`) |
| `--header` | No | Custom HTTP headers. Repeatable (`Key: Value`). |
| `--api-key` | No | W&B API key. Defaults to `WANDB_API_KEY`; ignored when `--header 'Authorization: ...'` is supplied. |
| `--entity` | For `projects`, `runs`, `artifacts`, `secrets` | W&B entity (username or team name) |
| `--project` | For `runs`, `artifacts`, `secrets` | W&B project name |
| `--type` | No | Artifact type filter for `artifacts` (default: `model`) |
| `--limit` | No | Maximum runs to return / scan (default: `25`) |

## Examples

```bash
# Enumerate server metadata and viewer identity
./aipostex wandb --target http://wandb.corp:8080 enum

# List all projects for an entity
./aipostex wandb --target http://wandb.corp:8080 projects --entity myteam

# List recent runs for a project
./aipostex wandb --target http://wandb.corp:8080 runs \
  --entity myteam --project my-model --limit 50

# List model artifacts for a project
./aipostex wandb --target http://wandb.corp:8080 artifacts \
  --entity myteam --project my-model --type model

# Scan run configs and summaries for secrets (gated)
./aipostex wandb --target http://wandb.corp:8080 secrets \
  --entity myteam --project my-model --force-exploit
```

## Workflow Progression

```
discover network (discovers W&B server on :8080)
  -> wandb enum (server metadata, viewer identity)
    -> wandb projects --entity <entity> (project inventory)
      -> wandb runs --entity <entity> --project <project> (run history)
      -> wandb artifacts --entity <entity> --project <project> (model artifacts)
      -> wandb secrets --entity <entity> --project <project> (credential scan, gated)
```

## What `secrets` Scans For

The `secrets` subcommand fetches run configs and summaries and applies pattern matching against:

- AWS access keys (`AKIA…`)
- API tokens and bearer credentials
- Passwords and secrets in config keys (`password`, `api_key`, `secret`, `token`, etc.)
- OpenAI / Anthropic / HuggingFace API keys

Findings are emitted as `high`-severity report entries carrying the matched key and its real value (evidence and the structured `extracted_credentials` channel are never redacted, so `report view --credentials` lists each named secret with its actual value). Each run source (`run_id`, config/summary section) is recorded alongside the match.

## What each `landed` level means here

Findings carry a `landed` axis recording what actually landed on the target. W&B is a read-only enumeration module, so it tops out at `read-confirmed` — it never writes to or executes on the target.

| `landed` | What produces it in wandb |
|---|---|
| `reachable` | `enum`, `projects`, `runs`, `artifacts` — server metadata, viewer identity, and inventory were enumerated; nothing has been read off the runs yet. |
| `read-confirmed` | `secrets` — run configs and summaries were fetched and scanned (whether or not a credential matched), confirming we read the target's run data. |

Ceiling: `read-confirmed`. The module reads training history and any logged secrets but never submits a write, so it cannot reach `influenced`, `execution-confirmed`, or `takeover-capable`.

## Implementation

Client logic lives in [`pkg/exploit/wandb`](https://github.com/professor-moody/aipostex/tree/main/pkg/exploit/wandb); CLI in `cmd/aipostex/wandb.go`.
