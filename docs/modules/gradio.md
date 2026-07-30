# Gradio

Enumerate and probe Gradio application instances.

## Overview

The `gradio` module targets Gradio web applications, covering configuration discovery, prediction endpoints, queue-based execution, file upload/download, file-chain correlation, and serve-path probing. It follows a predict/upload to file-chain to serve-probe progression.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Config discovery: version, title, endpoints, capabilities |
| `predict` | Call a prediction endpoint |
| `download-file` | Download a file by reference path |
| `file-chain` | Drive a file through the read chain (correlate file paths) |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `queue-probe` | Queue-backed execution probe |
| `upload-file` | Upload a proof file |
| `serve-probe` | Validate re-serve and file path accessibility |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | Gradio app URL (e.g., `http://127.0.0.1:7860`) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--api-name` | For `predict`, `queue-probe`, `upload-file` | API endpoint name |
| `--fn-index` | Alternative to `--api-name` | Function index number (also for `upload-file`) |
| `--input-json` | For `predict`, `queue-probe` | Input data as JSON array |
| `--file` | For `upload-file`, `download-file`, `file-chain`, `serve-probe` | File path or reference |
| `--filename` | For `upload-file` | Upload filename |
| `--content` | For `upload-file` | File content string |

!!! note
    Either `--api-name` or `--fn-index` is required for `predict` and `queue-probe`, but not both.

## Examples

```bash
# Enumerate config and endpoints
./aipostex gradio --target http://127.0.0.1:7860 enum

# Call a prediction endpoint
./aipostex gradio --target http://127.0.0.1:7860 predict \
  --api-name predict --input-json '["hello"]'

# Queue-backed execution probe (gated)
./aipostex gradio --target http://127.0.0.1:7860 queue-probe \
  --api-name predict --input-json '["hello"]' --force-exploit

# Upload a proof file (gated)
./aipostex gradio --target http://127.0.0.1:7860 upload-file \
  --api-name predict --force-exploit

# Download a file reference
./aipostex gradio --target http://127.0.0.1:7860 download-file \
  --file /tmp/gradio/demo.txt

# Correlate file paths
./aipostex gradio --target http://127.0.0.1:7860 file-chain \
  --file /tmp/gradio/demo.txt

# Validate serve paths (gated)
./aipostex gradio --target http://127.0.0.1:7860 serve-probe \
  --file /tmp/gradio/demo.txt --force-exploit
```

## Capability Classification

The `enum` command classifies Gradio app capabilities:

- **Queue enabled** -- whether the app uses queue-based execution
- **File input/output** -- whether endpoints accept or return files
- **API surface** -- discovered callable endpoints with parameter info

## What each `landed` level means here

`landed` records what actually landed on the target for each finding. The Gradio module reaches these levels:

| `landed` | What produces it in gradio |
|---|---|
| `reachable` | `enum` (config, endpoints, capabilities) and `queue-probe` when only queue status metadata came back — the app responded but nothing was accepted. |
| `influenced` | `predict` (a prediction endpoint accepted input), `upload-file` (a file was accepted onto the upload surface), and `queue-probe` when a queue job was accepted and returned execution handles — input landed, but the effect is not yet read back. |
| `read-confirmed` | `download-file`, and `file-chain` / `serve-probe` when a file path returns content — a file was read off the target through the serve/read chain. |

This module tops out at `read-confirmed`. Gradio never runs code for us: `predict`/`queue-probe`/`upload-file` confirm only that input was accepted (`influenced`), and the strongest concrete outcome is reading a served file back (`read-confirmed`) — it does not reach `execution-confirmed` or `takeover-capable`.

## Workflow Progression

```
discover network (discovers Gradio on :7860)
  → gradio enum (config, endpoints, capabilities)
    → gradio predict --api-name <name> (test prediction)
      → gradio queue-probe (queue execution, gated)
      → gradio upload-file (file upload, gated)
        → gradio download-file --file <ref> (read uploaded file)
        → gradio file-chain --file <ref> (correlate paths)
          → gradio serve-probe --file <ref> (validate serve, gated)
```

Returned file references and queue/event handles are preserved in finding metadata for chaining.
