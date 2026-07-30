# Jupyter

Enumerate and exploit Jupyter Notebook server instances.

## Overview

The `jupyter` module targets Jupyter Notebook servers, covering server metadata, kernel enumeration, notebook listing and reading, guarded code execution via the WebSocket kernel interface, and proof-of-concept actions for reverse shell capability and pip package installation. POST operations automatically acquire and send `_xsrf` tokens via cookie jar.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Server metadata and status |
| `kernels` | List active kernels |
| `notebooks` | List notebook files; optional `--mine-secrets` fetches each notebook and scans cells for credentials |
| `read-notebook` | Read a notebook file by path |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `exec` | Execute code in a running kernel via WebSocket |
| `start-kernel` | Start a new kernel on the server |
| `reverse-shell-proof` | Prove outbound socket capability via a kernel (uses non-routable TEST-NET address) |
| `pip-proof` | Prove pip install capability via a kernel (dry-run only, nothing installed) |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | Jupyter server URL (e.g., `http://127.0.0.1:8888`) |
| `--token` | No | Jupyter authentication token |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--path` | For `read-notebook` | Notebook file path |
| `--mine-secrets` | For `notebooks` | Fetch every listed notebook and emit findings for embedded secrets (extra API calls) |
| `--kernel` | For `exec`, `reverse-shell-proof`, `pip-proof` | Kernel ID to execute in |
| `--code` | For `exec` | Code string to execute |

## Examples

```bash
# Enumerate server
./aipostex jupyter --target http://127.0.0.1:8888 --token demo enum

# List active kernels
./aipostex jupyter --target http://127.0.0.1:8888 --token demo kernels

# List notebooks
./aipostex jupyter --target http://127.0.0.1:8888 --token demo notebooks

# List notebooks and mine cells for API keys / connection strings
./aipostex jupyter --target http://127.0.0.1:8888 --token demo notebooks --mine-secrets

# Read a specific notebook
./aipostex jupyter --target http://127.0.0.1:8888 --token demo \
  read-notebook --path notebooks/analysis.ipynb

# Execute code in a kernel (gated)
./aipostex jupyter --target http://127.0.0.1:8888 --token demo \
  exec --kernel kernel-1 --code "print('hi')" --force-exploit

# Start a new kernel (gated)
./aipostex jupyter --target http://127.0.0.1:8888 --token demo \
  start-kernel --force-exploit

# Prove reverse shell capability (gated, safe — uses TEST-NET)
./aipostex jupyter --target http://127.0.0.1:8888 --token demo \
  reverse-shell-proof --kernel kernel-1 --force-exploit

# Prove pip install capability (gated, dry-run only)
./aipostex jupyter --target http://127.0.0.1:8888 --token demo \
  pip-proof --kernel kernel-1 --force-exploit
```

## Execution Details

The `exec` command connects to the kernel's WebSocket shell channel and sends an `execute_request` message. This uses the `gorilla/websocket` library and supports proxy routing via `--proxy` (including SOCKS5).

## What each `landed` level means here

`landed` records what actually landed on the target for each finding. The Jupyter module reaches these levels:

| `landed` | What produces it in jupyter |
|---|---|
| `reachable` | `enum` (server metadata), `kernels` (kernel listing), and `notebooks` (notebook file listing) — the server responded and inventory was listed, but nothing was read or executed. |
| `read-confirmed` | `read-notebook` and `notebooks --mine-secrets`, which read notebook contents (and mined credentials) off the server. |
| `execution-confirmed` | the gated `exec` (code ran in a kernel and returned output), `start-kernel` (a new kernel was created), `reverse-shell-proof` (kernel opened an outbound socket to a TEST-NET address), and `pip-proof` when pip actually installs. If pip is blocked (externally-managed environment), `pip-proof` downgrades to `influenced` — the kernel ran the subprocess but no package installed. |
| `takeover-capable` | the gated `persist` (deploys an IPython startup script that phones home on kernel restart) and `revshell` (deploys a live reverse shell payload) — persistent standing control established through an executing kernel. |

This module reaches the full ladder: kernel `exec` gives confirmed code execution, and `persist`/`revshell` convert that into standing control.

## Operator console

For hands-on work in a live kernel, the [`shell`](../cli/shell.md) verb (`aipostex jupyter … shell --force-exploit`) opens an interactive Python REPL: each line you type executes in the kernel and prints stdout/results, and the session is mined for credentials on exit. It is an execution shell, so it requires `--force-exploit`; you drive every line, nothing chains on its own. Jupyter has no one-shot `request` verb — the kernel channel is stateful, so use the shell.

## Workflow Progression

```
discover network (discovers Jupyter on :8888)
  → jupyter enum (server metadata)
    → jupyter kernels (list kernels)
    → jupyter notebooks (list notebook files; add --mine-secrets to scan all cells)
      → jupyter read-notebook --path <path> (read content)
        → jupyter start-kernel (create a kernel, gated)
        → jupyter exec --kernel <id> --code <code> (execute, gated)
          → jupyter reverse-shell-proof --kernel <id> (outbound socket proof, gated)
          → jupyter pip-proof --kernel <id> (pip install proof, gated)
```
