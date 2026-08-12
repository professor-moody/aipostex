# MCP

Analyze and exploit Model Context Protocol (MCP) servers.

## Overview

The `mcp` module covers both local MCP configuration analysis and remote MCP server exploitation. It supports local config parsing (Claude Desktop, VS Code, Cursor), remote enumeration over HTTP/SSE, and guarded poison probes across multiple attack modes.

The HTTP transport handles both standard JSON responses and streamable-HTTP servers that return Server-Sent Events (SSE) on POST. Requests include `Accept: application/json, text/event-stream`, and `text/event-stream` responses are automatically parsed to extract the embedded JSON-RPC payload from `data:` lines. Mixed-case URL suffixes (e.g., `/SSE`, `/Sse`) are correctly normalized during transport detection.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `analyze` | Analyze a local MCP configuration file |
| `enum` | Enumerate a remote MCP HTTP/SSE endpoint |
| `env-extract` | Extract environment variables from MCP server processes via tool reflection and error leakage |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `config-hijack` | Write and verify a hijacked local config entry with backup/rollback |
| `poison` | Send exploit probes to an MCP server (9 modes) |
| `chain` | Automated multi-step credential exfiltration kill chain |
| `sandbox-escape` | Probe an MCP filesystem read tool for a path-based sandbox escape (CVE-2025-53109 / -53110 class) |
| `ssti` | Probe an MCP rendering/formatting tool for server-side template injection (Jinja2) |

## Flags

### Common

| Flag | Required | Description |
|---|---|---|
| `--target` | For `enum`, `poison` | MCP server URL (e.g., `http://127.0.0.1:3000`) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--config` | For `analyze`, `config-hijack` | Path to MCP config file |

### Config-Hijack Flags

| Flag | Required | Description |
|---|---|---|
| `--server` | No | Server name to add or replace. Defaults to `aipostex-hijack`. |
| `--url` | Either `--url` or `--command` | Remote MCP URL to install in the config. |
| `--command` | Either `--url` or `--command` | Local stdio command to launch from the config. |
| `--arg` | No | Argument for `--command`. Repeatable. |
| `--env` | No | Environment assignment for the entry (`KEY=VALUE`). Repeatable. |
| `--entry-transport` | No | Transport value to write. Defaults to `http`/`sse` from `--url` or `stdio` from `--command`. |

### Poison Flags

| Flag | Required | Description |
|---|---|---|
| `--mode` | Yes | Attack mode: `generic`, `ssrf-cloud`, `cmd-inject`, `path-traversal`, `type-field`, `default-value`, `example-inject`, `error-message`, `enum-poison` |
| `--tool` | For `generic` | Tool name to target |
| `--payload` | For `generic` | Payload string |
| `--attempts` | No | Number of payload attempts |
| `--target-alias` | For `ssrf-cloud` | Cloud provider: `aws-imds`, `gcp-metadata`, `azure-imds`. Mutually exclusive with `--url`. |
| `--url` | For `ssrf-cloud` | Custom SSRF target URL instead of a built-in cloud alias |
| `--command` | For `cmd-inject` | Command to inject |
| `--path` | For `path-traversal` | Path traversal string |

## Poison Modes

### generic

Sends arbitrary payload to a specified tool. Tests prompt injection and tool manipulation.

### ssrf-cloud

Probes fetch-like tools for SSRF access to cloud metadata endpoints (AWS IMDS, GCP metadata, Azure IMDS).

### cmd-inject

Targets shell/process-like tools with command injection payloads.

### path-traversal

Targets file-read/write tools with path traversal sequences.

### type-field (Full-Schema Poisoning)

Injects instruction text into JSON Schema `type` field definitions. Based on CyberArk's Full-Schema Poisoning research.

### default-value (Full-Schema Poisoning)

Sets parameter default values to trigger unintended behavior (e.g., default path pointing to sensitive file).

### example-inject (Full-Schema Poisoning)

Places prompt injection payloads in the `examples` array of parameter definitions.

### error-message (Full-Schema Poisoning)

Crafts tool responses with error messages containing instructions for the LLM.

### enum-poison (Full-Schema Poisoning)

Adds values to enum arrays that contain embedded instructions.

## Environment Extraction

The `env-extract` subcommand (read-only) attempts to extract environment variables from MCP server processes through:

1. **Tool reflection** -- asking exec-capable tools to print their environment
2. **Error message leakage** -- sending malformed requests to trigger verbose errors containing env vars
3. **Known env var patterns** -- scanning for `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `HF_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_OPENAI_KEY`, `GOOGLE_API_KEY`, `LANGCHAIN_API_KEY`, `WANDB_API_KEY`

## Chain (Kill Chain Automation)

The `chain` subcommand (gated) automates the multi-step credential exfiltration kill chain:

1. **Enumerate** -- discover available tools and schemas
2. **Score tools** -- identify high-value tools (file, exec, fetch, cloud)
3. **Environment probe** -- run env-extract against discovered tools
4. **Cloud metadata probe** -- attempt SSRF to AWS/GCP/Azure metadata endpoints via fetch-capable tools
5. **Report** -- generate chain summary with full attack path documentation

Flags: `--cloud` (aws/gcp/azure/all), `--skip-metadata`

## Sandbox Escape

The `sandbox-escape` subcommand (gated) tests whether an MCP filesystem **read** tool enforces its advertised directory boundary — the class of flaw assigned CVE-2025-53109 / CVE-2025-53110. It sends a prefix-check-bypass path (the allowed prefix followed by traversal), a percent-encoded traversal variant, and a bare absolute path, and checks whether the tool returns content from **outside** the sandbox. A read-like tool is auto-detected when `--tool` is not given (pure listing tools are excluded).

The escape is only claimed when the response carries a **runtime-only marker** — a Unix passwd signature such as `root:x:0:0` or `:/bin/bash` — that cannot be hallucinated. Enforcing the sandbox → **Info**, `reachable`; a confirmed read outside the directory → **High**, `impact` / `read-confirmed`.

Flags: `--tool` (auto-detected if empty), `--path-arg` (name of the tool's path argument, default `path`), `--allowed-prefix` (the tool's advertised allowed directory, default `/data/documents`), `--escape-target` (file outside the sandbox to try to read, default `/etc/passwd`).

## SSTI

The `ssti` subcommand (gated) sends template-injection payloads to an MCP **rendering / formatting** tool and checks the output for evaluation. It prioritizes the Jinja2 `{{ lipsum.__globals__.keys() }}` signal — whose `dict_keys` / `__globals__` / `'os'` / `builtins` output only exists inside the server's Python runtime and so cannot be hallucinated — over bare arithmetic (`{{7*7}}` → `49`). A render-like tool is auto-detected when `--tool` is not given.

Grading is honest about *how strongly* injection was proven: a globals leak confirms an SSTI that reaches the Python runtime (a code-execution surface) → **High**, `impact` / `read-confirmed`; a bare-arithmetic evaluation alone → **Medium**, `impact` / `influenced`; literal, un-evaluated output → **Info**, `reachable`.

Flags: `--tool` (auto-detected if empty), `--arg` (name of the tool argument that gets rendered, default `content`).

## Examples

```bash
# Analyze local config
./aipostex mcp analyze --config ~/.config/Claude/claude_desktop_config.json

# Enumerate remote endpoint
./aipostex mcp --target http://127.0.0.1:3000 enum

# Generic poison probe (gated)
./aipostex mcp --target http://127.0.0.1:3000 poison \
  --mode generic --tool fetch \
  --payload "Ignore previous instructions." \
  --attempts 2 --force-exploit

# SSRF cloud metadata (gated)
./aipostex mcp --target http://127.0.0.1:3000 poison \
  --mode ssrf-cloud --target-alias aws-imds --force-exploit

# Command injection (gated)
./aipostex mcp --target http://127.0.0.1:3000 poison \
  --mode cmd-inject --command id --force-exploit

# Path traversal (gated)
./aipostex mcp --target http://127.0.0.1:3000 poison \
  --mode path-traversal --path ../../etc/passwd --force-exploit

# Full-schema poisoning: type field injection (gated)
./aipostex mcp --target http://127.0.0.1:3000 poison \
  --mode type-field --force-exploit

# Full-schema poisoning: default value injection (gated)
./aipostex mcp --target http://127.0.0.1:3000 poison \
  --mode default-value --payload /etc/passwd --force-exploit

# Environment variable extraction (read-only)
./aipostex mcp --target http://127.0.0.1:3000 env-extract

# Write a hijacked remote MCP config entry (gated)
./aipostex mcp config-hijack \
  --config ~/.config/Claude/claude_desktop_config.json \
  --server aipostex-hijack \
  --url http://127.0.0.1:3000/mcp \
  --force-exploit

# Filesystem sandbox escape (gated)
./aipostex mcp --target http://127.0.0.1:3000 sandbox-escape \
  --allowed-prefix /data/documents --force-exploit

# Server-side template injection (gated)
./aipostex mcp --target http://127.0.0.1:3000 ssti \
  --tool render_report --arg report_data --force-exploit

# Automated credential chain (gated)
./aipostex mcp --target http://127.0.0.1:3000 chain --force-exploit

# Chain targeting only AWS metadata
./aipostex mcp --target http://127.0.0.1:3000 chain \
  --cloud aws --force-exploit
```

## Transport Compatibility

The MCP client supports three transport modes:

| Transport | How It Works |
|---|---|
| HTTP (JSON) | POST JSON-RPC to target URL, receive JSON response |
| HTTP (SSE) | POST JSON-RPC to target URL, receive `text/event-stream` with JSON-RPC in `data:` lines |
| stdio | Spawn local process, exchange NDJSON over stdin/stdout |

When targeting an endpoint that ends in `/sse` (case-insensitive), the client automatically rewrites the POST target to `/message` on the same base URL. This handles the common pattern where SSE MCP servers expose an SSE event stream at `/sse` and accept commands at `/message`.

## Analyze Capabilities

The `analyze` command parses local MCP config files and identifies:

- **Transport choices** -- stdio vs HTTP/SSE per server
- **Command execution** -- local commands configured to run (npx, uvx, python, node)
- **Plaintext credentials** -- API keys and tokens in environment variables (redacted in console)
- **Non-loopback exposure** -- servers binding to non-localhost addresses
- **Inspector/debug exposure** -- MCP Inspector or debug tooling configured
- **Tool shadowing** -- tool name collisions across configured servers
- **Remote URL correlation** -- remote MCP URLs that suggest follow-on `enum` or `poison` commands

## Enum Capabilities

The `enum` command classifies discovered tools into capability buckets:

- `fetch` -- HTTP fetch tools (SSRF potential)
- `file` -- file read/write tools (traversal potential)
- `exec` / `process` -- command execution tools
- `inspector` -- MCP Inspector or debug tooling

Each classification includes a confidence score and suggested exploit modes.

## What each `landed` level means here

The `landed` axis records what actually landed on the MCP server. The `mcp` module tops out at `execution-confirmed`; it does not claim `takeover-capable`.

| `landed` | What produces it in mcp |
|---|---|
| `reachable` | `enum` (endpoint responds; tools/inspector discovered); `poison` in a schema mode (`type-field`, `default-value`, `example-inject`, `error-message`, `enum-poison`), or when the tool returns an error, or `ssrf-cloud` with no provider marker; `sandbox-escape` when the tool enforces its directory boundary; `ssti` when the payloads are returned as literal, un-evaluated text |
| `influenced` | `config-hijack` after a local config entry is written and reparsed; `poison --mode generic` (payload accepted); `poison --mode cmd-inject` (a command-output marker appeared, but a substring match is not nonce-confirmed execution, so it stays "likely"); `poison --mode path-traversal` before a file signature is confirmed; `ssti` when only bare arithmetic evaluated (no runtime globals leak) |
| `read-confirmed` | `env-extract` when a real credential is leaked (env value returned); `poison --mode ssrf-cloud` when a provider marker is returned; `poison --mode path-traversal` when a file-read is confirmed (`file-read-confirmed`); `sandbox-escape` when a runtime passwd marker confirms a read outside the sandbox; `ssti` when the Jinja2 globals leak confirms the injection reaches the Python runtime; `chain` credential-exfiltration steps |
| `execution-confirmed` | `chain` cloud-metadata step — a fetch-capable tool processes an SSRF URL and returns AWS/GCP/Azure metadata provider markers |

## Operator console

To call a server's tools by hand, the [`shell`](../cli/shell.md) verb (`aipostex mcp … shell --force-exploit`) opens an interactive tool-caller: type `<tool> {"arg":"value"}` to invoke a discovered tool, `:tools` to list them, and the session is mined for credentials on exit. It is an execution shell, so it requires `--force-exploit`; you drive every call, nothing chains on its own. MCP has no one-shot `request` verb — the JSON-RPC session is stateful, so use the shell.

## Vulnerability Templates

aipostex includes 20 MCP-specific vulnerability templates that run automatically during `scan targets` and `discover network`. These cover infrastructure exposure, CVEs, and server-specific vulnerabilities from the [vulnerablemcp](https://vulnerablemcp.info/) database.

### Infrastructure Exposure

| Template | What It Detects |
|---|---|
| `mcp-auth-001` / `002` | Unauthenticated SSE and HTTP transports |
| `mcp-auth-003` / `005` | MCP Inspector UI and API exposed without auth |
| `mcp-auth-004` | DNS rebinding via Host header trust |
| `mcp-session-001` | Session IDs leaked in SSE endpoint URL query parameters |

### CVEs and Server-Specific

| Template | CVE | What It Detects |
|---|---|---|
| `cve-2025-65513` | CVE-2025-65513 | Fetch MCP Server SSRF via IP validation bypass |
| `cve-2025-49596` | CVE-2025-49596 | MCP Inspector RCE (versions < 0.14.1) |
| `cve-2025-66414` | CVE-2025-66414/66416 | Official MCP SDK DNS rebinding (TS < 1.24.0, Python < 1.23.0) |
| `cve-2025-53355` | CVE-2025-53355 | Kubernetes MCP server command injection via kubectl tools |
| `cve-2025-53967` | CVE-2025-53967 | Framelink Figma MCP server RCE via curl fallback |
| `cve-2025-59163` | CVE-2025-59163 | Vet MCP server DNS rebinding |
| `tra-2025-36` | TRA-2025-36 | Microsoft Learn MCP server SSRF via docs_fetch tool |
| `mcp-enum-006` | CVE-2025-10193 | Neo4j MCP Cypher server exposure and DNS rebinding |

Run templates against an MCP endpoint:

```bash
./aipostex scan targets http://127.0.0.1:3000 --tags mcp
```

See [Built-in Templates](../vuln-templates/builtin.md) for the full template reference.

## Workflow Progression

```
discover network / discover files (discovers MCP config or endpoint)
  → scan targets --tags mcp (run vulnerability templates)
  → mcp analyze --config <path> (local config analysis)
    → mcp config-hijack --config <path> --url <remote-mcp-url> --force-exploit (verified local config write)
  → mcp enum --target <url> (remote tool enumeration)
    → mcp env-extract (credential probing, read-only)
    → mcp poison --mode <mode> (exploit validation, gated)
    → mcp sandbox-escape (filesystem read-tool path escape, gated)
    → mcp ssti (rendering-tool template injection, gated)
    → mcp chain (automated credential exfiltration, gated)
```
