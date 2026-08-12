# MCP Server (`serve`)

Run aipostex as an MCP server so an LLM or agent can drive it.

## Overview

`serve` exposes a curated set of aipostex capabilities as [Model Context Protocol](mcp.md) tools over **stdio**, so an LLM or agent framework can drive reconnaissance and bounded exploitation. It speaks newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio transport) with **no SDK dependency** — a small in-tree server handles the core methods (`initialize`, `tools/list`, `tools/call`, `ping`).

Wire it into an MCP client (e.g. Claude) as a stdio server running `aipostex serve`.

```bash
aipostex serve
```

## Safety model

- **Recon / enumeration tools are read-only and exposed directly** — the model can call them freely.
- **Mutating tools are gated at the handler**: `rag_poison` refuses unless it is called with `"confirm": true`, so an autonomous model cannot mutate a target without an explicit signal. It is also marked with the MCP `destructiveHint` annotation in the tool listing.
- **`stdout` is the protocol channel; `stderr` is the audit log.** Every `tools/call` is logged to stderr (prefixed `[aipostex-mcp]`), so all diagnostics stay off the wire.

## Flags

| Flag | Required | Description |
|---|---|---|
| `--timeout` | No | Per-call HTTP timeout for tool handlers (default `90s`) |

## Exposed tools

### Read-only

| Tool | What it does |
|---|---|
| `fingerprint_model` | Behaviorally fingerprint the model family behind an OpenAI-compatible endpoint (identity, contradiction, knowledge-cutoff). Args: `target` (required), `model`. |
| `agent_probe` | Send a benign message to a bespoke `/chat` agent and capture its reply. |
| `agent_enum` | Ask a bespoke agent to list its tools/capabilities. |
| `agent_extract` | Attempt system-prompt/config extraction against a bespoke agent, running the output-filter-bypass matrix. |
| `agent_fingerprint` | Behaviorally fingerprint the model family behind a bespoke agent. |
| `rag_query` | Query a black-box RAG app and return the answer plus source citations (and any leaked secrets). Args: `target`, `query` (required), `query_path`. |
| `rag_map` | Map a black-box RAG knowledge base via a recon-query battery, flagging documents that leak secrets. |

The `agent_*` tools accept the configurable transport: `target` (required), optional `request_template` (JSON body with a `{{PROMPT}}` placeholder) and `response_field` (dot-path to the reply text).

### Gated (mutating)

| Tool | What it does |
|---|---|
| `rag_poison` | Ingest an attacker document into a RAG knowledge base and verify it surfaces on a trigger query. **Mutating** — refuses unless called with `"confirm": true`. Args: `target`, `title`, `content` (required), `trigger_query`, `confirm`. |

## Wiring it into a client

Register `aipostex serve` as a stdio MCP server. For example, in a Claude Desktop config:

```json
{
  "mcpServers": {
    "aipostex": {
      "command": "aipostex",
      "args": ["serve"]
    }
  }
}
```

The client then discovers the tools via `tools/list` and calls them via `tools/call`. Mutating calls must include `"confirm": true` in their arguments or the handler returns a refusal.

## Notes

- The server is transport-only: it holds no aipostex logic and never decides what is dangerous — the caller chose which tools to expose and marked the mutating ones. The gating lives in each handler.
- Because output goes to `stdout` as JSON-RPC, do **not** pipe anything else to stdout when running under a client; read the audit trail from `stderr`.
- Findings are not written to the report store from `serve`; each tool returns its result text directly to the calling model. Use the full CLI verbs (documented under [Agent](agent.md), [RAG](rag.md), and [OpenAI-Compatible](openai-compat.md)) when you want graded findings in a report.
