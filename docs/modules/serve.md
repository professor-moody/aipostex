# MCP Server (`serve`)

Run aipostex as an MCP server so an LLM or agent can drive it.

## Overview

`serve` exposes 17 curated aipostex capabilities as [Model Context Protocol](mcp.md) tools over **stdio**, so an LLM or agent framework can drive reconnaissance and bounded exploitation. It speaks newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio transport) with **no SDK dependency** — a small in-tree server handles the core methods (`initialize`, `tools/list`, `tools/call`, `ping`).

Wire it into an MCP client (e.g. Claude) as a stdio server running `aipostex serve`.

!!! tip "Give the model doctrine, not just schemas"
    Tool schemas tell a model *what it can call*; they do not tell it what a result is
    allowed to claim. See [Driving aipostex from an AI Agent](../operator-guide/ai-agent.md),
    or point a skill-aware client at the shipped skill in `.claude/skills/aipostex/`.

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

**Every CLI verb is a tool.** The surface is generated from the command tree, so all 201
verbs across 28 modules are callable, named `<module>_<verb>` — `mcp_enum`, `k8s_secret_read`,
`vectordb_search_sensitive`, `openai_compat_prompt_extract`, and so on. A verb added to the
CLI becomes a tool the next time the server starts; there is no list to maintain and nothing
to fall behind.

Each tool carries that verb's own flags as its input schema, its own documentation as its
description, and its own gating. Positional arguments, where a verb takes them, arrive as a
space-separated `args` string.

The tool returns exactly what the CLI printed — findings with their `stage`/`landed` grades,
the summary, and any Next Actions — so a model reads the same output an operator would.

### Legacy tool names

Generating the surface renamed four tools that existed when it was hand-written. Those names
still resolve, as **deprecated aliases** that redirect to the generated tool — a model that
learned an old name gets a redirect rather than "unknown tool" — but new callers should use
the generated name:

| Deprecated | Use |
|---|---|
| `fingerprint_model` | `openai_compat_fingerprint` |
| `mcp_read` | `mcp_enum` with `read: true` |
| `mcp_auth_posture` | `mcp_auth` |
| `k8s_posture` | `k8s_rbac_probe` (or `k8s_access_review` / `k8s_enum`) |

### Gating

Verbs that require `--force-exploit` are marked mutating (MCP `destructiveHint`) and **refuse
unless called with `"confirm": true`**. 90 of the 201 tools are gated this way.

`--force-exploit` is **not** a model-settable argument. The server appends it itself once
`confirm` is present, so a model cannot authorise a mutating action by guessing a flag name.
Output-plumbing flags (`--output`, `--format`, `--quiet`, `--width`, `--verbose`) are likewise
withheld: the MCP result is the delivery channel.

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
