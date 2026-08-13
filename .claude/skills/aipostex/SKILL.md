---
name: aipostex
description: Drive aipostex, the offensive AI-infrastructure recon and exploitation CLI — its kill-chain grading, gating model, module verbs, and reporting. Use when assessing AI/ML infrastructure (MCP servers, model runtimes, vector databases, ML platforms, agents, RAG apps) or when reading aipostex findings.
---

# aipostex

An offensive security CLI for AI infrastructure. It finds AI/ML services, enumerates what
they expose, and — where explicitly authorized — proves impact: reading data, obtaining
credentials, chaining one weakness into the next.

You may be driving it two ways:

- **The CLI** — 201 verbs across 28 command groups. Full inventory in
  [reference/verbs.md](reference/verbs.md).
- **`aipostex serve`** — an MCP server exposing **every one of those verbs** as an MCP tool
  (see [MCP server mode](#mcp-server-mode) below). Full parity with the CLI.

## Authorization comes first

This tool takes real actions against real systems. Before running anything beyond `--help`:

- **Confirm the target is in scope.** Ask the operator if it is not already established. A
  hostname that looks like a lab is not proof it is one.
- **Gated verbs need explicit intent.** 83 of the 201 verbs refuse to run without
  `--force-exploit` because they mutate a target, write to it, or drive execution. Never add
  `--force-exploit` to "see what happens", and never add it to a command the operator did not
  ask to be gated. If you are unsure whether an action is destructive, run the read-only verb
  first and report what it found.
- **Prefer the smallest step that answers the question.** `enum` before `extract`, `extract`
  before `poison`.

## The honesty rule — this is the point of the tool

aipostex exists to produce claims that survive scrutiny. **An honest "reachable", or an
honest 502, is worth more than a fabricated success**, because a single over-claim makes an
operator distrust the entire report.

Concretely, when you report results:

- **Never upgrade what the tool said.** If a finding is graded `reachable`, it means the port
  answered — not that you got in. Do not translate that into "accessed" or "compromised".
- **Never infer impact the tool did not prove.** "The endpoint is unauthenticated" is not
  "the data was exfiltrated" unless a verb actually read the data and graded it so.
- **Report honest negatives as results, not failures.** "The server does not implement
  resources/subscribe", "auth is enforced", "the model refused" — these are findings about
  the target and should be stated plainly.
- **Never mask or redact secrets in evidence.** aipostex deliberately keeps credentials in
  finding evidence, unredacted, because the operator needs the value and its context. Do not
  invent redaction when relaying output.

## Reading a finding

Every finding carries a `stage` (how far along the kill chain) and a `landed` grade (what was
actually proven). These two fields are the vocabulary of the whole tool — read them before
you characterise anything.

**`stage` — the kill chain**

| Stage | Meaning |
|---|---|
| `recon` | The target was identified or observed |
| `access` | A surface was reached or data was read |
| `impact` | Something of value was obtained or altered |
| `own` | Durable control was established |

**`landed` — what was actually proven**

| Grade | Meaning | Do NOT say |
|---|---|---|
| `reachable` | The service answered. Nothing was accessed. | "compromised", "accessed" |
| `read-confirmed` | Data was actually retrieved and is in the evidence. | "took over" |
| `influenced` | Behaviour changed, or a state change was accepted. | "executed code" |
| `execution-confirmed` | Code or a handler demonstrably ran. | "persistent" unless proven |
| `takeover-capable` | Durable control was demonstrated. | — |

A finding also carries `severity`, a `target`, module `metadata` (module, action, and
verb-specific fields), and `evidence` — the raw material that justifies the claim. **When
asked what a finding proves, quote the grade and the evidence, not your impression of them.**

## The operating loop

1. **Inventory** — `discover network` for a range, `discover files` for a host. Use
   `assess targets` when you want discovery, fingerprinting and template scanning in one pass;
   it finds more than `discover` alone because it enumerates each identified service.
2. **Enumerate the specific service** with its module (`mcp enum`, `mlflow experiments`,
   `k8s rbac-probe`, ...). Read-only. This is where you learn what is actually exposed.
3. **Retrieve** what enumeration only listed — `mcp enum --read`, `vectordb extract`,
   `mlflow runs`, `jupyter notebooks --mine-secrets`. Still read-only, and this is where
   credentials start appearing.
4. **Chain** — feed recovered credentials into the next hop. Findings emit **Next Actions**
   with the concrete follow-on command; prefer those over improvising.
5. **Prove impact** only with authorization — the gated verbs.
6. **Report** — `report view <findings> --credentials` for the loot index, `--chains` for the
   attack board, `--threat-model` for a coverage view, `--format dossier -o <dir>` for a
   handoff folder.

Save findings with `-o findings.jsonl -f jsonl` when a run matters; console output truncates
long evidence.

## Credentials chain automatically

Any secret that appears in a finding's **evidence** is extracted into the credential index by
`internal/credchain` — you do not need to scrape output yourself, and you should not build a
parallel secret scanner. `report view <file> --credentials` shows the typed list, marking
which are actionable pivots. That index is how a leaked MLflow parameter becomes the next
module's `--api-key`.

## Module map

Pick the module that matches the service. Full verb tables, with gating marked, are in
[reference/verbs.md](reference/verbs.md).

| Layer | Modules |
|---|---|
| Discovery | `discover`, `scan`, `assess`, `templates` |
| Model runtimes & gateways | `ollama`, `openai-compat`, `litellm`, `huggingface` |
| Serving stacks | `bentoml`, `triton`, `torchserve`, `tfserving` |
| ML platform | `mlflow`, `ray`, `kubeflow`, `wandb`, `k8s` |
| Data | `vectordb` |
| Agent & protocol layer | `mcp`, `a2a`, `agent`, `rag`, `gradio`, `jupyter` |
| Operator | `report`, `sessions`, `engagement`, `listen`, `request`, `serve` |

Two modules deserve a note because they behave differently:

- **`agent` and `rag`** target bespoke applications with no fixed API, so they take a
  *configurable transport*: `--target`, plus optionally a request template containing a
  `{{PROMPT}}` placeholder and a dot-path to the reply field. Run `agent probe` first — if the
  transport is wrong, every later verb reports a false negative.
- **`mcp`** covers both directions: attacking an MCP server (enumeration, poisoning,
  sandbox escape, SSTI) *and* detecting a malicious server attacking its client
  (`sampling`, `elicitation`, `roots` — server→client abuse that a tool listing cannot show).

## MCP server mode

`aipostex serve` runs aipostex as an MCP server over stdio, so an MCP client can call it.
Wire it in as a stdio server running `aipostex serve`.

It exposes **all 201 verbs** as tools, named `<module>_<verb>` — `mcp_enum`,
`k8s_secret_read`, `vectordb_search_sensitive`, and so on. Each carries that verb's own flags
as its schema and returns the CLI's own output, grades included.

Gating carries through: the 90 gated verbs are marked mutating and **refuse unless called
with `"confirm": true`**. You cannot set `--force-exploit` as an argument — the server adds it
once you confirm, so authorisation is an explicit act rather than a guessed flag. Output flags
(`--output`, `--format`, `--quiet`) are withheld because the tool result is the channel.

Two things to know when driving it: `stdout` is the protocol channel and `stderr` is the
audit log (every call is logged there), and findings are **not** written to the report store —
each tool returns its result text directly. Use the CLI verbs when you want graded findings
in a report.

## Common mistakes

- **Treating `reachable` as access.** The most common way to turn a correct tool into a
  dishonest report.
- **Adding `--force-exploit` reflexively.** It is a statement of intent, not a retry flag.
- **Improvising the next command** when the finding already emitted a Next Action containing
  the discovered identifiers.
- **Reporting a wall of findings.** Lead with what was *proven* (the highest `landed` grades
  and the credentials), then the surface.
- **Assuming a flag exists.** Check `--help`; the flag sets differ per module (for example
  `vectordb` selects its backend with `--type`, not `--provider`).
- **Piping anything to stdout under `serve`.** It corrupts the protocol stream.

## Where to look next

- Full verb inventory: [reference/verbs.md](reference/verbs.md)
- Per-module documentation: `docs/modules/<module>.md` in the repository
- Finding schema: `docs/schema/finding-schema.json`
- Grading vocabulary in depth: each module doc has a "What each `landed` level means here"
  section
