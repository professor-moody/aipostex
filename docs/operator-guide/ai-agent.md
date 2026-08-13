---
title: Driving aipostex from an AI Agent
---

# Driving aipostex from an AI Agent

aipostex is increasingly run by an LLM rather than typed by a person — through a coding
agent with shell access, or through [`aipostex serve`](../modules/serve.md), which exposes a
subset of its capabilities as MCP tools.

This page is the doctrine that belongs alongside the tool schemas. A model given only the
schemas will call the right verbs and still produce a bad report, because the hard part of
this tool is not *which command* but *what the result is allowed to claim*.

!!! note "Using Claude Code or another skill-aware client"
    The repository ships a ready-made skill at `.claude/skills/aipostex/`, containing this
    doctrine plus a generated inventory of every verb with its gating. Point your client at
    it rather than reproducing it by hand — a test keeps it in step with the command tree.

## Authorization is a precondition, not a flag

aipostex acts on real systems. An agent driving it should:

- **Confirm the target is in scope** before running anything beyond `--help`. A hostname that
  looks like a lab is not proof that it is one.
- **Treat `--force-exploit` as a statement of intent, not a retry.** 83 verbs refuse without
  it because they mutate a target, write to it, or drive execution. Never add it speculatively,
  and never add it to a command the operator did not ask to be run that way.
- **Prefer the smallest step that answers the question** — `enum` before `extract`, `extract`
  before `poison`.

The `request` verb is *conditionally* gated: safe HTTP methods run read-only, while
`POST`/`PUT`/`PATCH`/`DELETE` require `--force-exploit`.

## The honesty rule

aipostex exists to produce claims that survive scrutiny. **An honest `reachable`, or an
honest 502, is worth more than a fabricated success** — one over-claim makes an operator
distrust the whole report.

For an agent relaying results, that means four concrete rules:

1. **Never upgrade a grade.** `reachable` means the port answered. It does not mean "accessed",
   and it certainly does not mean "compromised".
2. **Never infer impact the tool did not prove.** "Unauthenticated" is not "data exfiltrated"
   unless a verb read the data and graded it so.
3. **Report honest negatives as results.** "Authentication is enforced", "the server does not
   implement this method", "the model refused" — these are findings about the target.
4. **Never mask secrets.** aipostex deliberately keeps credentials in evidence, unredacted,
   because the operator needs the value and its context.

## Read the grade, not the vibe

Every finding carries a `stage` and a `landed` grade. They are the vocabulary of the tool.

| `stage` | Meaning |
|---|---|
| `recon` | The target was identified or observed |
| `access` | A surface was reached or data was read |
| `impact` | Something of value was obtained or altered |
| `own` | Durable control was established |

| `landed` | Proven | Do not say |
|---|---|---|
| `reachable` | The service answered; nothing was accessed | "compromised", "accessed" |
| `read-confirmed` | Data was retrieved and is in the evidence | "took over" |
| `influenced` | Behaviour changed, or a state change was accepted | "executed code" |
| `execution-confirmed` | Code or a handler demonstrably ran | "persistent" unless proven |
| `takeover-capable` | Durable control was demonstrated | — |

When asked what a finding proves, quote the grade and the evidence rather than paraphrasing
an impression of them.

## The loop

1. **Inventory** — `discover network` for a range, `discover files` for a host, or
   `assess targets` for discovery plus fingerprinting plus template scanning in one pass.
2. **Enumerate** the specific service with its module (read-only).
3. **Retrieve** what enumeration only listed — this is where credentials appear.
4. **Chain** — findings emit **Next Actions** containing the discovered identifiers; prefer
   those over improvising the next command.
5. **Prove impact** only with authorization, using the gated verbs.
6. **Report** — `report view <findings> --credentials`, `--chains`, `--threat-model`, or
   `--format dossier -o <dir>`.

Save runs that matter with `-o findings.jsonl -f jsonl`; console output truncates long
evidence.

Secrets appearing in finding **evidence** are extracted into the credential index
automatically. Do not build a parallel secret scanner — use
`report view <file> --credentials`.

## Common failure modes

| Mistake | Why it matters |
|---|---|
| Treating `reachable` as access | The most common way to turn a correct tool into a dishonest report |
| Adding `--force-exploit` reflexively | It authorises state change; it is not a retry flag |
| Improvising the next command | The finding usually already emitted one, with real identifiers |
| Leading with a wall of findings | Lead with what was *proven* — the highest grades and the credentials |
| Assuming a flag exists | Flag sets differ per module (`vectordb` selects a backend with `--type`, not `--provider`) |
| Writing to stdout under `serve` | stdout is the MCP protocol channel; diagnostics belong on stderr |

## What `serve` exposes

[`aipostex serve`](../modules/serve.md) exposes 17 tools — the model and agent layer plus the
infrastructure surface (MCP servers, Ollama, MLflow, Ray, Kubernetes) — of which one
(`rag_poison`) is mutating and refuses without `"confirm": true`.

It is still a curated subset. An agent with shell access has the full 201-verb surface;
an agent limited to the MCP server does not, and should say so rather than implying it
assessed something it could not reach.
