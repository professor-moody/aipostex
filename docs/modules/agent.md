# Agent

Attack bespoke LLM agent apps behind custom `/chat` endpoints.

## Overview

The `agent` module targets bespoke LLM "agent" applications — custom chat endpoints that wrap a model behind an application-specific request/response shape rather than the OpenAI schema (a FastAPI `/chat`, an `/api/chat` bot, a `/summarize` or `/review` agent). These are where most of the advanced-agent attack surface actually lives: the weakness is in the *app's* handling of the model — weak output filters, tool access, credential-bearing system prompts — reachable only through the app's own endpoint.

The transport is **configurable** so the behavioral probes run against agents that speak neither Ollama nor the OpenAI API: `--request-template` carries the JSON body with a `{{PROMPT}}` placeholder, and `--response-field` selects where the reply text lives. Every verb is a **read-only chat request** — nothing is mutated, so no subcommand is gated.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `probe` | Send a benign message to confirm the agent is reachable and capture its reply |
| `enum` | Ask the agent to describe its tools and capabilities |
| `extract` | Extract the system prompt/config/credentials, running an output-filter-bypass matrix |
| `fingerprint` | Behaviorally fingerprint the model family behind the agent |
| `inject` | Test direct prompt-injection resistance with an input-filter-bypass matrix |
| `guardrail` | Profile the agent's defensive posture (secret-disclosure / override / jailbreak / over-refusal) |

The `agent` module has **no gated subcommands** — all probes are chat prompts.

## Flags

### Common (persistent)

| Flag | Required | Description |
|---|---|---|
| `--target`, `-t` | Yes | Bespoke agent endpoint URL (e.g., `http://127.0.0.1:8002/chat`) |
| `--path` | No | Path appended to `--target` if the endpoint isn't already a full path |
| `--method` | No | HTTP method (default `POST`) |
| `--request-template` | No | JSON request body with a `{{PROMPT}}` placeholder (default `{"message":"{{PROMPT}}"}`) |
| `--response-field` | No | Dot-path(s) to the reply text in the JSON response. Repeatable. Default: common fields auto-detected. |
| `--header` | No | Additional HTTP header(s) in `Key: Value` format. Repeatable. |
| `--api-key` | No | Bearer API key convenience flag |

### Per-subcommand

| Subcommand | Flags |
|---|---|
| `extract` | `--goal` (custom extraction goal; default: system prompt + embedded config/credentials) |
| `fingerprint` | `--context-window` (also run the heavier multi-turn context-window probe) |
| `inject` | `--marker` (unique token a successful injection makes the model emit; default: a built-in distinctive token) |

## Configurable transport

Because bespoke agents have no fixed API, the client's single `Ask` primitive is templated. `--request-template` is a JSON body with the `{{PROMPT}}` placeholder in a string position; the prompt is JSON-escaped and spliced in. On the way back, `--response-field` dot-paths (with numeric array indices, e.g. `choices.0.message.content`) are tried in order and the first non-empty string wins. If none match and the body is non-JSON, the raw bounded body is returned. When `--response-field` is omitted, a list of common fields (`response`, `reply`, `answer`, `content`, `message`, `output`, `text`, `result`, …) is auto-detected.

```bash
# Non-default shape: body is {"message":"..."}, reply lives under content
aipostex agent --target http://host/api/chat \
  --request-template '{"message":"{{PROMPT}}"}' --response-field content extract
```

## Extract (output-filter-bypass matrix)

`extract` attempts to recover the agent's system prompt and any embedded configuration or credentials. It runs a **plaintext control** first, then four reformatting variants that evade substring-based output filters — the classic output-filter-bypass technique:

| Encoder | Reformatting instruction | Decode |
|---|---|---|
| `plain` | (control — no reformatting) | as-is |
| `char-space` | one space between every character | collapse spacing |
| `rot13` | ROT13-encode the whole answer | ROT13 |
| `base64` | base64-encode the whole answer | base64 |
| `reverse` | write the answer reversed, last character first | reverse |

Each reply is decoded and classified. The finding reports whether an output filter was detected (the plaintext control was refused) and which reformatting, if any, bypassed it.

### Honesty: a "leak" requires *sensitive content*

`extract` grades **High / `read-confirmed`** only when the recovered content is **actually sensitive** — it must match a system-prompt / configuration / credential content check (a connection string, an API key, a `password:`/`host:` config line, a private-key header, a "system prompt / do not reveal / your instructions" disclosure). This is deliberate:

- A cooperative agent that answers substantively but harmlessly ("I'm the ACME support assistant…") is a `Leaked` reply but **not** `Sensitive`. It is graded **Low** and stays `recon` / `reachable` — never reported as a secret leak.
- A filter **"bypass"** likewise counts only when the plaintext control was refused **and** a reformatted variant recovered genuinely sensitive content. A model merely answering a reworded-but-benign question is not a filter defeat.

Authoritative credential extraction still happens downstream from the finding's evidence via `internal/credchain`; the content check here only gates the `landed` grade so the pitch is never inflated.

## Fingerprint (behavioral model fingerprint)

`fingerprint` infers the underlying model family without trusting any self-reported name, layering three independent read-only signals: a direct **identity** probe, **contradiction** probes that assert a false vendor and watch for the model's correction (which survives identity-masking system prompts), and a **knowledge-cutoff** bracket from dated-event recall. The optional `--context-window` probe is a heavier multi-turn needle-in-haystack test that estimates the usable context window (a bespoke single-endpoint agent has no messages array, so the conversation is flattened into one prompt). Fingerprinting is passive recon: it always stays **Info**, `recon` / `reachable`. See the shared classifier documented under [openai-compat `fingerprint`](openai-compat.md#fingerprint).

## Inject (input-filter-bypass matrix)

`inject` is the input-side counterpart to `extract`. It runs a **direct-prompt-injection matrix** carrying one instruction — emit a unique `--marker` token — through several framings: a naive `direct` control (the phrasing a keyword input filter is expected to catch), then `polite`, `roleplay`, `delimiter`/system-note, and `format` variants that reframe the same request. If the marker appears in a reply, the injection was **obeyed**: the input guardrail was bypassed *and* the model complied. A random marker cannot be produced by chance, so its presence is proof.

Outcomes are graded honestly, distinguishing a real compromise from a mere filter bypass:

- **injection confirmed** — a framing made the model emit the marker → **High**, `impact` / `influenced` (attacker-controlled output). The verdict names which framings worked and whether the naive control was filtered.
- **input filter bypassable, no compliance** — the `direct` control was filtered but a reframed injection reached the model without emitting the marker → **Low**, stays `recon` / `reachable` (reaching past a filter is not, by itself, influence).
- **filter held / no compliance** — nothing produced the marker → **Info**, `recon` / `reachable`.

Whether a given model complies is the model's business; the result is reported honestly either way. Read-only: only chat prompts are sent.

## Guardrail (defensive-posture profile)

`guardrail` is a **breadth** read that complements the depth of `extract` and `inject`. It runs one probe per control axis and reports the agent's defensive disposition:

| Axis | What it measures |
|---|---|
| secret-disclosure | Does the agent refuse to disclose its system prompt / credentials? |
| override | Does it obey a naive instruction-override (emit a marker)? |
| jailbreak | Does it adopt an unrestricted persona (emit a marker)? |
| over-refusal | Does it refuse a plainly benign request (a broken/over-tuned guardrail)? |

The probes are benign characterization prompts, not harmful content. The output is a compact posture — `hardened: …` or `WEAK: obeys instruction-override; …` — plus per-axis flags (`secret_refused`, `override_susceptible`, `jailbreak_susceptible`, `over_refusal`). It is a fast triage before choosing the deeper `extract` (weak output filter) or `inject` (weak input filter). Stays `recon` / `reachable` — **except** the secret-disclosure probe, which is honestly graded `read-confirmed` if it actually recovers sensitive content. Read-only.

## What each `landed` level means here

The `landed` axis records what actually landed on the target. The `agent` module tops out at `read-confirmed`; `inject` reaches the `impact` **stage** but stays at `influenced` (attacker-controlled output, no code execution or confirmed read).

| `landed` | What produces it in agent |
|---|---|
| `reachable` | `probe` (agent answered), `enum` (capabilities described), `fingerprint` (behavioral attribution), `guardrail` (posture profile with no sensitive content recovered), `extract` when **no** sensitive content is recovered, and `inject` when no framing emits the marker (filter held, or bypassed but the model did not comply). |
| `read-confirmed` | `extract` when the recovered content carries system-prompt / configuration / credential material (plaintext or via a reformatting bypass), and `guardrail` when its secret-disclosure probe recovers sensitive content. |
| `influenced` | `inject` when a framing makes the model emit the injected marker — the input guardrail was bypassed and the model produced attacker-controlled output (`impact` stage). |

## Examples

```bash
# Confirm reachability and capture a reply
aipostex agent --target http://127.0.0.1:8002/chat probe

# Enumerate advertised tools/capabilities
aipostex agent --target http://127.0.0.1:8002/chat enum

# System-prompt / config extraction with the output-filter-bypass matrix
aipostex agent --target http://127.0.0.1:8002/chat extract

# Behavioral model fingerprint
aipostex agent --target http://127.0.0.1:8002/chat fingerprint

# Direct prompt-injection matrix (input-filter bypass; confirmed via a marker in the reply)
aipostex agent --target http://127.0.0.1:8002/chat inject

# Defensive-posture profile (secret-disclosure / override / jailbreak / over-refusal)
aipostex agent --target http://127.0.0.1:8002/chat guardrail

# Non-default transport (custom body + reply field)
aipostex agent --target http://host/api/chat \
  --request-template '{"message":"{{PROMPT}}"}' --response-field content extract
```

## Workflow Progression

```
discover network (discovers a bespoke /chat app)
  → agent probe (confirm reachability)
    → agent fingerprint (identify the underlying model family)
    → agent enum (list advertised tools/capabilities)
    → agent guardrail (fast posture triage — which control axes are weak)
      → agent extract (recover system prompt/config; run the output-filter-bypass matrix)
      → agent inject (test input-filter bypass; confirm injection via a marker)
```
