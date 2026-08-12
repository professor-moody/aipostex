# OpenAI-Compatible

Enumerate and validate generic OpenAI-compatible inference endpoints.

## Overview

The `openai-compat` module targets any API that implements the OpenAI `/v1/models` and `/v1/chat/completions` interface. This covers vLLM, LiteLLM, LocalAI, LM Studio, and other compatible implementations. It provides authentication analysis, model enumeration, inference validation, operator-supplied generation, prompt extraction, tool enumeration, prompt injection testing, throughput testing, and proxy validation.

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `auth-sweep` | Classify weak authentication acceptance patterns |
| `enum` | List available models and metadata |
| `validate-inference` | Verify coherent, input-dependent inference from a model (a distinct second prompt must yield a distinct completion) |
| `prompt-extract` | Attempt to extract hidden system instructions |
| `tool-enum` | Enumerate function/tool calling behavior and test tool injection |
| `prompt-test` | Probe prompt injection, jailbreak, and refusal-bypass resistance |
| `litellm-probe` | Probe LiteLLM health, readiness, and model-info endpoints |
| `fingerprint` | Behaviorally fingerprint the underlying model family (identity, contradiction, knowledge-cutoff) |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `generate` | Send an operator-supplied prompt and capture the model response |
| `throughput` | Measure inference throughput with concurrent requests |
| `proxy-test` | Prove the endpoint can proxy inference requests |

## Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | API base URL (e.g., `http://127.0.0.1:8000`) |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--api-key` | No | API key for authentication |
| `--model` | For most commands | Model name to target |
| `--prompt` | For `generate` | Prompt text for inference |
| `--max-tokens` | For `generate` | Maximum tokens to request |
| `--requests` | Required for `throughput` | Number of requests to send (must be > 0) |
| `--concurrency` | Required for `throughput` | Parallel request count (must be > 0) |

## Auth Sweep

The `auth-sweep` command tests multiple weak authentication patterns:

- No authentication (no header)
- Empty Bearer token
- Placeholder keys (`sk-test`, `sk-dummy`, etc.)
- Development tokens

Each pattern is classified and reported as a finding.

When no `--model` is supplied, `auth-sweep` and `validate-inference` try the highest-value listed model first and then fall back through the remaining model list until one succeeds or all fail. Backend failures are preserved in `model_attempts` metadata with classes such as `backend-dependency-missing`, `backend-config-error`, and `model-route-error`, so a broken provider route does not hide a working local model behind the same proxy.

## Model Value Scoring

The module scores discovered models by value to the attacker:

- Model name analysis for high-value indicators (GPT-4, Claude, large parameter counts)
- Inference coherence scoring to confirm the model produces useful output
- Rate limit signal detection

## LiteLLM Probe

The `litellm-probe` subcommand targets LiteLLM-specific endpoints that are not part of the standard OpenAI API surface. Use it when the target is a LiteLLM proxy (typically on `:4000`). It probes three endpoints:

| Endpoint | What It Exposes | Severity |
|---|---|---|
| `/health/readiness` | LiteLLM version, DB connection status, cache status | Medium |
| `/health` | Backend topology — healthy/unhealthy endpoint counts and `api_base` URLs | High |
| `/v1/model/info` | Full model configurations; escalates to Critical if embedded API keys or credentials are found in `litellm_params` | High / Critical |

If none of the endpoints respond, the command emits an Info-level finding noting the probe returned no results.

## Fingerprint

The `fingerprint` subcommand infers the underlying model family behind the endpoint **without trusting any self-reported name** — deployments routinely mask a model's identity with a system prompt ("You are the NovaTech Assistant"), so a single "what model are you?" is unreliable. It layers three independent read-only signals whose agreement raises confidence and whose disagreement is reported honestly:

- **identity probe** — ask directly and scan the reply for vendor/family signatures.
- **contradiction de-masking** — assert a *false* vendor and watch which vendor the model corrects to; self-correction training tends to leak the true vendor even under an identity-masking system prompt.
- **knowledge-cutoff bracket** — estimate the training cutoff from dated-event recall, reported as a coarse bracket.

Attribution is emitted with a confidence level (`high` / `medium` / `low` / `unknown`); severity reflects attribution confidence, not risk. The optional `--context-window` flag adds a heavier multi-turn needle-in-haystack probe that estimates the usable context window (it sends filler and is off by default). Fingerprinting is passive recon — it always stays **Info**, `recon` / `reachable`.

The same transport-agnostic classifier backs the [agent `fingerprint`](agent.md) verb against bespoke chat apps.

## What each `landed` level means here

`landed` records what actually landed on the target for each finding. The openai-compat module reaches these levels:

| `landed` | What produces it in openai-compat |
|---|---|
| `reachable` | `enum` (model inventory), `auth-sweep` (weak-auth acceptance classes, including the inference-capable class), `validate-inference` when the endpoint responds but not coherently, `prompt-test` (jailbreak/refusal probes), `litellm-probe` (LiteLLM endpoint/topology/secret disclosure), `fingerprint` (behavioral model attribution — passive recon), and `tool-enum` results that only detect support — the API responded but the module does not stamp a stronger claim on these paths. |
| `read-confirmed` | `prompt-extract` when a probe returns content matching a hidden-instruction marker (a system prompt was read back), and `tool-enum` when tool calling is confirmed supported. |
| `influenced` | `validate-inference` when the model responds coherently but a distinct second prompt does not yield a distinguishable completion — inference ran but could not be told apart from a canned fixture. |
| `execution-confirmed` | `validate-inference` when the coherent response is confirmed **input-dependent** (a distinct prompt produces a distinct completion — the same reality probe the serving modules use); the gated `generate`, `proxy-test`, and `throughput` subcommands, where inference actually ran and returned output; plus `tool-enum` when an injected or forced tool call is proven to execute. |

This module tops out at `execution-confirmed` — inference ran — and does not reach `takeover-capable`.

## Operator console

Beyond the fixed subcommands, `openai-compat` supports the operator console's two by-hand primitives, both reusing this module's `--target`/`--header`/`--api-key`:

- `request` — a one-shot arbitrary HTTP operation against the endpoint (any path the verbs don't cover), authenticated or unauthenticated, with the response mined for loot. A raw request is honest and modest: Info severity, `read-confirmed` on a 2xx / `reachable` otherwise, stage access/recon — it never claims impact or own. See [`request`](../cli/request.md).
- `shell` — an interactive LLM chat REPL: you type prompts, the tool sends them to the model, and the reply prints back; on exit the session is mined for disclosed secrets. Chat is ungated (inference is not a mutation). See [`shell`](../cli/shell.md).

The console is manual interaction — the operator drives every request and turn; there is no automated chaining. Secrets are never redacted.

## Examples

```bash
# Test authentication patterns
./aipostex openai-compat --target http://127.0.0.1:8000 auth-sweep

# Enumerate models
./aipostex openai-compat --target http://127.0.0.1:8000 enum

# Validate inference on a model
./aipostex openai-compat --target http://127.0.0.1:8000 \
  validate-inference --model llama3

# Validate inference using model fallback
./aipostex openai-compat --target http://127.0.0.1:4000 validate-inference

# Send an operator prompt (gated)
./aipostex openai-compat --target http://127.0.0.1:4000 \
  generate --model local-smollm \
  --prompt "Explain what access this proxy gives me in one sentence." \
  --force-exploit

# Attempt prompt extraction
./aipostex openai-compat --target http://127.0.0.1:8000 \
  prompt-extract --model llama3

# Enumerate tool support and injection behavior
./aipostex openai-compat --target http://127.0.0.1:8000 \
  tool-enum --model llama3

# Probe prompt injection resistance
./aipostex openai-compat --target http://127.0.0.1:8000 \
  prompt-test --model llama3

# Throughput test (gated)
./aipostex openai-compat --target http://127.0.0.1:8000 throughput \
  --model llama3 --requests 5 --concurrency 2 --force-exploit

# Proxy validation (gated)
./aipostex openai-compat --target http://127.0.0.1:8000 proxy-test \
  --model llama3 --force-exploit

# Probe LiteLLM-specific endpoints
./aipostex openai-compat --target http://127.0.0.1:4000 litellm-probe

# Behaviorally fingerprint the underlying model family
./aipostex openai-compat --target http://127.0.0.1:8000 fingerprint --model llama3
```

## Workflow Progression

```
discover network (discovers OpenAI-compatible on :8000/:4000/:1234)
  → openai-compat auth-sweep (classify auth posture)
  → openai-compat litellm-probe (LiteLLM targets on :4000)
    → openai-compat enum (list models, value scoring)
      → openai-compat fingerprint --model <name> (identify the model family)
      → openai-compat validate-inference --model <name>
        → openai-compat generate --model <name> --prompt "..." (gated proof)
        → openai-compat prompt-extract --model <name>
          → openai-compat tool-enum --model <name>
          → openai-compat prompt-test --model <name>
          → openai-compat throughput (measure abuse potential, gated)
          → openai-compat proxy-test (validate proxying, gated)
```
