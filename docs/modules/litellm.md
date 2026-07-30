# LiteLLM

Top-level command: `aipostex litellm` — dedicated LiteLLM proxy assessment using the shared OpenAI-compatible HTTP client in [`pkg/exploit/openaicompat`](https://github.com/professor-moody/aipostex/tree/main/pkg/exploit/openaicompat).

## Subcommands

| Subcommand | Purpose |
|------------|---------|
| `enum` | Readiness, `/health`, `/v1/models`, `/v1/model/info` (including embedded credential patterns in model info). |
| `config-extract` | Flatten `litellm_params` per model from `/v1/model/info`. |
| `budget-probe` | Budget / TPM / RPM style fields from model info. |
| `proxy-chain` | Group models by inferred upstream provider and attach `api_base` when present. |

## Overlap with `openai-compat`

For generic OpenAI-compatible endpoints (including many LiteLLM deployments), `openai-compat litellm-probe`, `auth-sweep`, and `validate-inference` remain the primary workflow from `discover network`. Use `litellm` when you want LiteLLM-specific enumeration and config-focused findings in one module.

## What each `landed` level means here

`landed` records what actually landed on the target for each finding. The LiteLLM module reaches these levels:

| `landed` | What produces it in litellm |
|---|---|
| `reachable` | `proxy-chain --relay-test` when a per-provider relay probe fails to reach an upstream — the provider was inferred but no inference came back. |
| `read-confirmed` | `enum` (proxy version/readiness, model inventory, aggregated providers, and any API keys embedded in `/v1/model/info`), `config-extract` (flattened `litellm_params` and health), `budget-probe` (budget/TPM/RPM fields), and `proxy-chain` (provider grouping and aggregation) — all read config or inventory off the proxy. |
| `execution-confirmed` | `proxy-chain --relay-test` when a relay probe returns coherent inference through an upstream provider, and `key-gen` when the admin `/key/generate` endpoint mints a working backdoor key (admin write executed). |

This module tops out at `execution-confirmed`. It never stamps `takeover-capable`: a minted admin key or a working relay proves the proxy runs inference and accepts admin writes, but the module does not go on to demonstrate full standing control of the upstream providers.

## Operator console

Beyond the enumeration subcommands, `litellm` supports the operator console's two by-hand primitives, both reusing this module's `--target`/`--header`/`--api-key`:

- `request` — a one-shot arbitrary HTTP operation against the proxy (any endpoint the verbs don't cover, e.g. a looted-key `/v1/models` read), authenticated or unauthenticated, with the response mined for loot. A raw request is honest and modest: Info severity, `read-confirmed` on a 2xx / `reachable` otherwise, stage access/recon — it never claims impact or own. See [`request`](../cli/request.md).
- `shell` — an interactive LLM chat REPL through the proxy: you type prompts, the tool relays them to a model, and the reply prints back; on exit the session is mined for disclosed secrets. Chat is ungated (inference is not a mutation). See [`shell`](../cli/shell.md).

The console is manual interaction — the operator drives every request and turn; there is no automated chaining. Secrets are never redacted.

## Flags

Shared with other service modules: `--target`, `--header`, `--api-key` (sets `Authorization: Bearer` when no auth header is provided).
