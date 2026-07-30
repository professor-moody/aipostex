# request

Issue an arbitrary HTTP request to a service **through the tool** — the operator
console's one-shot primitive. You drive it; nothing runs on its own.

## Synopsis

```bash
aipostex request METHOD PATH-OR-URL [flags]        # top-level, any HTTP service
aipostex <module> request METHOD PATH [flags]      # per-module: reuses the module's --target/--header/--api-key
```

## Description

`request` lets an operator, after the module verbs have proven a stage, keep
operating a service **by hand**: issue any HTTP operation the service supports and
read the raw response. The tool handles the transport and injects whatever auth you
supply — a `--header`, an `--api-key`, a looted credential you paste in, or
**nothing at all** (many AI services are exposed unauthenticated; operating them
without credentials is the tool's origin story).

It is not a `curl` the tool prints for you — the tool makes the request itself, so
it is session-integrated and **loot-capturing**: the response is recorded as a
finding, and any secrets in the body are extracted into the credential index
(`report view --credentials`) exactly like any other evidence. Nothing is redacted.

In the console view the raw response body is written to **stdout** (so
`aipostex request … | jq` stays clean) while the finding block renders to stderr.
In a structured format (`--format jsonl -o …`) the finding carries the response as
evidence and stdout stays parseable.

The two forms share one implementation. The **per-module** verb (`aipostex mlflow
request …`) reuses that module's `--target`, `--header`, and `--api-key` and tags
the finding with the module's badge, so you don't re-supply them after running the
module's other verbs. The **top-level** `aipostex request` is the uniform primitive
for any HTTP service; its `--api-key` uses the `Authorization: Bearer` convention
(use `--header` for any other scheme).

Modules with a `request` verb: `mlflow`, `ray`, `ollama`, `openai-compat`,
`litellm`, `vectordb`, `huggingface`. (Protocol/stateful services — Jupyter kernels,
MCP, A2A — use [`shell`](shell.md); Kubernetes uses the kubectl kubeconfig handed
off by the [dossier](report-view.md).)

## Flags

| Flag | Description |
|---|---|
| `-t`, `--target` | Service base URL (omit if `PATH-OR-URL` is a full `http(s)://` URL). On a per-module verb this is the module's `--target`. |
| `--header` | Additional HTTP header(s) in `'Key: Value'` format (repeatable). |
| `--api-key` | Bearer API key convenience flag (top-level: `Authorization: Bearer <key>`; use `--header` for other schemes). |
| `--body` | Request body (literal string). |
| `--body-file` | Read the request body from a file, or `-` for stdin. |
| `--content-type` | `Content-Type` for the body (defaults to `application/json` when a body is present). |

Plus the standard output flags (`--format`, `-o`, `-v`) and network flags
(`--timeout`, `--insecure`, `--proxy`).

## What each `landed` level means here

A raw operator request is an **honest, modest** record: the tool cannot verify the
effect of an operator-authored call, so it never claims impact/own from one.

| `landed` | What produces it in `request` |
|---|---|
| `reachable` | A non-2xx response (401/403/404/5xx). Stage `recon` — the endpoint answered but did not serve the request; e.g. an honest 401 telling you auth is needed. |
| `read-confirmed` | A 2xx response. Stage `access` — you reached the service and read a real response. Secrets in that response are extracted into the loot index. |

Severity is always **Info** — a manual request is an operator action, not a
vulnerability claim. The value is the captured response and any looted credentials.
To escalate (e.g. prove code execution), use the module's dedicated exploit verbs or
[`shell`](shell.md).

## Examples

```bash
# Unauthenticated read of an exposed Ray dashboard
aipostex request -t http://10.0.20.20:8265 GET /api/jobs/

# Authenticated, with a looted key (Bearer)
aipostex request -t http://10.0.20.20:4000 GET /v1/models \
    --api-key sk-litellm-...

# POST with a body (Content-Type defaults to application/json)
aipostex request -t http://10.0.20.30:5000 POST /api/2.0/mlflow/runs/search \
    --body '{"experiment_ids":["3"],"max_results":50}'

# Per-module verb: reuses the module's --target/--header, tags the finding [mlflow]
aipostex mlflow -t http://10.0.20.30:5000 \
    --header 'Authorization: Basic cmF5LXBpcGVsaW5lOi4uLg==' \
    request GET '/api/2.0/mlflow/experiments/search?max_results=25'

# Capture the response, then mine it for loot
aipostex mlflow -t http://10.0.20.30:5000 --header 'Authorization: Basic ...' \
    request POST /api/2.0/mlflow/runs/search --body '{"experiment_ids":["3"],"max_results":200}' \
    --format jsonl -o runs.jsonl
aipostex report view runs.jsonl --credentials
```

## See also

- [`shell`](shell.md) — the interactive REPL for stateful/high-value services.
- [`report view`](report-view.md) — mine captured responses for the credential index.
- [Operator progression](../operator-guide/progression.md) — where the console fits the kill-chain.
