# Vector Databases

Enumerate, extract, and inject data across vector database instances: ChromaDB, Weaviate, Qdrant, Milvus, and pgvector.

## Overview

The `vectordb` module provides a unified interface across five vector database providers. Read-only commands (enum, extract, search-sensitive) run without restrictions. State-changing injection commands (inject, metadata-inject) require `--force-exploit`.

The ChromaDB client automatically tries multiple API endpoint formats for compatibility across ChromaDB 0.4.x through 0.6.x, including tenant/database-aware paths. The pgvector provider connects via PostgreSQL wire protocol (not HTTP).

All HTTP-based providers validate API-level error responses. Milvus and similar REST APIs may return HTTP 200 with a non-zero `code` field indicating an application-level failure (authentication errors, invalid collections, etc.). These are surfaced as errors rather than silently treated as empty successes.

## Supported Providers

| Provider | `--type` value | Default Port | Protocol |
|---|---|---|---|
| ChromaDB | `chromadb` | 8000 | HTTP REST |
| Weaviate | `weaviate` | 8080 | HTTP REST |
| Qdrant | `qdrant` | 6333 | HTTP REST |
| Milvus | `milvus` | 19530 | HTTP REST (v2.4+) |
| pgvector | `pgvector` | 5432 | PostgreSQL wire protocol |

## Subcommands

### Read-Only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `enum` | List collections/tables with document/row counts |
| `extract` | Extract documents/rows from a specific collection |
| `search-sensitive` | Search collections for sensitive data patterns (emails, SSNs, credit cards, API keys, passwords) |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `inject` | Insert crafted documents into a vector store for RAG poisoning testing |
| `metadata-inject` | Test whether metadata fields accept and return unsanitized prompt injection payloads |

## Flags

### Common Flags

| Flag | Required | Description |
|---|---|---|
| `--target` | Yes | Database URL (e.g., `http://127.0.0.1:8000`) or host:port for pgvector |
| `--type` | Yes | Provider type: `chromadb`, `weaviate`, `qdrant`, `milvus`, or `pgvector` |
| `--header` | No | Custom HTTP headers. Repeatable. |
| `--api-key` | No | API key for authenticated access |
| `--collection` | For `extract`/`inject`/`metadata-inject`, optional for `search-sensitive` | Collection or table name to target. For `search-sensitive`, errors if specified but matches nothing. |
| `--limit` | No | Maximum documents to return |
| `--exclude-collections` | For `search-sensitive` | Comma-separated collection names to skip |

### pgvector-Specific Flags

| Flag | Default | Description |
|---|---|---|
| `--db-user` | `postgres` | PostgreSQL user |
| `--db-password` | (empty) | PostgreSQL password (prefer `AIPOSTEX_VDB_PASSWORD` env var) |
| `--db-name` | `postgres` | PostgreSQL database name |
| `--db-sslmode` | `disable` | PostgreSQL SSL mode |

### Inject Flags

| Flag | Required | Description |
|---|---|---|
| `--payload` | Yes | Text content to embed and inject |
| `--metadata` | No | JSON string of metadata key-value pairs to attach |
| `--count` | No | Number of copies to inject (default: 1) |

### Metadata-Inject Flags

| Flag | Default | Description |
|---|---|---|
| `--key` | `source` | Metadata key to inject into |
| `--payload` | Standard prompt injection test | Custom injection payload |

## Examples

```bash
# Enumerate ChromaDB collections
./aipostex vectordb --target http://127.0.0.1:8000 --type chromadb enum

# Extract documents from a collection
./aipostex vectordb --target http://127.0.0.1:8000 --type chromadb \
  extract --collection my-docs

# Search for sensitive data across all collections
./aipostex vectordb --target http://127.0.0.1:8000 --type chromadb \
  search-sensitive

# Weaviate with API key
./aipostex vectordb --target http://127.0.0.1:8080 --type weaviate \
  enum --api-key demo

# Qdrant enumeration
./aipostex vectordb --target http://127.0.0.1:6333 --type qdrant enum

# Milvus enumeration
./aipostex vectordb --target http://127.0.0.1:19530 --type milvus enum

# Milvus extraction
./aipostex vectordb --target http://127.0.0.1:19530 --type milvus \
  extract --collection embeddings

# pgvector enumeration (PostgreSQL wire protocol)
./aipostex vectordb --target 127.0.0.1:5432 --type pgvector \
  --db-user postgres --db-name mydb enum

# RAG poisoning injection (gated)
./aipostex vectordb --target http://127.0.0.1:8000 --type chromadb \
  inject --collection docs --payload "Ignore previous instructions." \
  --count 3 --force-exploit

# Metadata injection test (gated)
./aipostex vectordb --target http://127.0.0.1:6333 --type qdrant \
  metadata-inject --collection docs --key source \
  --payload "Ignore all prior context." --force-exploit
```

## Sensitive Data Patterns

The `search-sensitive` command scans document content using 27 regex patterns organized by severity. These patterns are shared across all providers via `DefaultSensitivePatterns()`.

**Critical:** SSN, credit card, AWS access key, AWS secret key, GCP service account, OpenAI API key, Anthropic API key, GitHub PAT, Stripe key, Vault token, private key

**High:** HuggingFace token, JWT token, Slack webhook, API key (generic), password field, bearer token, generic secret assignment, connection string (PostgreSQL, MongoDB, MySQL, Redis, Snowflake, MSSQL), PagerDuty key, Datadog API key, Sentry DSN

**Medium:** Email address, classification marker

**Low:** Internal IP address

## Partial Failure Handling

When `extract` or `search-sensitive` encounters an error partway through paginated extraction (e.g., connection loss on page 2), the command returns all rows collected so far along with an error. The CLI surfaces this in the summary as a partial failure count, so operators know the results are incomplete without losing the data already retrieved.

## What each `landed` level means here

`landed` records what actually landed on the target for each finding. The vectordb module reaches these levels:

| `landed` | What produces it in vectordb |
|---|---|
| `reachable` | `enum` — collections and record counts were listed. |
| `influenced` | a bare `inject` (a crafted document was accepted, persistence not verified), `inject --verify-persist` when the re-read confirms nothing persisted, `metadata-inject` when the payload is not returned unsanitized, and `rag-verify` when the canary was injected but did not surface in LLM output. |
| `read-confirmed` | `extract` and `search-sensitive` (real records / sensitive data — PII, secrets — were read off the store), `inject --verify-persist` when *some* injected documents re-read after the delay, and `metadata-inject` when the read-back returns the injected payload unsanitized (the store echoes attacker-controlled metadata — a read-back of poisoned data, **not** code execution). |
| `takeover-capable` | `inject --verify-persist` when *all* injected documents are re-read (full persistence confirmed), and `rag-verify` when the injected canary is retrieved and surfaced in the LLM's response — a full RAG round-trip confirms the poisoned document persists and is re-read by the model. |

The vectordb module tops out at `takeover-capable` on the read/persistence axis and **never reaches `execution-confirmed`** — it reads and poisons data, it does not run code on the target. A bare `inject` stays at `influenced` until persistence is proven: `--verify-persist` grades honestly on how many documents actually re-read (none → `influenced`, some → `read-confirmed`, all → `takeover-capable`), and `rag-verify` claims `takeover-capable` only on a confirmed end-to-end round-trip. `metadata-inject`'s unsanitized echo is a read-back of poisoned metadata (`read-confirmed`), not execution.

## Operator console

For hands-on work beyond the fixed subcommands, `vectordb` exposes a `request` verb — the operator console's one-shot primitive. It reuses this module's `--target`/`--header`/`--api-key` to issue any arbitrary HTTP operation against the store (e.g. a raw collection query or a provider endpoint the verbs don't cover), authenticated or unauthenticated, and mines the response for loot. A raw request is honest and modest: Info severity, `read-confirmed` on a 2xx / `reachable` otherwise, stage access/recon — it never claims impact or own. See [`request`](../cli/request.md). vectordb has no interactive shell (its records are read/written through the verbs above and `request`).

## Workflow Progression

```
discover network (discovers vector DB on :8000/:8080/:6333/:19530/:5432)
  → vectordb enum (list collections, counts)
    → vectordb extract --collection <name> (read documents)
    → vectordb search-sensitive (find PII/credentials)
    → vectordb inject --collection <name> --payload <text> (RAG poisoning, gated)
    → vectordb metadata-inject --collection <name> (metadata injection test, gated)
```
