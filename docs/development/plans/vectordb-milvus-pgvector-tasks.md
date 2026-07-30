# Vector DB expansion (Milvus + pgvector) — task checklist

Source: `HANDOFF-aipostex-v020-expansion.md` (repository root), Task 1.  
Use this as a **verification and completion** list. Much of this is already implemented in-tree; unchecked items are optional follow-ups or manual validation.

**Code map:** [pkg/exploit/vectordb/](https://github.com/professor-moody/aipostex/tree/main/pkg/exploit/vectordb) · [cmd/aipostex/vectordb.go](https://github.com/professor-moody/aipostex/blob/main/cmd/aipostex/vectordb.go) · [cmd/aipostex/vectordb_test.go](https://github.com/professor-moody/aipostex/blob/main/cmd/aipostex/vectordb_test.go) · [pkg/fingerprint/fingerprint.go](https://github.com/professor-moody/aipostex/blob/main/pkg/fingerprint/fingerprint.go) (Milvus probe) · [internal/config/config.go](https://github.com/professor-moody/aipostex/blob/main/internal/config/config.go) (ports 19530, 5432) · [docs/modules/vectordb.md](https://github.com/professor-moody/aipostex/blob/main/docs/modules/vectordb.md)

---

## 1a. Milvus provider (`pkg/exploit/vectordb/`)

- [x] Implement REST client (collections list, describe, query/search, sensitive scan) — see [milvus.go](https://github.com/professor-moody/aipostex/blob/main/pkg/exploit/vectordb/milvus.go)
- [x] `NewProviderClient` / `Provider` registration for `--type milvus` — [providers.go](https://github.com/professor-moody/aipostex/blob/main/pkg/exploit/vectordb/providers.go)
- [x] Unit tests with `httptest` — [milvus_test.go](https://github.com/professor-moody/aipostex/blob/main/pkg/exploit/vectordb/milvus_test.go)
- [ ] **Manual / lab:** run `vectordb enum|extract|search-sensitive` against a real Milvus 2.4+ instance; capture findings JSON for regression fixtures if useful

---

## 1b. pgvector provider

- [x] `pgx/v5` client, table/column introspection, vector column detection — [pgvector.go](https://github.com/professor-moody/aipostex/blob/main/pkg/exploit/vectordb/pgvector.go)
- [x] CLI flags `--db-user`, `--db-password`, `--db-name`, `--db-sslmode` (see [vectordb.go](https://github.com/professor-moody/aipostex/blob/main/cmd/aipostex/vectordb.go))
- [x] Validation: pgvector flags only when type is pgvector (confirm in CLI init / `newVDBClient`)
- [ ] **Tests:** extend integration-style coverage if CI can run ephemeral Postgres (optional build tag); otherwise document lab-only validation

---

## 1c. Subcommand: `inject` (gated)

- [x] Shared inject helpers per provider — [inject.go](https://github.com/professor-moody/aipostex/blob/main/pkg/exploit/vectordb/inject.go)
- [x] `--collection`, `--payload`, `--metadata`, `--count`; `requireForceExploit` at CLI
- [x] Findings: High / execution-confirmed stage/landed metadata (verify in `runVDBInject` paths)
- [ ] **CLI tests:** [vectordb_test.go](https://github.com/professor-moody/aipostex/blob/main/cmd/aipostex/vectordb_test.go) covers gate + `--collection`; add Milvus/pgvector-specific **httptest** or mock success paths if gaps appear in review

---

## 1d. Subcommand: `metadata-inject` (gated)

- [x] Flags `--key`, `--payload`; force-exploit gate — see [vectordb.go](https://github.com/professor-moody/aipostex/blob/main/cmd/aipostex/vectordb.go)
- [x] Per-provider retrieve-and-verify behavior (code review [inject.go](https://github.com/professor-moody/aipostex/blob/main/pkg/exploit/vectordb/inject.go) / provider methods)
- [x] CLI tests for `--force-exploit` requirement — [vectordb_test.go](https://github.com/professor-moody/aipostex/blob/main/cmd/aipostex/vectordb_test.go)

---

## 1e. Fingerprint + default ports

- [x] Milvus HTTP probes in [fingerprint.go](https://github.com/professor-moody/aipostex/blob/main/pkg/fingerprint/fingerprint.go)
- [x] Default scan list includes `19530` and `5432` in [internal/config/config.go](https://github.com/professor-moody/aipostex/blob/main/internal/config/config.go)
- [x] `scan_network` tag mapping includes `milvus` — [scan_network.go](https://github.com/professor-moody/aipostex/blob/main/cmd/aipostex/scan_network.go)

---

## 1f. Vulnerability templates

- [x] `milvus-detect-001-unauth-access.yaml` under [pkg/vulncheck/templates/vectordb/](https://github.com/professor-moody/aipostex/tree/main/pkg/vulncheck/templates/vectordb)
- [ ] **Optional (handoff):** pgvector has no HTTP surface — either skip vulncheck template or add a **narrow** template for a known HTTP admin (pgAdmin, etc.) with clear false-positive controls

---

## 1g. Tests (summary)

- [x] `pkg/exploit/vectordb/milvus_test.go`
- [x] `pkg/exploit/vectordb/providers_test.go` (provider factory)
- [x] `cmd/aipostex/vectordb_test.go` (gates, required flags)
- [x] `main_test` registers `vectordb` — [main_test.go](https://github.com/professor-moody/aipostex/blob/main/cmd/aipostex/main_test.go)
- [ ] Add `pgvector_test.go` with docker-less mocks where feasible, or document “lab only”

---

## 1h. Documentation

- [x] [docs/modules/vectordb.md](https://github.com/professor-moody/aipostex/blob/main/docs/modules/vectordb.md) — providers table, flags, inject/metadata-inject, examples

---

## Sign-off

When all **manual / lab** and **optional** rows you care about are done, mark HANDOFF Task 1 complete in your release notes and move embedding-poisoning roadmap items (v0.8.0) that depend on stable `inject` behavior.
