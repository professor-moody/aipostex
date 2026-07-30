# Technical debt: ambiguous fingerprint coverage + CI maintenance

Short, actionable items that do not block feature releases but should be scheduled before GitHub runner deprecations bite.

---

## 1. Ambiguous fingerprint → template / workflow coverage

### Behavior (resolved)

- [pkg/fingerprint/fingerprint.go](https://github.com/professor-moody/aipostex/blob/main/pkg/fingerprint/fingerprint.go) `buildResults` sets `MatchKindAmbiguous` when:
  - `proxyLikely` (many services),
  - multiple services with no strong winner,
  - or multiple confirmed matches.
- [cmd/aipostex/scan_network.go](https://github.com/professor-moody/aipostex/blob/main/cmd/aipostex/scan_network.go) `selectableFingerprintResults` now expands ambiguous/proxy-like HTTP identities and labels template findings with uncertainty metadata instead of dropping the entire observation.
- Workflow plans still emit an “uncertain port” recommendation via `buildObservationWorkflowPlans`.

### Tradeoff

- **Pro:** Reduces false negatives when two weak signals are both real (e.g. alternate stacks on same port).
- **Con:** Findings from expanded coverage require operators to read `coverage_expanded` / `identity_confidence` before treating service identity as confirmed.

### Planning tasks

- [x] **Document** ambiguous expansion and non-HTTP template skips in `docs/`.
- [x] **Product decision:** Ambiguous/proxy-like HTTP identities are expanded by default, with explicit `coverage_expanded` metadata instead of a separate `--include-ambiguous` flag.
- [x] **Tests:** Golden cases cover ambiguous expansion and non-HTTP template skip behavior.

---

## 2. GitHub Actions: Node 20 deprecation

### Context

CI workflows emit annotations that **actions running on Node 20** will be migrated; see GitHub changelog (2025–2026).

Affected workflows (repo root):

- [.github/workflows/ci.yml](https://github.com/professor-moody/aipostex/blob/main/.github/workflows/ci.yml) — `actions/checkout@v4`, `actions/setup-go@v5`, `golangci/golangci-lint-action@v7`, `actions/upload-artifact@v4`
- [.github/workflows/docs.yml](https://github.com/professor-moody/aipostex/blob/main/.github/workflows/docs.yml)
- [.github/workflows/release.yml](https://github.com/professor-moody/aipostex/blob/main/.github/workflows/release.yml)

### Planning tasks

- [ ] **Bump action majors** when stable: e.g. `actions/checkout@v5`, `actions/setup-go@v6` (verify current releases on GitHub).
- [ ] **golangci-lint-action:** move to version compatible with Node 24 runners when required.
- [ ] **Optional:** set `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` in workflow `env` for early signal (per GitHub docs) — only after verifying compatibility.
- [ ] **Verify:** one PR that only touches workflows; full CI green.

### Non-goals

- Changing Go version (`go-version: "1.25"`) unless a separate upgrade is planned.

---

## 3. Sizing

Treat **§1** as a small product/design decision (1 PR for docs + optional flag). Treat **§2** as a single maintenance PR per quarter or when annotations escalate to failures.
