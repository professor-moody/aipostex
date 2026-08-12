# report view

Inspect raw findings, evidence, extracted credentials, and generated follow-up
commands from a saved run — without losing detail to the console summary.

## Synopsis

```bash
aipostex report view findings.jsonl [flags]
```

## Description

Use `report view` after saving a long or secret-heavy run with
`--format jsonl -o findings.jsonl`. It re-reads the findings, filters them, and
lets you pull out exactly what an operator needs next: the looted credentials,
the credential-injected follow-up commands, and the full raw evidence that the
console summary truncates.

## Flags

| Flag | Description |
|---|---|
| `--source` | Filter by finding source/module (e.g. `ray`, `mlflow`) |
| `--service` | Alias for `--source` (e.g. `--service mlflow`) |
| `--target` | Filter by target substring |
| `--severity` | Filter by severity |
| `--title-contains` | Filter by title substring |
| `--id` | Filter by finding ID |
| `--evidence` | Print full raw evidence for matching findings |
| `--credentials` | Print extracted credential values for matching findings |
| `--commands` | Print credential-derived follow-up commands |
| `--chains` | Reconstruct looted credentials as **attack chains** (see below): `find → loot → chain → reached`/`gap` |
| `--threat-model` | Render a **threat-model** view (see below): kill-chain coverage, crown jewels, ATLAS-aligned tactics |
| `--limit` | Maximum matching findings to display (`0` = no limit) |
| `--dossier-dir` | Write an operator **dossier** (see below) to this directory instead of printing to the console |

## Examples

```bash
# Everything, quick triage
aipostex report view findings.jsonl

# Just the loot and the pivots
aipostex report view findings.jsonl --credentials --commands

# Narrow to one module + read the raw evidence
aipostex report view findings.jsonl --source ray --title-contains runtime_env --evidence

# Reconstruct the attack chains from the loot
aipostex report view findings.jsonl --chains

# Threat-model deliverable: how far each target was pushed + ATLAS tactics
aipostex report view findings.jsonl --threat-model
```

## Threat model: `--threat-model`

`--threat-model` turns the findings into a threat-model deliverable, built entirely from
the honest `stage`/`landed` kill-chain metadata every module already emits — nothing is
inferred or inflated:

1. **Kill-chain coverage** — the furthest each target was actually pushed
   (`recon → access → impact → own`, `reachable → takeover-capable`), sorted by depth.
2. **Crown jewels** — the findings that reached the deepest `landed` levels
   (`takeover-capable`, `execution-confirmed`, `read-confirmed`) — what the operator
   actually got, not what was merely reachable.
3. **MITRE ATLAS-aligned tactics** — a curated grouping of the findings by ATLAS tactic
   (Discovery, ML Model Access, Defense Evasion, Credential Access, Execution, Exfiltration,
   Persistence, …). The tactic and technique **label** are the authoritative anchor; a
   specific `AML.T####` id is attached only where high-confidence (e.g. `AML.T0051` LLM
   Prompt Injection, `AML.T0054` LLM Jailbreak), so no id is fabricated. The mapping is
   aipostex's own, not MITRE's.

It is the Module-10 threat-model / assumption-register view: it reads the same `stage`/`landed`
axes that grade every finding and rolls them up into "what did we prove, and how far."

## Chains: `--chains`

`--chains` reconstructs the operator's **attack chains** from the findings — the
`find → loot → chain → reached` narrative — instead of printing a flat list. For every
looted, chainable credential it shows one chain:

```bash
aipostex report view findings.jsonl --chains
```

```
── Attack chains ──────────────────────────────────────────────────────────────

  Chain 1  172.16.50.20:8265 → 172.16.50.30:5000  (mlflow-basic-auth)
    [find]    ray        Ray runtime_env exposes MLflow gateway credentials  (ray-aaa111, reachable)
    [loot]    cred       mlflow-basic-auth mlflow-gw = YWRtaW46c2VjcmV0  (from ray-aaa111)
    [chain]   next       aipostex mlflow --target http://172.16.50.30:5000 --header "Authorization: Basic YWRtaW46c2VjcmV0" enum
    [reached] mlflow     MLflow experiments enumerated (3 visible)  (mlflow-bbb222, read-confirmed)

  Chain 2  172.16.50.40:8180  (hf-token)
    [find]    openai-compat TGI leaks HuggingFace token in environment  (tgi-ccc333, reachable)
    [loot]    cred       hf-token hf-env = hf_ABCDEF123456  (from tgi-ccc333)
    [chain]   next       aipostex huggingface --target http://172.16.50.40:8180 --header "Authorization: Bearer hf_ABCDEF123456" enum
    [gap]     run        not yet run — execute the command above to exercise this hop

  2 chain(s): 1 reached a correlated downstream finding on the unlocked target, 1 with an un-run next step.
  ([reached] = a finding already exists on the unlocked target; it is correlated by host+module, not a verified credential replay.)
```

What each row means, and what's honest about it:

- **`find`** — the finding that leaked the credential, shown with its own
  `landed`. The `find → loot → chain` spine is exact: the credential records
  its source finding id and the target it applies to.
- **`loot`** — the credential itself, **raw** (aipostex never redacts evidence).
- **`chain`** — the concrete follow-on command(s) the autochain engine generated for
  that credential, targeting the **unlocked** host.
- **`reached`** — a downstream finding that **already exists** on the unlocked target,
  correlated by host + module. This is **not** a verified credential replay: there is
  no explicit action→result edge, the tool never recorded that this credential
  produced that finding, and the finding may even predate the loot. It is shown with
  **its own** landed and deliberately labeled `reached`, never "proven".
- **`gap`** — a chainable credential whose next hop **hasn't been run yet**: the chain
  ends here and names the exact next command to run.

Filters apply first, so `--chains --service mlflow` scopes the board to one module.

## Dossier: `--dossier-dir`

`--dossier-dir <dir>` turns the (filtered) findings into an **operator dossier** —
organized, parseable, copy-ready files — instead of dumping to the console. It's
the aipostex answer to "give me the loot as files," with two twists that keep it
ours rather than a generic export:

- **Every credential is landed/stage-tagged.** Each entry is joined back to its source
  finding's `stage`/`landed`, so you can tell confirmed-usable loot
  from speculative loot at a glance — and which finding it came from.
- **Commands are chain-engine output, not generic snippets.** `commands.sh` is
  the credential-injected next-actions from the same autochain engine behind
  `--commands`, grouped by target.

```bash
aipostex report view findings.jsonl --dossier-dir ./engagement-dossier
# [*] wrote dossier to ./engagement-dossier: 3 credential(s) (2 chainable), 5 command(s), 4 target(s), 6 evidence file(s)
```

Filters apply first, so you can scope a dossier to one module or severity
(`--service mlflow --dossier-dir ./mlflow-loot`).

!!! tip "One command instead of two"
    You don't have to save `findings.jsonl` first. `--format dossier -o <dir>` on any
    run writes the same folder directly (`aipostex scan targets … --format dossier -o
    ./engagement`), and `report view ./engagement` reads a dossier directory straight
    back (it loads `<dir>/findings.jsonl`). See
    [output formats](../output/formats.md#dossier-operator-files).

### Querying the dossier

The files are the query surface — there is no separate query command. Scope by
service up front with `--service`, or query the generated files with `jq`/`grep`
(credentials carry `source_service` — where a secret was looted — and
`target_url` — where it applies):

```bash
# creds looted FROM a given service
jq -r '.[] | select(.source_service=="ray") | "\(.type)\t\(.value)"' dossier/credentials.json

# creds usable AGAINST a given service (by target)
jq -r '.[] | select(.target_url|test("5000")) | "\(.type)\t\(.value)\t\(.target_url)"' dossier/credentials.json

# only the chainable creds + their landed/stage
jq -r '.[] | select(.chainable) | "\(.type)\t\(.landed)\t\(.target_url)"' dossier/credentials.json

# credentials.txt is already grouped by service
grep -A5 '^# mlflow' dossier/credentials.txt
```

### Dossier layout

A flat, greppable directory (no per-service subdirs, no zip — that's
[`engagement bundle`](bundle.md)'s job):

| File | Contents |
|---|---|
| `credentials.json` / `.csv` | Looted credentials, each tagged with its `landed`/`stage` and source finding. |
| `credentials.txt` | Copy-ready `name=value` credentials, grouped by service. |
| `commands.sh` | Credential-injected follow-on commands, grouped by target. Review before running. |
| `targets.csv` | In-scope targets: service, finding count, worst severity. |
| `evidence/<finding-id>.txt` | Raw evidence per finding that has any. |
| `findings.jsonl` | The findings the dossier was built from. |
| `README.md` | Index + counts. |

!!! warning "The dossier holds live secrets"
    `credentials.*` and `commands.sh` embed looted credentials, so they are
    written owner-only (`0600`/`0700`). Treat the directory like the credentials
    it contains.

## See also

- [report render](report.md) — narrative engagement report
- [report summary](summary.md) — metrics-focused executive summary
- [engagement bundle](bundle.md) — zip with tabular HTML + JSON
