# Output Formats

aipostex supports multiple output formats, selected via the shared `--format` (`-f`) flag on commands that emit findings (for example `scan targets`, `discover network`, `discover files`). Other commands use dedicated flags (see below).

## Console (default)

```bash
./aipostex scan targets --target http://127.0.0.1:11434
```

Console output renders color-coded findings to stdout with:

- **Severity badge** -- `CRIT`, `HIGH`, `MED`, `LOW`, `INFO` with distinct colors
- **Source tag** -- module that generated the finding (e.g., `[vulncheck]`, `[ollama]`)
- **Title** -- finding headline
- **Target** -- the scanned URL or file path
- **Template** -- template ID (for vulncheck findings)
- **Context** -- key metadata values (module, action, version, model, etc.)
- **Dedupe** -- collapsed duplicate count when applicable
- **Next** -- workflow recommendations (`[read]` or `[gated]` prefixed)
- **Evidence** -- display-safe evidence preview (truncated to 100 chars, or 240 in verbose mode)
- **Tags** -- finding tags

The decorative ASCII banner is displayed only on interactive TTY sessions.

### Grouped Output

The `discover network` command uses a grouped console layout: findings are buffered and displayed grouped by host in the footer, with confirmed service names in each host header. Within each group, findings are sorted by severity (critical first). Fingerprint-level `INFO` findings are folded into the host header rather than shown individually.

When fingerprint evidence is weaker, grouped output now separates it visibly:

- confirmed services stay in the host header
- `suspected:` lines list low-confidence matches
- `warning:` lines attach ambiguity or reverse-proxy guidance to the affected host:port

This makes multi-host scans easier to read compared to interleaved per-finding output. The `scan targets` and `discover files` commands use standard flat output (each finding printed as it occurs).

File-discovery findings are grouped under a synthetic `local-files` bucket so local paths do not inflate host counts in summaries and reports.

### Example Output

```
 HIGH  [vulncheck] Ollama Unauthenticated - 3 Models Exposed
  target: http://127.0.0.1:11434
  template: ollama-auth-001-unauthenticated-api
  next: [read] aipostex ollama --target http://127.0.0.1:11434 enum
  tags: ollama, auth, misconfiguration, llmjacking

 INFO  [vulncheck] Ollama Version Disclosed: 0.1.44
  target: http://127.0.0.1:11434
  template: ollama-auth-001-unauthenticated-api

────────────────────────────────────────────────────────
Findings: 0 critical 1 high 0 medium 0 low 1 info (total: 2)
```

## JSON

```bash
./aipostex scan targets --target http://127.0.0.1:11434 --format json --output findings.json
```

JSON output wraps all findings in a `FindingCollection` object, written when the command completes:

```json
{
  "engagement_id": "eng-a1b2c3d4e5f6",
  "start_time": "2025-01-15T10:30:00Z",
  "end_time": "2025-01-15T10:30:05Z",
  "findings": [
    {
      "id": "f-abc123",
      "timestamp": "2025-01-15T10:30:01Z",
      "source": "vulncheck",
      "template_id": "ollama-auth-001-unauthenticated-api",
      "target": "http://127.0.0.1:11434",
      "title": "Ollama Unauthenticated - 3 Models Exposed",
      "severity": "high",
      "description": "...",
      "remediation": "...",
      "tags": ["ollama", "auth"],
      "metadata": { ... }
    }
  ]
}
```

!!! warning
    JSON output buffers all findings in memory and writes them at the end. For long-running scans or large result sets, prefer JSONL.

## JSONL

```bash
./aipostex discover network --target 10.0.0.0/24 --format jsonl --output findings.jsonl
```

JSONL (JSON Lines) streams one finding per line as it is produced:

```json
{"id":"f-abc123","timestamp":"2025-01-15T10:30:01Z","source":"vulncheck","target":"http://10.0.0.5:11434","title":"Ollama Unauthenticated","severity":"high",...}
{"id":"f-def456","timestamp":"2025-01-15T10:30:02Z","source":"fingerprint","target":"http://10.0.0.6:8888","title":"AI service suspected: jupyter","severity":"info","metadata":{"match_kind":"suspected","confidence":"medium",...}}
```

JSONL is recommended for:

- Long-running scans (`discover network` on large CIDRs)
- Crash-tolerant output (partial results are preserved)
- Pipe processing (`jq`, `grep`, etc.)
- Large result sets that would be expensive to buffer

Post-processing commands such as `engagement merge`, `report summary`, `report render`, `report graph`, and `engagement bundle` accept either JSON or JSONL input.

## stdout vs stderr

| Stream | Content |
|---|---|
| **stdout** | Findings output (console, JSON, JSONL, CSV, HTML, SARIF, Markdown, or PDF path via `--output`) |
| **stderr** | Progress lines, warnings, `--force-exploit` blocked messages, command summaries, `Next actions` guidance |

This separation allows clean piping:

```bash
# Pipe findings through jq, summaries still print to terminal
./aipostex scan targets --target http://127.0.0.1:11434 --format json | jq '.findings[].title'

# Save findings to file, see summaries on terminal
./aipostex discover network --target 10.0.0.0/24 --format jsonl --output findings.jsonl
```

## CSV

```bash
./aipostex scan targets --target http://127.0.0.1:11434 --format csv --output findings.csv
```

Fixed-column CSV suitable for spreadsheets. One row per finding.

## HTML

```bash
./aipostex discover network --target 10.0.0.10 --format html --output report.html
```

Self-contained HTML report with executive-grade layout: severity summary cards, per-host grouped findings, client-side search and severity filters, expandable evidence and remediation, and a sticky sidebar table of contents. Prefer writing to a file (not stdout).

Key features:

- **Engagement strip** -- displays target scope, scan mode (`Detection Only` / `Full Assessment`), timestamps, and finding counts.
- **Executive summary** -- risk verdict with severity breakdown and top findings; language adjusts based on scan mode.
- **Proof badges** -- template-based findings display `VERIFIED` (detection templates) or `EXPLOITED` (exploit templates) badges. See the [finding schema](finding-schema.md) for how badges are determined.
- **Auto-generated evidence** -- all template-based (`vulncheck`) findings automatically carry HTTP request/response evidence, shown in collapsible detail blocks within the finding row.
- **Scan mode metadata** -- findings carry `scan_mode` in metadata, preserved when generating reports from engagement JSON or JSONL findings.

## SARIF

```bash
./aipostex scan targets --target http://127.0.0.1:3000 --format sarif --output results.sarif
```

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for GitHub Code Scanning, DefectDojo, VS Code SARIF Viewer, and similar tools.

## Markdown

```bash
./aipostex scan targets --target http://127.0.0.1:11434 --format markdown --output report.md
```

Alias: `--format md`. Report with summary table, findings grouped by host, remediation summary, and optional workflow next-actions.

## PDF

```bash
./aipostex scan targets --target http://127.0.0.1:11434 --format pdf --output report.pdf
```

Renders the HTML report through headless Chrome/Chromium (`--print-to-pdf`). **Requires** Chrome or Chromium on `PATH`. Use `--format html` if PDF generation is unavailable.

## Dossier (operator files)

`--format dossier -o <dir>` writes the whole organized operator folder in **one
command**: landed/stage-tagged looted credentials (`credentials.json`/`.csv`/`.txt`),
credential-injected follow-up commands (`commands.sh`), in-scope `targets.csv`, raw
`evidence/`, `findings.jsonl`, and a `README.md` index. Like every `-o` target it
also tees the console view, so the run prints findings live while the folder is
written. It requires `-o <dir>` (it errors otherwise, like `pdf`).

```bash
# run + organized loot folder in one command
aipostex scan targets --target http://127.0.0.1:8888 --format dossier -o ./engagement

# report view accepts the directory directly (reads <dir>/findings.jsonl)
aipostex report view ./engagement --chains
aipostex report view ./engagement --credentials
```

!!! tip "The easy way: run inside a session"
    `aipostex sessions start <name>` opens an engagement dossier and makes it the default output, so
    **every** subsequent command accumulates into it with no `--format dossier -o` flag at all. See
    [sessions](../cli/sessions.md).

The same folder can also be produced from an already-saved findings file with
`report view findings.jsonl --dossier-dir <dir>` — useful when you filtered the
findings first. See [report view](../cli/report-view.md#dossier-dossier-dir) for the
full layout. The credential files embed live secrets and are written owner-only
(`0600`/`0700`).

## Format Comparison

| Feature | Console | JSON | JSONL | CSV | HTML | SARIF | Markdown | PDF |
|---|---|---|---|---|---|---|---|---|
| Streaming output | Yes | No (buffered) | Yes | No | No | No | No | No |
| Machine-readable | No | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Crash recovery | Partial | No | Yes | No | No | No | No | No |
| Full metadata | Limited | Yes | Yes | Partial | Yes | Partial | Partial | Yes |
| Evidence display | Truncated preview | Full | Full | Truncated | Full (expand) | In message | In cells | Like HTML |
| Recommended for | Interactive use | APIs, tooling | Long scans | Excel/Sheets | Human report | CI security | Wikis, PRs | Shareable doc |
