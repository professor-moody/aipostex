# report render

Generate a **narrative** engagement report (distinct from raw `--format html` scan output).

## Synopsis

```bash
aipostex report render findings.json [flags]
```

## Description

Uses the internal `reportgen` package to build a summary model from either `FindingCollection` JSON or JSONL findings, then renders:

- **html** — standalone styled HTML (executive-oriented layout)
- **markdown** / **md**
- **json** — structured report object

This is complementary to `./aipostex ... --format html`, which writes the finding-oriented HTML output directly from a scan command.

## Flags

| Flag | Description |
|---|---|
| `--format` | `html` (default), `markdown`, or `json` |
| `--output`, `-o` | Output file (default: stdout) |

## Examples

```bash
aipostex report render findings.json -o narrative.html
aipostex report render findings.json --format markdown -o narrative.md
aipostex report render findings.json --format json | jq .
```

## See also

- [report summary](summary.md) — metrics-focused executive summary
- [engagement bundle](bundle.md) — zip with tabular HTML + JSON
