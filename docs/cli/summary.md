# report summary

Build an executive-style summary (risk score, severity bars, top chains, remediation priorities) from one or more engagement JSON or JSONL files.

## Synopsis

```bash
aipostex report summary [file1.json] [file2.json] ... [flags]
```

## Description

Reads standard `FindingCollection` JSON or JSONL findings (same output family produced by `scan targets`, `discover network`, `assess network`, and `engagement merge`). Prints a color summary to **stderr**. If `--output` (`-o`) is set, also writes a structured JSON object with the same metrics (for dashboards or archiving).

## Flags

| Flag | Description |
|---|---|
| `--output`, `-o` | Optional path for JSON summary (default: stderr-only human summary) |

Only `--output` is used by this command.

## Examples

```bash
aipostex report summary findings.json
aipostex report summary part1.json part2.json -o exec-summary.json
```

## See also

- [engagement merge](merge.md)
- [report render](report.md)
