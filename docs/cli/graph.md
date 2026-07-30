# report graph

Emit a Mermaid or Graphviz DOT attack graph from staged findings grouped per host.

## Synopsis

```bash
aipostex report graph [flags]
```

## Description

Reads `--input` JSON or JSONL findings. Stages are taken from `metadata.stage` when present; otherwise inferred from finding source and severity (e.g. fingerprint → recon, medium vulncheck → access, high/critical vulncheck → impact).

Default output is Mermaid `flowchart TD` to stdout. Use `-o` to write a file.

## Flags

| Flag | Description |
|---|---|
| `--input` | Engagement JSON path (**required**) |
| `--format` | `mermaid` (default) or `dot` |
| `--output`, `-o` | Output file (default: stdout) |

## Examples

```bash
aipostex report graph --input merged.json -o attack.mmd
aipostex report graph --input merged.json --format dot -o attack.dot
```

View Mermaid in [Mermaid Live Editor](https://mermaid.live) or GitHub-flavored Markdown. Render DOT with Graphviz (`dot -Tpng attack.dot -o attack.png`).

## See also

- [engagement merge](merge.md)
