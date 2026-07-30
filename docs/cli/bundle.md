# engagement bundle

Package engagement findings into a zip archive with HTML report, raw evidence files, and index.

## Synopsis

```bash
aipostex engagement bundle [flags]
```

## Description

Requires `--input` pointing to either an engagement JSON file or JSONL findings. Produces a zip (default name `bundle-{engagement_id}.zip`) containing:

- `bundle-{id}/report.json` — normalized engagement document
- `bundle-{id}/report.html` — rendered HTML report (same renderer as `--format html`)
- `bundle-{id}/evidence/` — one `.txt` per finding with evidence longer than 200 characters
- `bundle-{id}/README.md` — index and counts

## Flags

| Flag | Description |
|---|---|
| `--input` | Engagement JSON path (**required**) |
| `--output`, `-o` | Zip output path (default: `bundle-{engagement_id}.zip`) |

## Example

```bash
aipostex engagement bundle --input engagement.json -o handoff.zip
```

## See also

- [Output formats](../output/formats.md) — HTML report behavior
