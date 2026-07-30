# CLI Migration

The CLI is now grouped by operator intent instead of a flat list of top-level commands.

## Old to New

| Old | New |
|---|---|
| `scan-network` | `discover network` |
| `scan-files` | `discover files` |
| `scan` | `scan targets` |
| `scan-all` | `assess network` |
| `templates` | `templates list` |
| `template-info` | `templates info` |
| `merge` | `engagement merge` |
| `bundle` | `engagement bundle` |
| `report` | `report render` |
| `summary` | `report summary` |
| `graph` | `report graph` |

## Examples

```bash
# Old
./aipostex scan-network --target 10.0.0.0/24

# New
./aipostex discover network --target 10.0.0.0/24

# Old
./aipostex scan --target http://127.0.0.1:11434

# New
./aipostex scan targets --target http://127.0.0.1:11434

# Old
./aipostex report findings.json -o report.html

# New
./aipostex report render findings.json -o report.html
```

## Flag Updates

- Network workflows now use repeated singular `--target` instead of `--targets`.
- `report render` uses `--format` instead of `--report-format`.
- `report graph` uses `--format` instead of `--graph-format`.
- Root-level flags are now scoped to the command families that actually use them.
