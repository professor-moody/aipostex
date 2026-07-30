# scan targets

Run YAML-based vulnerability scans against one or more AI infrastructure targets.

## Synopsis

```bash
aipostex scan targets [target...] [flags]
```

## Description

The `scan targets` command loads vulnerability templates (both embedded and from optional directories), filters them by tags or severity, and executes matching templates against the specified targets. Each template runs a detect phase to confirm the target type, then executes checks with HTTP matchers and extractors to identify vulnerabilities.

Targets can be passed as positional arguments, via `--target`, or both. All sources are merged and deduplicated.

## Flags

| Flag | Short | Required | Default | Description |
|---|---|---|---|---|
| `--target` | `-t` | No | | Target URL(s). Can be specified multiple times. At least one target is required (flag or positional). |
| `--mode` | | No | `detect` | Scan mode: `detect` (safe, runs only detection templates) or `full` (includes exploitation templates). |
| `--tags` | | No | *(all)* | Filter templates by tag (e.g., `ollama`, `mcp`, `auth`). |
| `--severity` | | No | *(all)* | Filter templates by severity (`critical`, `high`, `medium`, `low`, `info`). |
| `--templates-dir` | | No | *(none)* | Additional templates directory. Loaded after built-in templates. |

See [Common Flags](global-flags.md) for shared output and runtime controls.

## Summary Output

After scanning, a summary is printed to stderr with:

- Targets attempted
- Templates considered and matched
- Findings emitted
- Request and template error counts
- Zero-finding targets
- Workflow plans inferred from finding tags (Next Actions)

If no findings are emitted but one or more targets hit request or template failures, `scan targets` exits with a partial-failure status so incomplete assessments are visible to automation.

## Workflow Plans

After findings are emitted, `scan targets` reverse-maps template tags to service names and generates
workflow recommendations for discovered exploit paths. These appear as a "Next Actions" section
on stderr, matching the format used by `discover network`.

## No-Port Warning

When a target URL has no port, `scan targets` warns and includes a copyable `discover network` command to discover AI service ports.

## Scan Modes

Templates are classified as **detection** (passive, read-only checks) or **exploit** (active payloads, SSRF, command injection, inference abuse). The `--mode` flag controls which templates run:

| Mode | Detection Templates | Exploit Templates | Use Case |
|---|---|---|---|
| `detect` (default) | Yes | No | Safe reconnaissance, no target modification |
| `full` | Yes | Yes | Full assessment with active exploitation |

In `detect` mode, the engine skips all exploit-type templates automatically. The console output shows the active mode and a template type breakdown.

## Examples

```bash
# Scan an Ollama instance (positional target, default detect mode)
./aipostex scan targets http://127.0.0.1:11434

# Full assessment including exploitation templates
./aipostex scan targets http://127.0.0.1:11434 --mode full

# Same thing using --target flag
./aipostex scan targets --target http://127.0.0.1:11434

# Scan for MCP vulnerabilities only
./aipostex scan targets http://127.0.0.1:3000 --tags mcp

# Scan for critical issues only
./aipostex scan targets --target http://127.0.0.1:8000 --severity critical

# Scan multiple targets
./aipostex scan targets --target http://10.0.0.5:11434 --target http://10.0.0.6:8000

# Scan through a proxy with TLS skip
./aipostex scan targets --target https://10.0.0.10:8443 \
  --proxy socks5://127.0.0.1:1080 --insecure

# Use custom templates alongside built-ins
./aipostex scan targets --target http://127.0.0.1:11434 \
  --templates-dir ./my-templates
```

## Template Loading

1. Built-in templates are loaded first from the embedded `embed.FS`
2. If `--templates-dir` is specified, templates from that directory are loaded and may override built-in templates with the same ID
3. Templates are filtered by `--tags` and `--severity` before execution

## Finding Deduplication

Findings are deduplicated deterministically before output based on source, template ID, target, title, severity, description, and evidence. Duplicate counts are preserved in `metadata.dedupe_count`.
