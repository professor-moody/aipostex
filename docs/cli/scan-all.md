# assess network

Run fingerprinting, vulnerability templates, and optional exploit-style enumeration in one pipeline.

## Synopsis

```bash
aipostex assess network [target...] [flags]
```

## Description

`assess network` expands targets (IPs, hostnames, or CIDRs), discovers AI services on configured ports, runs embedded (and optional extra) vulnerability templates against each HTTP-compatible discovered identity, then optionally runs lightweight enumeration per service type (unless skipped).

Ambiguous/proxy-like HTTP identities are expanded across plausible services with `coverage_expanded=true` metadata. Non-HTTP identities such as PostgreSQL/pgvector are not sprayed with HTTP templates; they remain available to module enumeration and produce an informational skip for the template phase.

Phases:

1. Network fingerprinting
2. Template scanning (unless `--skip-scan`)
3. Module enumeration (unless `--skip-exploit`)

Output uses the shared `--format` flag (default grouped console). Use `-f json -o engagement.json` or `-f jsonl -o findings.jsonl` for machine-readable output.

If the run completes with zero findings but some template scans or service enumerations fail, `assess network` exits with a partial-failure status so incomplete coverage is visible.

## Flags

| Flag | Description |
|---|---|
| `--target` | Host(s) or CIDR(s) to scan (required) |
| `--ports` | Override port list (default: built-in AI service ports) |
| `--mode` | Scan mode: `detect` (safe, default) or `full` (includes exploitation templates) |
| `--skip-exploit` | Stop after vuln scanning |
| `--skip-scan` | Stop after fingerprinting only |
| `--tags` | Filter templates by tags |
| `--severity` | Filter templates by severity |
| `--templates-dir` | Extra templates directory |

See [Common Flags](global-flags.md) for shared output and runtime controls.

## Examples

```bash
aipostex assess network --target 10.0.0.0/24
aipostex assess network --target 192.168.1.50 --ports 11434,8000,3000
aipostex assess network --target 10.0.0.0/24 --skip-exploit -f json -o assess-network.json
```

## See also

- [discover network](scan-network.md) — discovery + templates without full enumeration
- [Output formats](../output/formats.md)
