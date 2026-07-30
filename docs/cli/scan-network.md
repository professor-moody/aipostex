# discover network

Fingerprint a network for AI services and optionally run vulnerability templates against discoveries.

## Synopsis

```bash
aipostex discover network [target...] [flags]
```

## Description

The `discover network` command performs three operations in sequence:

1. **Port scanning** -- TCP connect probes to each host:port combination
2. **Service fingerprinting** -- HTTP-based probes to identify specific AI services (Ollama, Jupyter, MCP, etc.)
3. **Auto-scan** -- optionally runs matching vulnerability templates against discovered services

Open ports are first-class output. Every TCP-open port survives into the final discovery table and machine-readable findings, even when fingerprinting is weak, partial, or times out. Service identity is now an attribute of the port row rather than the thing that decides whether the row exists.

Discovered services are still deduplicated by URL and service type for follow-on template scanning. Vulnerability scan results are further deduplicated before output. When no vulnerability templates are loaded (both embedded and custom fail), a warning is emitted and auto-scan is effectively disabled.

Fingerprint results now surface four operator-facing classes:

- `confirmed` -- strong or corroborated service identity
- `suspected` -- weak/generic evidence only
- `ambiguous` -- overlapping matches with no strong winner, or a likely reverse proxy
- `candidate` / `unidentified` -- open port with partial evidence or no surviving fingerprint

The machine-readable output keeps `specificity` for compatibility, but `port_state`, `fingerprint_status`, `timed_out`, `candidate_services`, `matched_probes`, `match_kind`, `confidence`, and `ambiguity_reason` are the preferred fields for interpreting discovery quality.

During auto-scan, ambiguous/proxy-like HTTP identities are expanded instead of dropped. Findings from those runs carry `coverage_expanded=true`, `candidate_services`, and `identity_confidence=ambiguous`, so operators get complete visibility without mistaking the identity for a confirmed service. Clear non-HTTP identities such as PostgreSQL/pgvector are preserved for module follow-on paths, but HTTP vulnerability templates are skipped with an informational `http-template-incompatible` finding.

Targets can be passed as positional arguments, via `--target`, or both. All sources are merged and deduplicated.

## Flags

| Flag | Required | Default | Description |
|---|---|---|---|
| `--target` | No | | Host(s) or CIDR range(s) to scan. Can be specified multiple times. At least one target is required (flag or positional). |
| `--ports` | No | *(AI defaults)* | Ports to probe. Defaults to common AI service ports. |
| `--mode` | No | `detect` | Scan mode: `detect` (safe, runs only detection templates) or `full` (includes exploitation templates). |
| `--auto-scan` | No | `true` | Run vulnerability templates on discovered services. |
| `--discovery-only` | No | `false` | Only perform service discovery, skip vulnerability scanning entirely. |
| `--tags` | No | *(all)* | Filter vulnerability templates by tag. When provided, replaces auto-detected service tags (exclusive, not additive). |
| `--severity` | No | *(all)* | Filter templates by severity. |
| `--templates-dir` | No | *(none)* | Additional templates directory. |

See [Common Flags](global-flags.md) for shared output and runtime controls.

## Default Ports

When `--ports` is not specified, the following AI service ports are probed:

| Port | Service |
|---|---|
| 80 | HTTP reverse proxy |
| 443 | HTTPS reverse proxy |
| 8443 | Alternate HTTPS |
| 11434 | Ollama |
| 8000 | vLLM, ChromaDB |
| 4000 | LiteLLM |
| 8080 | LocalAI, Weaviate |
| 1234 | LM Studio |
| 6333 | Qdrant |
| 8888 | Jupyter |
| 7860 | Gradio |
| 8501 | Streamlit |
| 5000 | MLflow |
| 8265 | Ray Dashboard |
| 3000 | MCP servers |
| 6274 | MCP Inspector / MCPJam Inspector |

!!! note
    Ports 80, 443, and 8443 are included because production AI services are frequently deployed behind reverse proxies. When 3+ distinct services are detected on the same port, the result is flagged as `proxy_likely` and a warning is emitted during scanning.

## CIDR Expansion

CIDR ranges are expanded to individual host IPs. The `--max-hosts` flag (default `65536`) limits expansion to prevent accidentally scanning enormous ranges. Set to `0` to disable the guardrail. Large IPv6 CIDRs (63+ host bits, e.g., `/64` and larger) are rejected before expansion to prevent integer overflow. Overlapping CIDRs are deduplicated before the host count is checked against `--max-hosts`.

URL-format targets (e.g., `http://10.0.0.1:8000`) are normalized before expansion -- the scheme is stripped, the host is used for CIDR/host processing, and any port in the URL is merged into the port scan list.

## Summary Output

After scanning, a summary is printed to stderr with:

- Hosts and ports probed
- Open ports discovered
- Confirmed and suspected identities
- Timed-out and unclassified open ports
- Workflow targets generated
- Gated suggestions count
- Per-service scan results, including incomplete coverage when request or template failures occur
- Ambiguous service identities expanded and non-HTTP services skipped for HTTP-only templates

### Grouped Console Output

In console mode, `discover network` prints one discovery row per TCP-open port. The row shows `PORT`, `STATE`, `IDENTITY`, `CONFIDENCE`, `NOTES`, and `SERVER`, so ports never disappear just because fingerprinting is inconclusive. Ambiguity, candidate evidence, and timeout notes are attached to the affected port row directly.

## Workflow Guidance

For each discovered open port, `discover network` attaches **Next actions** -- either broad validation commands or service-specific follow-on commands when the fingerprint is strong enough. These appear in:

- Console stderr output as a grouped `Next actions` section
- Machine-readable `metadata.workflow` on findings in JSON/JSONL output

Read-only commands appear before gated commands.

For `suspected`, `ambiguous`, `candidate`, or `unidentified` ports, workflow generation becomes more conservative:

- a broad `scan targets --target <url>` recommendation is prepended
- module-specific follow-ons are only emitted for `confirmed` and `suspected` identities
- gated recommendations are suppressed until the service identity is stronger

Fingerprint findings include `port_state`, `fingerprint_status`, `timed_out`, `candidate_services`, `matched_probes`, `version` (when detected via probe regex), and `proxy_likely` (when 3+ services match the same port) in metadata.

## Scan Modes

The `--mode` flag controls whether exploitation templates run during the auto-scan phase:

- **`detect`** (default): Only detection templates execute — passive checks for auth issues, version disclosure, config exposure, and enumeration. No payloads are sent.
- **`full`**: All matching templates execute, including active exploitation (command injection, SSRF, path traversal, inference abuse).

The console output clearly shows the active mode:

```
── Vulnerability Scan ───────────────────────────────────────
[*] Mode: Detection Only (no exploitation templates)
[*] Running templates against 5 service(s)
[*] Loaded 131 templates (85 detection, 46 exploit)
```

HTML reports include the scan mode in the engagement strip and adjust the executive summary language accordingly.

If no findings are emitted but some discovered services encountered scan errors, request errors, or template errors, `discover network` exits with a partial-failure status.

## Credential Chain-Loading

When scan findings contain credentials (Jupyter tokens, API keys, bearer tokens), they are automatically extracted and injected into workflow recommendations. The console shows a summary:

```
[*] Discovered 2 credential(s) for 2 target(s)
```

Workflow suggestions in the "Next Actions" section will include the discovered credentials:

```
── Next Actions ────────────────────────────────────────
  10.0.0.5:8888
    aipostex jupyter --target http://10.0.0.5:8888 --token abc123... enum
```

## Examples

```bash
# Scan a /24 subnet with default ports (default detect mode)
./aipostex discover network 10.0.0.0/24

# Full assessment including exploitation templates
./aipostex discover network 10.0.0.0/24 --mode full

# Same thing using --target flag
./aipostex discover network --target 10.0.0.0/24

# Scan specific host and ports
./aipostex discover network 127.0.0.1 --ports 11434,8000,8888

# Large CIDR with no host limit, through a proxy
./aipostex discover network --target 10.10.0.0/20 \
  --max-hosts 0 --proxy http://127.0.0.1:8080

# Scan without auto-running templates
./aipostex discover network --target 10.0.0.0/24 --auto-scan=false

# Stream results for long-running scans
./aipostex discover network --target 10.0.0.0/16 \
  --format jsonl --output findings.jsonl

# URL-format target (scheme stripped, port 8000 merged into scan list)
./aipostex discover network http://10.0.0.1:8000
```
