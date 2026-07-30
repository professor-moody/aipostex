# Common Flags

These flags are shared by command families, not every command at the root.

- `discover network`, `scan targets`, and `assess network` share output, HTTP/runtime, and concurrency controls.
- `discover files` shares output plus local concurrency and stealth controls.
- Service modules share output and HTTP/runtime controls, and mutating module actions use `--force-exploit`.
- The operator console (`request`, `shell`) accepts the standard `--target`/`--header`/`--api-key` plus output and network flags; the execution shells also honor `--force-exploit`.

## Output Control

| Flag | Short | Default | Description |
|---|---|---|---|
| `--output` | `-o` | *(stdout)* | Output file path. When omitted, findings write to stdout. |
| `--format` | `-f` | `console` | Output format: `console`, `json`, `jsonl`, `csv`, `html`, `sarif`, `markdown` (or `md`), `pdf` (requires Chrome; use `--output`). |
| `--verbose` | `-v` | `false` | Enable verbose output with extended descriptions and evidence. |

## Network & Transport

| Flag | Default | Description |
|---|---|---|
| `--timeout` | `10s` | HTTP request timeout. |
| `--fingerprint-timeout` | `10s` | Per-port fingerprinting budget for `discover network` and `assess network`. TCP-open ports remain visible even if fingerprinting times out. |
| `--proxy` | *(none)* | Proxy URL. Supports `http://`, `https://`, and `socks5://` schemes. Applied to all HTTP requests and WebSocket connections. |
| `--insecure` | `false` | Skip TLS certificate verification for HTTPS targets. |

## Concurrency & Stealth

| Flag | Default | Description |
|---|---|---|
| `--concurrency` | `10` | Number of parallel workers for scanning and fingerprinting. Must be >= 1. |
| `--stealth` | `false` | OPSEC mode: caps concurrency to 1, adds 1-5s random jitter per request, rotates User-Agent headers. |
| `--max-hosts` | `65536` | Maximum hosts to scan in `discover network` or `assess network` CIDR expansion. Set to `0` to disable the guardrail. Large IPv6 CIDRs (63+ host bits) are rejected before expansion to prevent overflow. |

## Safety

| Flag | Default | Description |
|---|---|---|
| `--force-exploit` | `false` | Enable mutating and high-noise exploit actions. Required for commands that modify target state (model poisoning, code execution, file uploads, etc.). |

!!! warning
    `--yes-i-mean-it` is a deprecated alias for `--force-exploit`. It is hidden from help output but still accepted.

## Usage Examples

```bash
# Write JSON output to a file through a SOCKS5 proxy
./aipostex scan targets --target http://10.0.0.5:11434 \
  --format json --output findings.json \
  --proxy socks5://127.0.0.1:1080

# Stealth scan with verbose output
./aipostex discover network --target 10.0.0.0/24 \
  --stealth --verbose

# Skip TLS verification for HTTPS targets
./aipostex scan targets --target https://10.0.0.10:8443 --insecure

# Stream JSONL for a long-running network scan
./aipostex discover network --target 10.0.0.0/16 \
  --format jsonl --output findings.jsonl --max-hosts 0
```
