# OPSEC & Stealth

aipostex includes operational security features for engagements where detection avoidance matters.

## Stealth Mode

Enable with `--stealth`:

```bash
./aipostex discover network --target 10.0.0.0/24 --stealth
```

Stealth mode applies three controls:

### Request Jitter

Each HTTP request is delayed by a random 1-5 second interval before being sent. This prevents burst patterns that trigger rate limiting or IDS alerts.

### User-Agent Rotation

When no User-Agent header is explicitly set, stealth mode rotates through 10 browser User-Agent strings covering Chrome, Firefox, Edge, Safari, and Opera across macOS, Windows, and Linux:

- Chrome on macOS, Windows, Linux
- Firefox on macOS, Windows, Linux
- Edge on Windows, Linux
- Safari on macOS
- Opera on Windows

This avoids fingerprinting based on consistent or unusual User-Agent headers.

### Default User-Agent (Non-Stealth)

Even without `--stealth`, fingerprint probe requests set a default browser User-Agent header.
Some AI services and WAFs reject requests without a User-Agent, so this is always applied unless
the probe defines its own.

### Concurrency Caps

Stealth mode caps all concurrency to 1:

- `discover network` / `assess network` uses 1 concurrent probe
- `scan targets` uses 1 concurrent template
- `discover files` uses 1 concurrent file walker
- Exploit modules use 1 concurrent request

## Proxy Support

Route all traffic through a proxy with `--proxy`:

```bash
# HTTP proxy
./aipostex scan targets --target http://10.0.0.5:11434 \
  --proxy http://127.0.0.1:8080

# HTTPS proxy
./aipostex scan targets --target https://10.0.0.5:8443 \
  --proxy https://proxy.internal:8443

# SOCKS5 proxy
./aipostex discover network --target 10.0.0.0/24 \
  --proxy socks5://127.0.0.1:1080
```

Proxy support covers:

- All HTTP/HTTPS requests (scan, fingerprint, exploit modules)
- WebSocket connections (Jupyter kernel execution)
- All three schemes: `http://`, `https://`, `socks5://`

!!! tip
    For Burp Suite interception, use `--proxy http://127.0.0.1:8080 --insecure`.

## TLS Verification

Skip TLS certificate verification with `--insecure`:

```bash
./aipostex scan targets --target https://10.0.0.10:8443 --insecure
```

This sets `InsecureSkipVerify` on the TLS configuration for:

- HTTP client connections
- WebSocket dialer connections

Useful for:

- Targets with self-signed certificates
- Internal CA environments
- Proxy interception (Burp, mitmproxy)

## CIDR Size Guardrails

The `--max-hosts` flag prevents accidentally scanning massive ranges:

```bash
# Default: max 65536 hosts
./aipostex discover network --target 10.0.0.0/8
# Error: CIDR range expands to more than 65536 hosts

# Disable the guardrail
./aipostex discover network --target 10.0.0.0/8 --max-hosts 0
```

## Signal Handling

Ctrl+C (SIGINT) is handled cleanly:

- In-flight HTTP requests are cancelled via `context.Context`
- Findings already written are preserved in the output file
- The output file is properly closed (important for JSON format)

This means you can safely cancel a long-running scan and still use the partial results.

## Output Separation

| Stream | Content |
|---|---|
| stdout | Findings only (never progress or diagnostic output) |
| stderr | Progress, warnings, blocked exploit messages, summaries |

This separation ensures:

- Clean piping of findings to `jq`, `grep`, or other tools
- Progress visibility even when findings write to a file
- No accidental leakage of diagnostic data into finding output

## OPSEC Recommendations

### Low-Noise Reconnaissance

```bash
# Stealth network scan with JSONL output
./aipostex discover network --target 10.0.0.0/24 \
  --stealth --format jsonl --output recon.jsonl

# Stealth file scan
./aipostex discover files --path /home/user \
  --stealth --format jsonl --output files.jsonl
```

### Proxied Exploitation

```bash
# Route through SOCKS5 with TLS skip
./aipostex ollama --target https://10.0.0.5:11434 enum \
  --proxy socks5://127.0.0.1:1080 --insecure
```

### Long-Running Scans

```bash
# Use JSONL for crash recovery on large ranges
./aipostex discover network --target 10.0.0.0/16 \
  --max-hosts 0 --format jsonl --output full-scan.jsonl
```

If interrupted, `full-scan.jsonl` contains all findings emitted before cancellation.
