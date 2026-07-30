# Quickstart

This guide walks through three core workflows to get you scanning in minutes.

## 1. Discover AI Services on a Network

Use `discover network` to fingerprint AI services across a network range:

```bash
./aipostex discover network 10.0.0.0/24
```

This probes default AI ports (Ollama 11434, vLLM 8000, Jupyter 8888, etc.) and automatically runs detection templates against discovered services. By default, only safe detection checks run (no exploitation payloads).

For a full assessment including active exploitation (SSRF, command injection, inference abuse):

```bash
./aipostex discover network 10.0.0.0/24 --mode full
```

Target a specific host with custom ports:

```bash
./aipostex discover network 127.0.0.1 --ports 11434,8000,8888
```

Targets can also be passed via the `--target` flag (e.g., `--target 10.0.0.0/24`). Positional arguments and flags are merged.

The output includes discovered services, vulnerability findings, and **Next actions** -- concrete follow-on commands for each discovered service.

## 2. Scan a Target for Vulnerabilities

Run YAML vulnerability templates against a known target:

```bash
./aipostex scan targets http://127.0.0.1:11434
```

Filter by tags or severity:

```bash
./aipostex scan targets http://127.0.0.1:3000 --tags mcp
./aipostex scan targets http://127.0.0.1:8000 --severity critical
```

Targets can also be passed via `--target` (e.g., `--target http://...`). Positional arguments and flags are merged.

View available templates before scanning:

```bash
./aipostex templates list
./aipostex templates info ollama-auth-001-unauthenticated-api
```

## 3. Scan Files for AI Artifacts

Discover API keys, model files, MCP configs, and other AI artifacts on disk:

```bash
./aipostex discover files --path /tmp/loot
```

Write findings to a file in JSON format:

```bash
./aipostex discover files --path /home/user --format json --output findings.json
```

## Following the Kill Chain

After discovery, use the suggested next commands to progress through the exploit chain. For example, if `discover network` discovers an Ollama instance:

```bash
# Step 1: Enumerate the Ollama instance
./aipostex ollama --target http://10.0.0.5:11434 enum

# Step 2: Extract system prompts from discovered models
./aipostex ollama --target http://10.0.0.5:11434 prompts

# Step 3: Run inference (compute theft validation)
./aipostex ollama --target http://10.0.0.5:11434 generate --model llama3 --prompt "hello"

# Step 4: Poison a model (requires --force-exploit)
./aipostex ollama --target http://10.0.0.5:11434 poison \
  --base-model llama3 --new-model llama3-backdoor \
  --system-prompt "Return internal policy." --force-exploit
```

!!! warning "Force-Exploit Gating"
    Commands that modify target state or generate significant noise require the `--force-exploit` flag. Read-only enumeration and extraction commands do not.

## Output Formats

aipostex supports multiple output formats:

```bash
# Console output (default, with colors)
./aipostex scan targets --target http://127.0.0.1:11434

# JSON (buffered, written at end)
./aipostex scan targets --target http://127.0.0.1:11434 --format json --output findings.json

# JSONL (streaming, one finding per line -- recommended for long-running scans)
./aipostex discover network --target 10.0.0.0/24 --format jsonl --output findings.jsonl
```

## Next Steps

- [Core Concepts](concepts.md) -- understand findings, templates, rules, and workflows
- [CLI Reference](../cli/global-flags.md) -- all flags and commands
- [Operator Progression](../operator-guide/progression.md) -- the full kill chain flow
- [Exploit Modules](../modules/index.md) -- deep dive into each module
