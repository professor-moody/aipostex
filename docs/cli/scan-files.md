# discover files

Scan the filesystem for AI artifacts, credentials, and configuration files.

## Synopsis

```bash
aipostex discover files --path <directory> [flags]
```

## Description

The `discover files` command walks specified directories and matches files against YAML discovery rules. Rules can match on filename globs, path patterns (including `**` for recursive directory matching), and content regex patterns. It is designed to find:

- API keys (OpenAI, Anthropic, Hugging Face, Google, AWS, Pinecone, etc.)
- MCP configurations (Claude Desktop, VS Code, Cursor)
- Local LLM artifacts (GGUF models, Ollama configs, safetensors)
- Vector database data and configurations
- Fine-tuning datasets and RAG pipelines
- Jupyter AI notebooks

## Flags

| Flag | Short | Required | Default | Description |
|---|---|---|---|---|
| `--path` | `-p` | Yes | | Path(s) to scan. Can be specified multiple times. |
| `--rules-dir` | | No | *(none)* | Additional rules directory. Loaded after built-in rules. |

See [Common Flags](global-flags.md) for shared output and runtime controls.

## Excluded Directories

The following directories are skipped by default:

- `.git`
- `node_modules`
- `__pycache__`
- `venv` / `.venv`
- `.cache`
- `.npm` / `.yarn`
- `vendor`

## Summary Output

After scanning, a summary is printed to stderr with:

- Paths scanned
- Rules loaded
- Files considered
- Excluded/error skip counts
- Findings emitted

## Examples

```bash
# Scan a directory for AI artifacts
./aipostex discover files --path /tmp/loot

# Scan with JSON output to file
./aipostex discover files --path /home/user --format json --output findings.json

# Stealth scan with streaming JSONL output
./aipostex discover files --path /home/user --stealth --format jsonl --output findings.jsonl

# Scan multiple paths
./aipostex discover files --path /home/user --path /opt/ai-services

# Use custom rules alongside built-ins
./aipostex discover files --path /tmp/loot --rules-dir ./my-rules
```

## Path Canonicalization

When multiple `--path` values are provided, they are canonicalized before scanning:

1. Paths are cleaned (trailing slashes removed, `.` resolved)
2. Exact duplicates are removed
3. Paths that are subdirectories of another provided path are subsumed (e.g., `/loot` and `/loot/subdir` becomes just `/loot`)

This prevents duplicate findings from overlapping scan roots.

## Rule Loading

1. Built-in rules are loaded from the embedded `embed.FS`
2. If `--rules-dir` is specified, rules from that directory are loaded after embedded rules
3. Invalid glob patterns in rules are rejected at load time with a descriptive error
4. All rules are applied to every file encountered during the walk
