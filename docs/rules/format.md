# Rule Format

Discovery rules are YAML files that define patterns for finding AI artifacts on the filesystem. The `discover files` command loads rules and walks specified directories, matching each file against all loaded rules.

## Schema

```yaml
rules:
  - name: "Rule Name"
    category: "ai-credentials"
    severity: "high"
    description: "What this rule detects and why it matters."
    file_patterns:
      - ".env"
      - "*.yaml"
      - "*.json"
    path_patterns:
      - "*/.config/Claude/*"
      - "*/AppData/Roaming/Claude/*"
    content_patterns:
      - 'sk-[a-zA-Z0-9]{20,}'
      - 'OPENAI_API_KEY\s*[=:]\s*\S+'
    max_file_size: 10485760
```

## Fields

| Field | Required | Default | Description |
|---|---|---|---|
| `name` | Yes | | Human-readable rule name |
| `category` | Yes | | Rule category for grouping |
| `severity` | Yes | | Finding severity: `critical`, `high`, `medium`, `low`, `info` |
| `description` | No | | What this rule detects and its security impact |
| `file_patterns` | No | | Glob patterns matched against the filename (basename only) |
| `path_patterns` | No | | Glob patterns matched against the full file path |
| `content_patterns` | No | | Regex patterns matched against file contents |
| `max_file_size` | No | 10485760 (10MB) | Maximum bytes to read for content pattern matching |

!!! note
    At least one of `file_patterns`, `path_patterns`, or `content_patterns` must be specified for a rule to match anything.

## Matching Behavior

A file matches a rule when **any** of these conditions is true:

1. The filename matches any `file_patterns` glob
2. The full path matches any `path_patterns` glob
3. The file content matches any `content_patterns` regex (up to `max_file_size` bytes)

When both `file_patterns` and `content_patterns` are specified, the file must match at least one file pattern AND at least one content pattern.

## Categories

Built-in rules use these categories:

| Category | Description |
|---|---|
| `ai-credentials` | API keys and tokens for AI services |
| `mcp-config` | MCP server configuration files |
| `local-llm` | Local LLM artifacts and configurations |
| `vectordb` | Vector database data and configurations |
| `core-assessment` | Fine-tuning data, RAG configs, LLMjacking indicators |

## Pattern Types

### File Patterns

Glob patterns matched against the filename only (not the full path):

```yaml
file_patterns:
  - ".env"           # exact filename
  - ".env.*"         # .env.local, .env.production, etc.
  - "*.yaml"         # any YAML file
  - "*.gguf"         # GGUF model files
  - "token"          # exact filename
```

### Path Patterns

Glob patterns matched against the full file path:

```yaml
path_patterns:
  - "*/.cache/huggingface/token"
  - "*/.config/Claude/*"
  - "*/.ollama/models/*"
  - "**/config/mcp.json"        # ** matches any directory depth
```

`**` is supported for recursive directory matching. Invalid glob patterns are rejected when rules are loaded.

### Content Patterns

Regex patterns matched against file contents:

```yaml
content_patterns:
  - 'sk-[a-zA-Z0-9]{20,}'                    # OpenAI key format
  - 'OPENAI_API_KEY\s*[=:]\s*\S+'            # env variable assignment
  - '"mcpServers"'                             # MCP config marker
  - 'from mcp\.server import'                 # MCP server code
```

Content patterns use Go's `regexp` syntax (RE2).

## Complete Example

```yaml
rules:
  - name: "OpenAI API Key"
    category: "ai-credentials"
    severity: "high"
    description: "OpenAI API key found in file. Can be used for unauthorized inference, billing fraud, or data access."
    file_patterns:
      - ".env"
      - ".env.*"
      - "*.cfg"
      - "*.yaml"
      - "*.yml"
      - "*.json"
      - "*.py"
    content_patterns:
      - 'sk-[a-zA-Z0-9]{20,}'
      - 'OPENAI_API_KEY\s*[=:]\s*\S+'

  - name: "Claude Desktop MCP Config"
    category: "mcp-config"
    severity: "high"
    description: "Claude Desktop MCP configuration found. Contains server definitions and potentially API tokens."
    file_patterns:
      - "claude_desktop_config.json"
    path_patterns:
      - "*/Claude/*"
      - "*/.config/Claude/*"
      - "*/AppData/Roaming/Claude/*"
```
