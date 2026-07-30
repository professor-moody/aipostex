# Writing Rules

This guide walks through creating custom file discovery rules for aipostex.

## Step 1: Create a Rule File

Create a YAML file with a `rules` list. Each file can contain multiple rules.

```yaml
rules:
  - name: "My Custom AI Credential"
    category: "ai-credentials"
    severity: "high"
    description: "Custom AI service API key found."
    file_patterns:
      - ".env"
      - "*.yaml"
    content_patterns:
      - 'MY_AI_KEY\s*[=:]\s*\S+'
```

## Step 2: Choose Matching Strategy

### Filename Only

Match files by name regardless of content. Good for well-known config file names.

```yaml
rules:
  - name: "Specific Config File"
    category: "mcp-config"
    severity: "high"
    file_patterns:
      - "claude_desktop_config.json"
      - "mcp.json"
```

### Path Pattern

Match files based on their full directory path. Good for files in known locations.

```yaml
rules:
  - name: "Hugging Face Cache Token"
    category: "ai-credentials"
    severity: "high"
    path_patterns:
      - "*/.cache/huggingface/token"
```

### Recursive Path Pattern

Use `**` to match files at any directory depth:

```yaml
rules:
  - name: "MCP Config Anywhere"
    category: "mcp-config"
    severity: "high"
    path_patterns:
      - "**/mcp.json"
      - "**/.cursor/mcp.json"
```

### Content Pattern

Match files containing specific strings or patterns. Good for credentials in arbitrary files.

```yaml
rules:
  - name: "Anthropic API Key"
    category: "ai-credentials"
    severity: "high"
    file_patterns:
      - ".env"
      - "*.py"
      - "*.js"
    content_patterns:
      - 'sk-ant-[a-zA-Z0-9\-]{20,}'
```

### Combined Matching

Combine file patterns with content patterns for precision. The file must match a file pattern AND a content pattern.

```yaml
rules:
  - name: "MCP Server Source Code"
    category: "mcp-config"
    severity: "medium"
    file_patterns:
      - "*.py"
      - "*.ts"
      - "*.js"
    content_patterns:
      - 'from mcp\.server import'
      - '@mcp\.tool'
      - 'McpServer\('
```

## Step 3: Write Content Patterns

Content patterns use Go RE2 regex syntax.

### Common Patterns

```yaml
# API key format: prefix + alphanumeric string
- 'sk-[a-zA-Z0-9]{20,}'

# Environment variable assignment
- 'MY_KEY\s*[=:]\s*\S+'

# JSON key-value
- '"apiKey"\s*:\s*"[^"]+"'

# Import statement
- 'from mcp\.server import'

# Connection string
- 'mongodb://[^\s]+'
```

### Pattern Tips

- Escape dots in regex: `mcp\.server` not `mcp.server`
- Use `\s*` for flexible whitespace around operators
- Use `[=:]` to match both assignment and YAML syntax
- Use `\S+` to match non-whitespace token values
- Keep patterns specific enough to avoid false positives

## Step 4: Test Your Rules

### Load custom rules alongside built-ins

```bash
./aipostex discover files --path /tmp/test-data --rules-dir ./my-rules
```

### Verbose output for debugging

```bash
./aipostex discover files --path /tmp/test-data --rules-dir ./my-rules --verbose
```

## Step 5: Organize Rules

Group related rules into themed YAML files:

```
my-rules/
├── custom_credentials.yaml    # API keys for internal services
├── internal_configs.yaml      # Internal tool configurations
└── data_artifacts.yaml        # Training data and model files
```

All `.yaml` files in the `--rules-dir` directory are loaded.

## File Size Considerations

Content patterns only scan the first `max_file_size` bytes (default 10MB). For large files like model weights, use `file_patterns` or `path_patterns` instead of `content_patterns`.

```yaml
rules:
  - name: "GGUF Model File"
    category: "local-llm"
    severity: "medium"
    file_patterns:
      - "*.gguf"
    # No content_patterns needed -- filename is sufficient
```

## Embedding Custom Rules

To include rules in the binary rather than loading from `--rules-dir`, see [Adding Templates](../development/adding-templates.md).
