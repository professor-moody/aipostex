# templates list / info

List and inspect vulnerability templates.

## templates list

### Synopsis

```bash
aipostex templates list [flags]
```

### Description

Lists all loaded vulnerability templates with their severity, ID, name, and tags. Templates are grouped by category: MCP, Ollama, vector databases, Jupyter, OpenAI-compatible, Ray, MLflow, Gradio, campaign, and other.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--tags` | *(all)* | Filter templates by tag. |
| `--templates-dir` | *(none)* | Additional templates directory. |

### Examples

```bash
# List all templates
./aipostex templates list

# List MCP-related templates
./aipostex templates list --tags mcp

# List templates including custom directory
./aipostex templates list --templates-dir ./my-templates

# Verbose output shows source file paths
./aipostex templates list --verbose
```

### Output

Templates are displayed in a table grouped by category:

```
Category: ollama
  [HIGH] ollama-auth-001-unauthenticated-api  Ollama - Unauthenticated API Access  [ollama, auth, misconfiguration]
  [INFO] ollama-enum-002-system-prompt-extraction  Ollama - System Prompt Extraction  [ollama, prompt]

Category: mcp
  [HIGH] mcp-auth-001-unauthenticated-sse  MCP - Unauthenticated SSE  [mcp, auth]
  ...
```

---

## templates info

### Synopsis

```bash
aipostex templates info <template-id> [flags]
```

### Description

Shows detailed information for a single template identified by its exact ID. Displays metadata, detect steps, and check details including matchers and severity.

### Arguments

| Argument | Required | Description |
|---|---|---|
| `<template-id>` | Yes | The exact template ID (e.g., `ollama-auth-001-unauthenticated-api`). |

### Flags

| Flag | Default | Description |
|---|---|---|
| `--templates-dir` | *(none)* | Additional templates directory. |

### Examples

```bash
# View template details
./aipostex templates info ollama-auth-001-unauthenticated-api

# View a CVE template
./aipostex templates info cve-2025-65513-fetch-mcp-ssrf

# Include custom templates in lookup
./aipostex templates info my-custom-template --templates-dir ./my-templates
```

### Output

```
Template: ollama-auth-001-unauthenticated-api
  Name:      Ollama - Unauthenticated API Access
  Severity:  high
  Author:    aipostex
  Tags:      ollama, auth, misconfiguration, llmjacking
  References:
    - https://vulnerablemcp.info/
    - https://www.pillar.security/blog/operation-bizarre-bazaar

  Description:
    Ollama instance is accessible without authentication...

  Detect Steps: 1
    [1] GET /

  Checks: 3
    [1] Model enumeration without authentication  (high)
        GET /api/tags
    [2] Version disclosure  (info)
        GET /api/version
    [3] Running models disclosure  (medium)
        GET /api/ps
```
