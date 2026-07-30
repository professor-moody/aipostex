# Adding Templates & Rules

This guide covers adding new vulnerability templates and discovery rules, both as embedded assets and as operator-supplied files.

## Adding Embedded Templates

Embedded templates are compiled into the binary and available without `--templates-dir`.

### 1. Create the Template File

Add a YAML file under `pkg/vulncheck/templates/<category>/`:

```
pkg/vulncheck/templates/
├── a2a/
├── bentoml/
├── campaign/
├── gradio/
├── huggingface/
├── jupyter/
├── kubeflow/
├── langchain/
├── litellm/
├── mcp/
├── mlflow/
├── ollama/
├── openai/
├── ray/
├── tfserving/
├── torchserve/
├── triton/
├── vectordb/
├── vllm/
└── myservice/                  # new category
    └── myservice-auth-001-unauthenticated-api.yaml
```

### 2. Write the Template

Follow the [Template Format](../vuln-templates/format.md) specification:

```yaml
id: myservice-auth-001-unauthenticated-api
transport: http                    # default; use "mcp" for MCP stateful checks (see below)
info:
  name: "MyService - Unauthenticated API Access"
  type: detection                  # or "exploit" for active payloads
  severity: high
  author: aipostex
  description: |
    MyService is accessible without authentication.
  reference:
    - https://example.com/advisory
  tags: [myservice, auth, misconfiguration]

detect:
  - method: GET
    path: /api/status
    matchers:
      - type: body_contains
        value: "myservice"

checks:
  - name: "Data enumeration without auth"
    method: GET
    path: /api/data
    matchers:
      - type: status
        value: "200"
    severity: high
    finding:
      title: "MyService Unauthenticated Data Access"
      description: "Data endpoint is accessible without authentication."
      remediation: "Enable authentication."
```

### 3. Verify Embedding

The `embed.FS` directive in `pkg/vulncheck/templates_embed.go` automatically includes all files under `templates/`:

```go
//go:embed templates
var embeddedTemplates embed.FS
```

New subdirectories and files are included automatically -- no code changes needed.

!!! note "The `detect:` phase and `transport:`"
    The optional `detect:` block runs **before** `checks:` as a service gate — if no detect step
    matches, the template short-circuits and produces no findings, which is what keeps a template
    from firing against the wrong service. Set `transport: mcp` (instead of the default `http`) for
    templates that must drive a stateful Model Context Protocol handshake rather than raw HTTP; MCP
    checks dispatch on the JSON-RPC method in the check `body` (`tools/list` for detection,
    `tools/call` for the exploit path). See [Template Execution Model](../architecture/template-execution-model.md)
    for exactly how detect gating, matcher AND-logic, and transport dispatch work at runtime.

### 4. Test

```bash
# Verify the template loads
go run ./cmd/aipostex templates list | grep myservice

# View details
go run ./cmd/aipostex templates info myservice-auth-001-unauthenticated-api

# Run against a target
go run ./cmd/aipostex scan targets --target http://127.0.0.1:9000
```

### 5. Count Templates

```bash
make count-templates
```

## Adding Embedded Discovery Rules

Embedded rules are compiled into the binary and available without `--rules-dir`.

### 1. Create or Edit a Rule File

Add rules to an existing file or create a new YAML file under `pkg/discover/rules/`:

```
pkg/discover/rules/
├── api_keys.yaml
├── mcp_configs.yaml
├── local_llm.yaml
├── vectordb_rag.yaml
├── core_assessment.yaml
└── myservice.yaml          # new rule pack
```

### 2. Write Rules

Follow the [Rule Format](../rules/format.md) specification:

```yaml
rules:
  - name: "MyService Configuration"
    category: "myservice-config"
    severity: "high"
    description: "MyService configuration with credentials."
    file_patterns:
      - "myservice.yaml"
      - "myservice.json"
    content_patterns:
      - 'MYSERVICE_API_KEY\s*[=:]\s*\S+'
```

### 3. Verify Embedding

The `embed.FS` directive in `pkg/discover/rules_embed.go` automatically includes all files under `rules/`:

```go
//go:embed rules
var embeddedRules embed.FS
```

### 4. Test

```bash
# Create a test file
echo 'MYSERVICE_API_KEY=test123' > /tmp/test-myservice.yaml

# Run discovery
go run ./cmd/aipostex discover files --path /tmp --verbose
```

## Operator-Supplied Templates & Rules

Operators can supply additional templates and rules at runtime without rebuilding:

### Custom Templates

```bash
# Create a directory with custom templates
mkdir -p my-templates/custom/
cp my-template.yaml my-templates/custom/

# Run with custom templates
./aipostex scan targets --target http://target:9000 --templates-dir ./my-templates
./aipostex templates list --templates-dir ./my-templates
```

Custom templates load after embedded ones. If a custom template has the same ID as a built-in, the custom version takes precedence.

### Custom Rules

```bash
# Create a directory with custom rules
mkdir -p my-rules/
cp my-rules.yaml my-rules/

# Run with custom rules
./aipostex discover files --path /home/user --rules-dir ./my-rules
```

Custom rules load after embedded ones and are applied alongside them.

## Template ID Conventions

| Pattern | Example | Usage |
|---|---|---|
| `<service>-auth-NNN-<slug>` | `ollama-auth-001-unauthenticated-api` | Authentication issues |
| `<service>-enum-NNN-<slug>` | `mlflow-enum-002-artifact-surface` | Information exposure |
| `cve-YYYY-NNNNN-<slug>` | `cve-2025-65513-fetch-mcp-ssrf` | CVE-specific checks |
| `<campaign>-NNN-<slug>` | `bizarre-bazaar-001-llmjacking-validation` | Campaign emulation |

## Testing Checklist

- [ ] Template loads without errors (`templates list` command)
- [ ] Template details display correctly (`templates info <id>`)
- [ ] `type` field is set correctly (`detection` for passive, `exploit` for active payloads)
- [ ] Detect phase correctly gates execution
- [ ] Matchers produce findings on vulnerable targets
- [ ] Extractors populate variables correctly
- [ ] Finding text renders with interpolated values
- [ ] Tags enable correct filtering
- [ ] No false positives on unrelated services
- [ ] Exploit templates are skipped in `--mode detect` (default)
