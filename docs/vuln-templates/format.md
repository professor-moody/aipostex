# Template Format

Vulnerability templates are YAML files that define HTTP-based checks against AI services. They follow a detect-then-check pattern with optional detection probes, matchers, and extractors.

## Schema

```yaml
id: <unique-template-id>
info:
  name: "Human-readable name"
  type: detection|exploit            # Optional, defaults to detection
  severity: critical|high|medium|low|info
  cvss: 9.3                          # Optional CVSS score
  author: aipostex                   # Template author
  description: |                     # Multi-line description
    Detailed explanation of the vulnerability.
  reference:                         # Optional reference URLs
    - https://example.com/advisory
  tags: [tag1, tag2, tag3]           # Filterable tags
  classification:                    # Optional MITRE mapping
    mitre-atlas: [AML.T0049]

detect:                              # Optional detection phase
  - method: GET
    path: /
    matchers:
      - type: body_contains
        value: "expected string"

checks:                              # One or more vulnerability checks
  - name: "Check description"
    method: GET|POST
    path: /api/endpoint
    headers:                         # Optional request headers
      Content-Type: application/json
    body: '{"key": "value"}'         # Optional request body
    matchers:                        # All must match for a finding
      - type: status
        value: "200"
      - type: body_contains
        value: "\"models\":["
    extractors:                      # Optional data extraction
      - type: json
        name: variable_name
        path: "models.#"
    severity: high                   # Check-level severity override
    finding:                         # Output finding when matched
      title: "Title with {{variable_name}}"
      description: "Description with {{variable_name}}"
      remediation: "How to fix this."
      evidence: "Optional evidence text"
```

## Top-Level Fields

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Unique template identifier. Convention: `<service>-<type>-<number>-<slug>` |
| `info` | Yes | Template metadata block |
| `detect` | No | Pre-check steps to confirm target type before running checks |
| `checks` | Yes | Vulnerability check steps |

## Info Block

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Human-readable template name |
| `type` | No | Template type: `detection` (default) or `exploit`. Controls whether the template runs in detect-only mode. |
| `severity` | Yes | Default severity: `critical`, `high`, `medium`, `low`, `info` |
| `cvss` | No | CVSS score (float) |
| `author` | Yes | Template author |
| `description` | No | Detailed vulnerability description |
| `reference` | No | List of reference URLs |
| `tags` | No | List of tags for filtering |
| `classification` | No | MITRE ATLAS or other framework mapping |

### Template Types

Templates are classified as **detection** or **exploit** via the `type` field:

- **`detection`** (default): Passive checks — auth enumeration, version disclosure, config exposure, DNS rebinding probes, tool listing. These run in all scan modes.
- **`exploit`**: Active exploitation — command injection, SSRF, path traversal, file reads, inference abuse. These only run when `--mode full` is specified.

Templates without a `type` field default to `detection`, maintaining backwards compatibility with custom templates.

## Detect Steps

The `detect` block is optional. If present, all detect steps must match for the template's checks to execute. This prevents running irrelevant checks against unrelated services.

Each detect step is an HTTP request with matchers (same format as check matchers).

## Check Steps

Each check defines an HTTP request, matchers that must all pass, optional extractors, and a finding to emit on match.

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Check description |
| `method` | Yes | HTTP method: `GET`, `POST`, etc. |
| `path` | Yes | URL path (appended to target) |
| `headers` | No | Request headers map |
| `body` | No | Request body string. If set but no `Content-Type` header is provided, the engine defaults to `application/json` for JSON-like bodies (starting with `{` or `[`) and `application/x-www-form-urlencoded` otherwise. |
| `matchers` | Yes | List of matchers (all must pass) |
| `extractors` | No | List of data extractors |
| `severity` | No | Override the template-level severity for this check |
| `finding` | Yes | Finding template for output |

## Matcher Types

| Type | Value | Behavior |
|---|---|---|
| `status` | HTTP status code as string | Response status must equal value |
| `body_contains` | String | Response body must contain value |
| `body_not_contains` | String | Response body must not contain value |
| `body_regex` | Regex pattern | Response body must match pattern |
| `header_contains` | String | Response headers must contain value |
| `json_path` | gjson path + value | JSON path must exist; if value is non-empty, must match |

All matchers in a check use AND logic -- every matcher must pass for the check to produce a finding.

### json_path Matcher

The `json_path` matcher uses [gjson](https://github.com/tidwall/gjson) syntax:

```yaml
matchers:
  - type: json_path
    key: "models.#"        # gjson path expression
    value: ""              # empty = just check existence
```

Common gjson patterns:

- `models.#` -- array length
- `models.0.name` -- first model name
- `version` -- top-level field

## Extractor Types

Extractors pull data from responses into named variables for use in finding templates.

### json

Extract a value using a gjson path:

```yaml
extractors:
  - type: json
    name: model_count
    path: "models.#"
```

### regex

Extract a value using a regex capture group:

```yaml
extractors:
  - type: regex
    name: version
    regex: '"version":"([^"]+)"'
    group: 1
```

### header

Extract a value from a response header:

```yaml
extractors:
  - type: header
    name: server_header
    key: "Server"
```

## Variable Interpolation

Extracted values are available as `{{variable_name}}` in finding fields:

```yaml
finding:
  title: "Ollama Unauthenticated - {{model_count}} Models Exposed"
  description: "Models include: {{first_model}}"
```

Variables are interpolated in `title`, `description`, `remediation`, and `evidence` fields.

## Complete Example

```yaml
id: ollama-auth-001-unauthenticated-api
info:
  name: "Ollama - Unauthenticated API Access"
  severity: high
  author: aipostex
  description: |
    Ollama instance is accessible without authentication. An attacker can
    enumerate models, extract system prompts, execute inference, and
    potentially create or delete models.
  reference:
    - https://vulnerablemcp.info/
  tags: [ollama, auth, misconfiguration, llmjacking]
  classification:
    mitre-atlas: [AML.T0049, AML.T0034, AML.T0040]

detect:
  - method: GET
    path: /
    matchers:
      - type: body_contains
        value: "Ollama is running"

checks:
  - name: "Model enumeration without authentication"
    method: GET
    path: /api/tags
    matchers:
      - type: status
        value: "200"
      - type: body_contains
        value: "models"
    extractors:
      - type: json
        name: model_count
        path: "models.#"
      - type: json
        name: first_model
        path: "models.0.name"
    severity: high
    finding:
      title: "Ollama Unauthenticated - {{model_count}} Models Exposed"
      description: "Ollama API is accessible without authentication. Models available include: {{first_model}}."
      remediation: "Enable authentication via reverse proxy, bind to localhost only, or implement network-level access controls."

  - name: "Version disclosure"
    method: GET
    path: /api/version
    matchers:
      - type: status
        value: "200"
    extractors:
      - type: json
        name: ollama_version
        path: "version"
    severity: info
    finding:
      title: "Ollama Version Disclosed: {{ollama_version}}"
      description: "Ollama version {{ollama_version}} is exposed."
```
