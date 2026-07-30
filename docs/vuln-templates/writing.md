# Writing Templates

This guide walks through creating a custom vulnerability template for aipostex.

## Step 1: Choose an ID

Template IDs follow the convention: `<service>-<type>-<number>-<description>`

- `service`: target service (e.g., `ollama`, `mcp`, `jupyter`)
- `type`: finding type (e.g., `auth`, `enum`, `cve`)
- `number`: sequential number within the service/type
- `description`: short kebab-case slug

Example: `myservice-auth-001-unauthenticated-api`

## Step 2: Define the Info Block

```yaml
id: myservice-auth-001-unauthenticated-api
info:
  name: "MyService - Unauthenticated API Access"
  type: detection                    # or "exploit" for active payloads
  severity: high
  author: your-name
  description: |
    MyService API is accessible without authentication.
  reference:
    - https://example.com/advisory
  tags: [myservice, auth, misconfiguration]
```

The `type` field determines when the template runs:

- **`detection`** (default): Runs in both `--mode detect` and `--mode full`. Use for passive checks (GET requests, auth probes, version disclosure).
- **`exploit`**: Only runs in `--mode full`. Use when the template sends active payloads (command injection, SSRF, inference requests, file reads via tool invocation).

## Step 3: Add Detection (Optional)

The `detect` block prevents your template from running against unrelated services. Add it when the check paths might return false positives on other services.

```yaml
detect:
  - method: GET
    path: /
    matchers:
      - type: body_contains
        value: "MyService is running"
```

!!! tip
    If your checks are specific enough (unique paths, unique response bodies), you can skip the `detect` block.

## Step 4: Write Checks

Each check sends an HTTP request and verifies the response with matchers.

### Basic Status Check

```yaml
checks:
  - name: "API accessible without auth"
    method: GET
    path: /api/status
    matchers:
      - type: status
        value: "200"
    severity: high
    finding:
      title: "MyService Unauthenticated API"
      description: "The API responded with 200 without credentials."
      remediation: "Enable authentication."
```

### POST with Body

```yaml
checks:
  - name: "RPC endpoint accepts commands"
    method: POST
    path: /rpc
    headers:
      Content-Type: application/json
    body: '{"method": "list", "id": 1}'
    matchers:
      - type: status
        value: "200"
      - type: body_contains
        value: "result"
    finding:
      title: "MyService RPC Accepts Unauthenticated Commands"
      description: "The RPC endpoint processes commands without auth."
```

### Negative Matching

Use `body_not_contains` to ensure blocked or error patterns are absent:

```yaml
matchers:
  - type: status
    value: "200"
  - type: body_not_contains
    value: "unauthorized"
  - type: body_not_contains
    value: "blocked"
```

### JSON Path Matching

Use `json_path` with gjson syntax to check response structure:

```yaml
matchers:
  - type: json_path
    key: "data.#"
    value: ""          # empty = just verify the path exists
```

### Regex Matching

```yaml
matchers:
  - type: body_regex
    value: "version.*[0-9]+\\.[0-9]+"
```

## Step 5: Add Extractors

Extractors pull values from responses for use in finding text.

### JSON Extractor

```yaml
extractors:
  - type: json
    name: item_count
    path: "items.#"
  - type: json
    name: first_item
    path: "items.0.name"
```

### Regex Extractor

```yaml
extractors:
  - type: regex
    name: version
    regex: '"version":"([^"]+)"'
    group: 1
```

## Step 6: Use Variables in Findings

Reference extracted values with `{{name}}`:

```yaml
finding:
  title: "MyService Exposed - {{item_count}} Items"
  description: "Found {{item_count}} items including {{first_item}}."
  remediation: "Restrict API access."
```

## Step 7: Test Your Template

### List to verify it loads

```bash
./aipostex templates --templates-dir ./my-templates
```

### View details

```bash
./aipostex templates info myservice-auth-001-unauthenticated-api \
  --templates-dir ./my-templates
```

### Run against a target

```bash
./aipostex scan targets --target http://127.0.0.1:9000 \
  --templates-dir ./my-templates
```

## Multi-Check Templates

A single template can have multiple checks at different severity levels:

```yaml
checks:
  - name: "Data enumeration"
    method: GET
    path: /api/data
    matchers:
      - type: status
        value: "200"
    severity: high
    finding:
      title: "Data Exposed"
      description: "Data endpoint is accessible."

  - name: "Version disclosure"
    method: GET
    path: /api/version
    matchers:
      - type: status
        value: "200"
    severity: info
    finding:
      title: "Version Disclosed"
      description: "Version information is accessible."
```

## Embedding Custom Templates

To include templates in the binary rather than loading from `--templates-dir`, see [Adding Templates](../development/adding-templates.md).

## Template Tips

- Use `detect` to prevent false positives on unrelated services
- Order checks from most to least severe
- Extract useful values for reporting context
- Write actionable remediation guidance
- Tag templates consistently for filtering
- Test against real and mock services before submitting
