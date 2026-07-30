# Contributing

## Prerequisites

- Go 1.25+
- `golangci-lint` (for linting)
- Make (for build targets)

## Building

```bash
# Standard build
make build
# Output: bin/aipostex

# Cross-compile all platforms
make build-all
# Output: bin/aipostex-{linux,darwin,windows}-{amd64,arm64}

# Direct Go build (without version metadata)
go build ./cmd/aipostex
```

The Makefile embeds version and build time via linker flags:

```makefile
LDFLAGS=-ldflags "-s -w -X .../config.Version=$(VERSION) -X .../config.BuildTime=$(BUILD_TIME)"
```

## Testing

```bash
# Full test suite with race detector
make test

# Short tests (skip long-running tests)
make test-short

# Run specific package tests
go test -v ./pkg/vulncheck/...
go test -v ./cmd/aipostex/...
```

### Test Patterns

Tests follow Go conventions. Key patterns in this codebase:

- **CLI tests** (`cmd/aipostex/*_test.go`): Test command registration, flag validation, force-exploit gating, and summary output
- **Engine tests** (`pkg/vulncheck/*_test.go`, `pkg/discover/*_test.go`): Test template loading, rule matching, and scan behavior
- **Client tests** (`pkg/exploit/*_test.go`): Test client construction, request building, and response parsing
- **Integration tests**: `make test-lab` runs against localhost on common AI ports (requires local services)

### Test Lab

Run against local AI services for integration testing:

```bash
make test-lab
```

This runs `discover network` against `127.0.0.1` on ports `11434,8000,6333,8888`.

## Linting

```bash
make lint    # golangci-lint run ./...
make fmt     # gofmt -s -w .
make vet     # go vet ./...
```

## Project Layout

```
cmd/aipostex/          CLI commands, orchestration, workflow generators
internal/assessment/    Finding dedup, canonical URLs, severity stats
internal/config/        Runtime configuration
internal/enrichment/    Proof classification, artifact labeling
internal/output/        Output formatters (console, JSON, JSONL, CSV, HTML, SARIF, Markdown, PDF)
internal/reportgen/     Narrative report generation
internal/runtimehttp/   HTTP transport (proxy, stealth, TLS)
pkg/discover/          File discovery engine + YAML rules
pkg/fingerprint/       Network service fingerprinting + honeypot detection
pkg/stringutil/        String coherence scoring
pkg/vulncheck/         Template engine + YAML vuln templates
pkg/exploit/           Post-exploitation client libraries
pkg/report/            Finding schema
```

### Package Dependency Rules

- `cmd/aipostex/` imports everything
- `pkg/exploit/*` imports `pkg/report`, `pkg/exploit/common`, and `internal/runtimehttp`
- `pkg/vulncheck` imports `pkg/report` and `internal/runtimehttp`
- `pkg/discover` imports `pkg/report`
- `pkg/fingerprint` imports `internal/runtimehttp`
- `internal/output` imports `pkg/report`
- `pkg/stringutil` has no internal dependencies
- `pkg/report` has no internal dependencies

## Code Style

- Standard Go formatting (`gofmt`)
- No exported API without doc comments
- Error wrapping with `fmt.Errorf("context: %w", err)`
- Context propagation for cancellable operations
- Table-driven tests where appropriate

## Adding Functionality

See these guides for common contribution types:

- [Adding Modules](adding-modules.md) -- new exploit module end-to-end
- [Adding Templates](adding-templates.md) -- new vuln templates or discovery rules
