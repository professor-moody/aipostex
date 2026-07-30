# Installation

## Prerequisites

- **Go 1.25+** ([download](https://go.dev/dl/))
- **Git** (to clone the repository)
- **Make** (optional, for build targets)

## Build from Source

```bash
git clone https://github.com/professor-moody/aipostex.git
cd aipostex
make build
```

The binary is output to `bin/aipostex`. The build uses `CGO_ENABLED=0` for a fully static binary with no external dependencies.

Version and build timestamp are embedded via linker flags automatically.

## Direct Go Build

If you prefer not to use Make:

```bash
go build ./cmd/aipostex
```

This produces an `aipostex` binary in the current directory without version metadata.

## Cross-Compilation

Build for all supported platforms at once:

```bash
make build-all
```

This produces binaries in `bin/`:

| Platform | Binary |
|---|---|
| Linux (amd64) | `aipostex-linux-amd64` |
| Linux (arm64) | `aipostex-linux-arm64` |
| macOS (amd64) | `aipostex-darwin-amd64` |
| macOS (arm64) | `aipostex-darwin-arm64` |
| Windows (amd64) | `aipostex-windows-amd64.exe` |

All cross-compiled binaries are statically linked (`CGO_ENABLED=0`).

## Verify Installation

```bash
./bin/aipostex version
```

Expected output:

```
aipostex <version> (built <timestamp>)
```

## Embedded Assets

aipostex compiles all built-in vulnerability templates and file discovery rules into the binary using Go's `embed.FS`. No external template or rule files are required to run.

Operator-supplied templates and rules can be layered on top at runtime via `--templates-dir` and `--rules-dir`.
