# Adding Modules

This guide walks through adding a new post-exploitation module to aipostex.

## Overview

A new module requires changes in three layers:

1. **Client library** in `pkg/exploit/<module>/`
2. **CLI commands** in `cmd/aipostex/<module>.go`
3. **Tests** in both layers

## Step 1: Create the Client Library

Create a new directory under `pkg/exploit/`:

```
pkg/exploit/myservice/
├── client.go
└── client_test.go
```

### Client Structure

Follow the established pattern from existing modules:

```go
package myservice

import (
    "context"
    "net/http"
    "time"

    "github.com/professor-moody/aipostex/pkg/exploit/common"
)

type Client struct {
    baseURL string
    client  *http.Client
    headers http.Header
    ctx     context.Context
}

func NewClient(ctx context.Context, baseURL string, timeout time.Duration, headers http.Header) (*Client, error) {
    httpClient, err := common.NewHTTPClient(timeout)
    if err != nil {
        return nil, err
    }
    return &Client{
        baseURL: common.NormalizeTarget(baseURL),
        client:  httpClient,
        headers: headers,
        ctx:     ctx,
    }, nil
}
```

### Read Methods

Implement enumeration and data extraction methods:

```go
func (c *Client) Enumerate() (*EnumResult, error) {
    // ...
}

func (c *Client) ListItems() ([]Item, error) {
    // ...
}
```

### Write Methods

Implement state-changing methods (these will be gated at the CLI layer):

```go
func (c *Client) Execute(payload string) (*ExecResult, error) {
    // ...
}
```

### Use common helpers

Use `pkg/exploit/common` for HTTP operations:

- `common.NormalizeTarget(url)` -- normalize the target URL
- `common.NewHTTPClient(timeout) (*http.Client, error)` -- create an HTTP client
- `common.NewHTTPClientWithOptions(opts) (*http.Client, error)` -- create with proxy/stealth
- `common.DoJSON(client, req, &result)` -- execute and decode JSON
- `common.ParseHeaderFlags(values) (http.Header, error)` -- parse `Key: Value` headers

## Step 2: Create CLI Commands

Add a new file `cmd/aipostex/<module>.go`:

```go
package main

import (
    "github.com/spf13/cobra"
    "github.com/professor-moody/aipostex/pkg/exploit/myservice"
)

func newMyServiceCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "myservice",
        Short: "Enumerate and exploit MyService instances",
    }

    // Common flags
    var target string
    var headers []string
    cmd.PersistentFlags().StringVarP(&target, "target", "t", "", "Target URL")
    cmd.PersistentFlags().StringArrayVar(&headers, "header", nil, "Custom headers")

    // Add subcommands
    cmd.AddCommand(newMyServiceEnumCmd(&target, &headers))
    cmd.AddCommand(newMyServiceExecCmd(&target, &headers))

    return cmd
}
```

### Enum Subcommand (read-only)

```go
func newMyServiceEnumCmd(target *string, headers *[]string) *cobra.Command {
    return &cobra.Command{
        Use:     "enum",
        Short:   "Enumerate MyService instance",
        Example: "  aipostex myservice --target http://127.0.0.1:9000 enum",
        RunE: func(cmd *cobra.Command, args []string) error {
            // Validate flags
            // Create client
            // Call enumerate
            // Build findings
            // Write output with workflow plans
            return nil
        },
    }
}
```

### Gated Subcommand

```go
func newMyServiceExecCmd(target *string, headers *[]string) *cobra.Command {
    return &cobra.Command{
        Use:     "exec",
        Short:   "Execute command on MyService (requires --force-exploit)",
        Example: "  aipostex myservice --target http://127.0.0.1:9000 exec --force-exploit",
        RunE: func(cmd *cobra.Command, args []string) error {
            if err := requireForceExploit("myservice exec"); err != nil {
                return err
            }
            // ...
            return nil
        },
    }
}
```

### Register the Command

In `main.go`, add the command to the root:

```go
rootCmd.AddCommand(newMyServiceCmd())
```

## Step 3: Build Findings

Use `newExploitFinding()` from `exploit_common.go` to create findings. Its signature is
`newExploitFinding(source, target, title, severity, description string, metadata map[string]interface{})`
— **source first, metadata as a map** (module-declared display keys drive the `context:` line):

```go
finding := newExploitFinding(
    report.SourceMyService,                             // source (add a constant in pkg/report)
    myTarget,                                           // target
    "MyService Enumeration - N Items Found",            // title
    report.SeverityHigh,                                // severity
    "MyService is accessible without authentication.",  // description
    map[string]interface{}{                             // metadata
        "module":   "myservice",
        "action":   "enum",
        "provider": "myservice",
    },
)
finding.Evidence = evidenceString

// Tag what landed honestly. Use gatedStrength(verified, strong, weak) to claim a strong
// label only when the effect was actually verified (avoids over-claiming on a bare 2xx).
finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "myservice-enum", "enumeration")

// If the finding loots a credential, surface it in the creds: block (and
// `report view --credentials`) instead of only in evidence: — via lootCredentialRecord.
finding.Metadata["extracted_credentials"] = lootCredentialRecord(
    "myservice-secret", secretName, secretValue, myTarget, "where it was found")
```

Then emit the findings with a summary via `writeExploitFindingsWithSummary` (never a raw writer) —
this drives the framed `── Summary ──` block, the credential hint, and `── Next Actions ──`:

```go
return writeExploitFindingsWithSummary(findings, &exploitSummary{
    Module:              "myservice",
    Action:              "enum",
    ResourcesEnumerated: len(items), // count things ENUMERATED (models/collections/tools), not findings
    Mutating:            false,
    WorkflowPlans:       plans,
})
```

## Step 4: Add Workflow Plans

Build workflow plans so findings suggest follow-on commands:

```go
func buildMyServiceEnumWorkflowPlan(target string, items []string) *workflowPlan {
    plan := &workflowPlan{
        Target:        target,
        Stage:         "correlation",
        Rationale:     "MyService enumerated",
        Landed:        "read-confirmed",
        ChainSource:   "myservice-enum",
    }
    plan.Recommendations = append(plan.Recommendations, workflowRecommendation{
        Command:   fmt.Sprintf("aipostex myservice --target %s exec --force-exploit", target),
        Rationale: "Demonstrate execution",
        Gated:     true,
        Priority:  50,
        Stage:     "takeover",
    })
    return plan
}
```

## Step 5: Add Fingerprint Probes

If the service has a distinct HTTP signature, add probes in `pkg/fingerprint/fingerprint.go`:

```go
{
    Service:     "myservice",
    DefaultPort: 9000,
    HTTPProbes: []HTTPProbe{
        {Method: "GET", Path: "/api/status", MatchStatus: 200,
         MatchBody: "myservice", Specificity: 80},
        {Method: "GET", Path: "/api/version", MatchStatus: 200,
         MatchBody: "version", VersionRegex: `"version"\s*:\s*"([^"]+)"`,
         Specificity: 60},
    },
},
```

Probes below `MinSpecificityThreshold` (30) are filtered from results. Optional fields include `MatchBodyNot` (reject false positives), `MatchHeader` (match response headers), and `VersionRegex` (extract version from first capture group).

Add the port to `DefaultConfig()` in `internal/config/config.go`.

## Step 6: Add Tests

### Client tests

```go
// pkg/exploit/myservice/client_test.go
func TestNewClientNormalizesTarget(t *testing.T) { ... }
func TestEnumerateReturnsItems(t *testing.T) { ... }
```

### CLI tests

```go
// cmd/aipostex/myservice_test.go
func TestMyServiceExecRequiresForceExploit(t *testing.T) { ... }
```

### Main test update

Add the new command to the registered subcommands test in `main_test.go`.

## Step 7: Add a Finding Source Constant

In `pkg/report/finding.go`, add:

```go
SourceMyService = "myservice"
```

## Checklist

- [ ] Client library in `pkg/exploit/<module>/`
- [ ] Constructor accepts `context.Context` and returns `(*Client, error)`
- [ ] CLI commands in `cmd/aipostex/<module>.go`
- [ ] CLI callers handle constructor error returns
- [ ] Gated commands use `requireForceExploit()`
- [ ] Workflow plans with read-first ordering
- [ ] Finding source constant in `pkg/report/`
- [ ] Fingerprint probes (if applicable)
- [ ] Default port in config (if applicable)
- [ ] Tests for client and CLI
- [ ] Main test updated for command registration
- [ ] Documentation page in `docs/modules/<module>.md` (cover overview, subcommands, flags, examples, workflow progression)
- [ ] Add the new page to the `nav` section in `mkdocs.yml` under `Exploit Modules`
