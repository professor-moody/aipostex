# Template Execution Model

The vulncheck engine (`pkg/vulncheck`) turns YAML templates into findings. A template is a declarative description of an attack — where to look, how to confirm it, what to report — but it does nothing on its own. This page traces the path a template travels once the engine has it: how it is loaded, how it is selected for a scan, how its detect and check phases run against a target, and how a match becomes a `report.Finding`. The [Template Format](../vuln-templates/format.md) page documents the YAML schema itself; this page is about the engine that consumes it.

## Pipeline at a Glance

```
  LOAD                       SELECT                        EXECUTE (per template, per target)
  ┌────────────────┐         ┌──────────────────┐         ┌───────────────────────────────────┐
  │ embedded FS    │         │ FilteredTemplates│         │ normalize target (trim trailing /) │
  │ LoadEmbedded() │──┐      │  • tag match     │         │             │                       │
  │                │  │      │  • severity match│         │   transport == mcp ? ──yes──▶ MCP   │
  │ --templates-dir│  ├─▶ e.Templates ──▶       │──▶ set  │             │ no                    │
  │ LoadTemplates()│  │      │  • ModeDetect     │  of     │   Phase 1: detect[] (gate)          │
  │  (overrides by │  │      │    drops exploit  │  tmpls  │     all matchers AND → step matched │
  │   ID)          │──┘      │    templates      │         │     any step matched → gate open    │
  └────────────────┘         └──────────────────┘         │             │                       │
                                                          │   Phase 2: checks[]                 │
   Concurrency: buffered-channel semaphore (size          │     matchAll (AND) → extract → build │
   e.Concurrency) fans templates out per target           │             ▼                       │
                                                          │        report.Finding[]             │
                                                          └───────────────────────────────────┘
                                                                        │
                                            DedupeAndSortFindings() ◀───┘
                                            (severity desc, dedupeKey, dedupe_count)
```

## Template Loading and ID Collision Handling

Templates reach the engine from two sources. Embedded templates are compiled into the binary via Go's `embed.FS` and loaded through `LoadEmbeddedTemplates()`. Operator-supplied templates come from `--templates-dir` and are loaded through `LoadTemplates(dir)`. Both paths funnel into `addTemplate()`, which appends to the engine's `e.Templates` slice — but with override semantics keyed on template ID.

When `addTemplate()` sees a template whose `ID` already exists in the slice, it performs an in-place replacement rather than appending (`engine.go:148-158`). This is how an operator overrides a shipped template: load the embedded set first, then load a directory containing a template with the same ID, and the operator's version wins. The replacement is silent when `warnOnDuplicate=false`; when `warnOnDuplicate=true` (as both engine loaders use), it emits a `warning: duplicate template id ...` line to stderr naming the overridden source path (`engine.go:148-160`).

A template is only ever added if it passes `Validate()`. Validation checks the required fields (`id`, `info.name`, `info.severity`, `info.author`, `info.description`), a legal severity value, an `info.type` of `detection` or `exploit`, a `transport` of `http` or `mcp`, and every detect/check step's matchers and extractors. If validation fails, the template is rejected and never enters the engine (`template.go:245-318`).

## Template Selection: Tags, Severities, and Exploit Gating

A scan does not run every loaded template. `FilteredTemplates(tags, severities)` reduces `e.Templates` to the set that applies to this run (`engine.go:165-178`):

- **Tag intersection.** `tagMatch` is true when no tags were requested (`len(tags)==0`) or the template's tags overlap the filter. `HasAnyTag()` returns true if any requested tag matches any template tag, case-insensitively (`template.go:420-459`).
- **Severity matching.** `sevMatch` is true when no severities were requested or `MatchesSeverity()` succeeds. That method is deliberately broad: it matches on the template-level severity, the *max* check severity, or any individual check's effective severity (its override, or the template default). A template with a `low` default but one `high` check will match a `high` filter (`template.go:420-459`).
- **Mode gating.** When the engine is in `ModeDetect`, any template with `IsExploit()==true` is excluded automatically, before tag or severity filtering is even consulted (`engine.go:165-178`). This is the enforcement point behind the detect-vs-full distinction: exploit templates simply cannot be selected in detect mode.

If nothing survives the filter, `ScanDetailed()` returns a `no templates match the specified filters` error rather than an empty result (`engine.go:187-269`).

## The HTTP Execution Model (Default Transport)

`ExecuteTemplateDetailed()` runs a single template against a single target. It first normalizes the target by trimming a trailing slash, then dispatches on transport: an `mcp` transport hands off to the MCP executor (see below), and everything else runs the HTTP path (`engine.go:279-344`).

The HTTP path is two phases sharing one variable map. Template-level `vars` seed a cross-step `variables` map at the start. Phase 1 runs the `detect[]` steps as a gate; Phase 2 runs the `checks[]` that build findings. Variables extracted in one step are merged into the map and are visible to every later step via `interpolate()`, which substitutes `{{variable}}` placeholders in paths, bodies, headers, and finding fields (`engine.go:291-341`).

### Phase 1 — Detect: Service Gating

The detect phase answers "is the right service even here?" before the engine spends checks on it — the mechanism that prevents false positives against unrelated services. Each detect step is an HTTP request whose matchers are evaluated with `matchAll()`; if all matchers on a step pass, that step is *matched*. **Any** single matched detect step opens the gate, and the engine breaks on the first match (`engine.go:297-322`). On a match, that step's extractors run and their variables are merged into the map. If no detect step matches, the template short-circuits and produces no findings. Templates with an empty `detect[]` skip the gate entirely and proceed straight to checks.

### Phase 2 — Check: Building Findings

Each check runs through `executeCheck()`, which issues its HTTP request, evaluates the check's matchers with AND semantics, extracts variables, and — only on a match — builds a finding via `buildCheckFinding()` (`engine.go:325-344`). A check that does not match contributes no finding but its (empty) extraction still merges harmlessly, and subsequent checks continue to run and can see any variables earlier checks extracted.

## Matcher Semantics: AND Logic and Matcher Types

`matchAll()` returns true only if **every** matcher returns true — pure AND logic, with no OR combinator (`engine.go:615-667`). This is intentional: a finding should require every stated condition, so a single missing signal suppresses a false positive. The matcher types are:

| Type | Semantics |
|---|---|
| `status` | Exact HTTP status-code equality |
| `body_contains` | Substring present in the body |
| `body_not_contains` | Substring absent from the body |
| `body_regex` | Regex matches the body |
| `header_contains` | Case-insensitive substring in the named header |
| `json_path` | gjson path exists; if a value is given, must equal it |

Every matcher supports an optional `negate` flag, which inverts its result after evaluation (`engine.go:615-667`). Regex patterns are compiled through `compileRegexCached()`, a `sync.Map` cache with a soft limit of 1024 patterns; past the limit, new patterns still compile but are not cached (`engine.go:699-715`).

## Variable Extraction and Interpolation

Extractors pull response data into named variables (`engine.go:669-697`):

- **`regex`** — a capture group from the body; the group defaults to 1.
- **`json`** — a gjson path against the body.
- **`header`** — a named response header.

An extractor only writes its variable when the extracted value is non-empty, so an absent field leaves the variable unset rather than blank. Extracted values feed `interpolate()`, which replaces `{{variable}}` placeholders in later steps and in the finding's `title`, `description`, `remediation`, and `evidence` (`engine.go:291-341`).

## Content-Type and Request Context

When a check or detect step carries a body but sets no `Content-Type`, `applyDefaultContentType()` picks one: `application/json` for bodies starting with `{` or `[`, otherwise `application/x-www-form-urlencoded` (`engine.go:603-613`).

Every request uses `e.requestContext()`, which returns the engine's `Context` when set and `context.Background()` otherwise. The context is checked before each step so a cancelled scan (Ctrl+C) stops promptly rather than draining every remaining step (`engine.go:748-753`).

## The MCP Transport Alternative

Templates tagged `transport: mcp` cannot be driven over raw HTTP — the Model Context Protocol needs a stateful `initialize → session → tools/call` handshake. These templates go to `executeTemplateMCP()`, which speaks the protocol through `pkg/exploit/mcp.Client` (`executor_mcp.go:37-112`). The executor hands the client the template's `mcp-headers`, calls `client.Initialize()`, then `client.ListTools()`. A failed initialize is treated like a quiet HTTP detect miss, not an error — the target simply isn't a usable MCP server.

To reuse the existing matcher and extractor machinery unchanged, the executor re-marshals the discovered tool inventory into an HTTP-shaped JSON-RPC envelope, `{"result":{"tools":[...]}}`. Detect steps then match against that body, and extraction via `json_path` (e.g. `result.tools.#.name`) or `body_regex` works exactly as it does over HTTP (`executor_mcp.go:75-95`).

Checks dispatch on the JSON-RPC method parsed from `check.Body` by `parseMCPCheckBody()` (`executor_mcp.go:182`):

- **`tools/list`** (or an unset method) matches against the tool inventory — the detection path.
- **`tools/call`** invokes a named tool — the exploit path. If the named tool isn't exposed, the check is simply inapplicable and yields no finding. `mcpInjection()` chooses which argument carries the payload, preferring a well-known injection field (`command`, `cmd`, `shell`, `path`, `file`, `url`, `input`, and similar) and falling back to the longest string argument. The result comes back through `client.CallToolResult()`, and an `isError: true` result is treated as a synthesized `500` status, so any `status: 200` gate fails and a rejected call is never reported as a successful exploit.

Both MCP checks funnel into the same `buildCheckFinding()` as the HTTP path, so landed, evidence, and metadata are derived identically regardless of transport.

## Stage, Landed, and Evidence

`buildCheckFinding()` assembles the `report.Finding` (`engine.go:514-583`). It interpolates the finding's `title`, `description`, `remediation`, and `evidence` with the merged variable set (template vars plus the check's extractions), and copies extracted values into metadata.

`stage` and `landed` come from the check when set. When both `check.Stage` and `check.Landed` are empty, the engine applies defaults: `stage='impact'`, and `landed='execution-confirmed'` for an exploit template or `'read-confirmed'` for a detection template (`engine.go:563-577`). The exploit-vs-detection distinction is what separates "we ran the exploit and it landed" from "we confirmed the condition exists."

When the finding carries no explicit `evidence` after interpolation, `buildAutoEvidence()` synthesizes one from the request method, URL, status, and body, truncating the body at 2048 bytes with an ellipsis (`engine.go:578-598`).

## Version Matching and Advisory Confidence

Checks with an `affected_version` block cross-reference a CVE range against an extracted version string. `executeCheck()` reads the version from `variables[check.AffectedVersion.Variable]` and calls `VersionSatisfies()` (`engine.go:481-507`). The outcome sets the finding's advisory confidence (`engine.go:495-505`):

- **In range** → `affected-version-confirmed`.
- **Range unparseable** → `versionUnparseable=true` and `service-exposed-risk` confidence. Suppressing here would conflate "couldn't parse the version" with "not affected" — a silent false negative on a CVE check — so the finding is reported at lower confidence for manual verification.
- **No version extracted** → `exploit-proof` for an exploit template, otherwise `service-exposed-risk` for a detection template.

## Concurrency Control

`Scan()`/`ScanDetailed()` fan templates out across goroutines, one per template, bounded by a buffered-channel semaphore of size `e.Concurrency`. Each goroutine acquires a slot with `sem <- struct{}{}` before launching and releases it with `defer func() { <-sem }()`, so at most `Concurrency` templates execute against a target at once (`engine.go:198`, `engine.go:208`, `engine.go:212`). Results and metrics are merged under a mutex.

## Progress Reporting and Metrics

If `Engine.OnProgress` is set, it fires a `ProgressEvent` on template start, on match, and on error, carrying a `Type` (`start`/`match`/`error`/`complete`), `TemplateID`, `Target`, `FindingCount`, and `Current`/`Total` counters (`engine.go:217-264`).

`ScanDetailed()` also returns `ScanMetrics`, which separate `RequestErrors` (network-level failures) from `TemplateErrors` (template-level failures such as malformed interpolation producing an invalid URL) and records a `FailedTemplates` list. A template that returns no error still lands in the metrics if it accumulated request or template errors along the way (`engine.go:187-269`).

## Finding Deduplication

Findings from all templates and targets pass through `DedupeAndSortFindings()` in the assessment layer (`assessment.go:124-176`). It sorts by severity descending (worst first), then by a `dedupeKey` built from `Source`, `TemplateID`, `Target`, `Title`, `Severity`, `Description`, `Evidence`, `landed`, and `action`. Findings sharing an identical key collapse to one, and the survivor records how many duplicates were folded in via `dedupe_count` in its metadata.

## Worked Example: A Template's Journey

Take the Ollama unauthenticated-API template from the [format page](../vuln-templates/format.md): a `detection` template, tagged `ollama, auth, ...`, with a `detect` step probing `/` and two checks against `/api/tags` and `/api/version`.

1. **Load.** It ships embedded, so `LoadEmbeddedTemplates()` adds it. If an operator had a same-ID template under `--templates-dir`, theirs would replace it in place (with a stderr warning).
2. **Select.** A scan with tag filter `ollama` keeps it — `HasAnyTag` matches. In `ModeDetect` it survives because `IsExploit()` is false; a `--severity critical` filter would drop it, since neither its `high`/`info` checks nor its default reach `critical`.
3. **Normalize + detect.** Against `http://target:11434/`, the trailing slash is trimmed. The detect step GETs `/` and matches `body_contains: "Ollama is running"`. All matchers on the step pass, so the gate opens; had it missed, the template would produce nothing.
4. **Check 1 — `/api/tags`.** A `200` plus `body_contains: "models"` satisfies `matchAll()`. Two `json` extractors fill `{{model_count}}` and `{{first_model}}`. `buildCheckFinding()` interpolates the title `Ollama Unauthenticated - N Models Exposed`, and — being a detection template with no explicit stage/landed fields — stamps `stage='impact'`, `landed='read-confirmed'`. With no `evidence` in the YAML, `buildAutoEvidence()` attaches the request/response transcript.
5. **Check 2 — `/api/version`.** A `200` extracts `{{ollama_version}}`, producing a second, `info`-severity finding. Because it runs after check 1, the version value is also available to any later step in the map.
6. **Dedup + sort.** Both findings flow into `DedupeAndSortFindings()`. The `high` finding sorts above the `info` one; a repeat scan of the same target would collapse identical duplicates and bump `dedupe_count`.
