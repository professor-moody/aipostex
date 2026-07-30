package vulncheck

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/professor-moody/aipostex/pkg/exploit/mcp"
	"github.com/professor-moody/aipostex/pkg/report"
)

// executeTemplateMCP runs a transport:mcp template by speaking the Model Context
// Protocol instead of issuing raw HTTP requests. Static HTTP steps can never
// complete an MCP exchange: the official SDK's Streamable HTTP transport requires
// initialize → an Mcp-Session-Id header → tools/call, with SSE-framed responses.
// This executor drives that handshake via pkg/exploit/mcp.Client (which already
// auto-discovers /mcp vs /message and builds schema-aware tool arguments) and
// maps the template's existing matchers/extractors onto the protocol:
//
//   - A check whose JSON-RPC body uses method "tools/list" (or omits a method) is
//     matched against the discovered tool inventory, re-marshaled into the same
//     {"result":{"tools":[...]}} shape an HTTP response would carry, so body_regex
//     and json-path (result.tools.#.name) extractors work unchanged.
//   - A check whose body uses method "tools/call" invokes the named tool, placing
//     the template's payload into the schema's best-matching field, and matches
//     against the decoded tool output (content[].text). A tool that isn't exposed
//     simply makes that check inapplicable (no finding); a tool that runs but
//     reports isError is treated as a failed exploit (synthesized non-200 status),
//     never a successful one.
//
// Tagging a template transport:mcp therefore requires no rewrite of its bodies —
// the same JSON-RPC envelopes that document the attack are parsed and replayed
// over a real session.
func (e *Engine) executeTemplateMCP(tmpl *Template, target string) ([]report.Finding, ScanMetrics, error) {
	metrics := ScanMetrics{}
	variables := make(map[string]string, len(tmpl.Vars))
	for k, v := range tmpl.Vars {
		variables[k] = v
	}

	client, err := mcp.NewClient(e.requestContext(), target, e.defaultTimeout, mcpTemplateHeaders(tmpl, variables))
	if err != nil {
		return nil, ScanMetrics{TemplateErrors: 1}, nil
	}
	// Reuse the engine's HTTP client so the MCP path shares the scan's transport
	// config (timeout, redirect limits) and is injectable in tests.
	client.HTTPClient = e.httpClient()
	defer client.Close()

	if err := client.Initialize(); err != nil {
		// Pre-handshake failure: the target isn't an MCP server or is unreachable, so we
		// can't tell "not MCP" from "broken MCP". Treat it like an HTTP detect miss —
		// quiet, inapplicable, NOT counted (else every non-MCP host in a broad scan would
		// register a false MCP failure). Post-handshake failures below ARE surfaced.
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "  [debug] mcp template %s: initialize failed against %s: %v\n", tmpl.ID, target, err)
		}
		return nil, metrics, nil
	}

	tools, err := client.ListTools()
	if err != nil {
		// The MCP handshake succeeded, so this IS an MCP server — a tools/list failure is a
		// real inability to test it, not a clean pass. Surface it so the scan's coverage
		// reflects an incomplete MCP check (an MCP-only scan must not read as "clean").
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "  [debug] mcp template %s: tools/list failed against %s: %v\n", tmpl.ID, target, err)
		}
		metrics.TemplateErrors++
		metrics.FailedTemplates = append(metrics.FailedTemplates, TemplateFailure{
			TemplateID: tmpl.ID, Target: target, Error: fmt.Sprintf("mcp tools/list: %v", err),
		})
		return nil, metrics, nil
	}
	toolsByName := make(map[string]mcp.Tool, len(tools))
	for _, t := range tools {
		toolsByName[t.Name] = t
	}
	toolsListBody := marshalMCPToolsEnvelope(tools)

	// Phase 1: detect — gate on the discovered tool inventory.
	if len(tmpl.Detect) > 0 {
		detected := false
		for _, step := range tmpl.Detect {
			if e.Context != nil && e.Context.Err() != nil {
				return nil, metrics, nil
			}
			if matchAll(step.Matchers, http.StatusOK, toolsListBody, nil) {
				for _, ext := range step.Extractors {
					if value := extract(ext, toolsListBody, nil); value != "" {
						variables[ext.Name] = value
					}
				}
				detected = true
				break
			}
		}
		if !detected {
			return nil, metrics, nil
		}
	}

	// Phase 2: checks.
	var findings []report.Finding
	for _, check := range tmpl.Checks {
		if e.Context != nil && e.Context.Err() != nil {
			return findings, metrics, nil
		}
		finding, extracted, matched := e.executeMCPCheck(check, tmpl, client, target, toolsByName, toolsListBody, variables)
		if matched && finding != nil {
			findings = append(findings, *finding)
		}
		for k, v := range extracted {
			variables[k] = v
		}
	}
	return findings, metrics, nil
}

// executeMCPCheck runs one check of an MCP template, dispatching on the JSON-RPC
// method embedded in check.Body.
func (e *Engine) executeMCPCheck(check Check, tmpl *Template, client *mcp.Client, target string,
	toolsByName map[string]mcp.Tool, toolsListBody string, variables map[string]string) (*report.Finding, map[string]string, bool) {

	method, toolName, callArgs := parseMCPCheckBody(interpolate(check.Body, variables))

	var (
		respBody    string
		status      int
		evidenceURL string
	)
	switch method {
	case "tools/call":
		tool, ok := toolsByName[toolName]
		if !ok {
			// The named tool isn't exposed by this server — the check doesn't apply.
			return nil, nil, false
		}
		value, hints := mcpInjection(callArgs)
		res, err := client.CallToolResult(tool.Name, mcp.BuildToolArguments(tool, value, hints))
		if err != nil {
			if e.Verbose {
				fmt.Fprintf(os.Stderr, "  [debug] mcp template %s: tools/call %s failed: %v\n", tmpl.ID, tool.Name, err)
			}
			return nil, nil, false
		}
		respBody = res.Text
		if res.IsError {
			// The tool ran but reported an error: the exploit did not land. A
			// non-200 synthesized status fails any `status: 200` gate so we never
			// report a successful exploitation off a rejected call.
			status = http.StatusInternalServerError
		} else {
			status = http.StatusOK
		}
		evidenceURL = fmt.Sprintf("%s [tools/call %s]", target, tool.Name)
	default: // "tools/list" or unset — operate on the discovered tool inventory.
		respBody = toolsListBody
		status = http.StatusOK
		evidenceURL = fmt.Sprintf("%s [tools/list]", target)
	}

	if !matchAll(check.Matchers, status, respBody, nil) {
		return nil, nil, false
	}

	extracted := make(map[string]string)
	for _, ext := range check.Extractors {
		if value := extract(ext, respBody, nil); value != "" {
			extracted[ext.Name] = value
		}
	}
	allVars := make(map[string]string, len(variables)+len(extracted))
	for k, v := range variables {
		allVars[k] = v
	}
	for k, v := range extracted {
		allVars[k] = v
	}

	finding := e.buildCheckFinding(check, tmpl, target, allVars, extracted, "", false, method, evidenceURL, status, respBody)
	return finding, extracted, true
}

// parseMCPCheckBody extracts the JSON-RPC method, tool name and arguments from a
// template step body. A body that isn't valid JSON-RPC yields an empty method,
// which routes to the tools/list inventory branch.
func parseMCPCheckBody(body string) (method, toolName string, args map[string]any) {
	body = strings.TrimSpace(body)
	if body == "" {
		return "", "", nil
	}
	var env struct {
		Method string `json:"method"`
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		return "", "", nil
	}
	return env.Method, env.Params.Name, env.Params.Arguments
}

// mcpInjectionFieldNames are argument keys that commonly carry the injected
// payload, used to choose which static argument is the exploit value.
var mcpInjectionFieldNames = []string{
	"command", "cmd", "shell", "exec", "script",
	"path", "file", "filename", "filepath",
	"url", "uri", "query", "input",
}

// mcpInjection selects the payload value and field-name hints from a template's
// static tools/call arguments. It prefers a well-known injection field; failing
// that, the longest string value. The chosen field leads the hint list so
// BuildToolArguments targets it when mapping onto the server's real schema.
func mcpInjection(args map[string]any) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	chosen := ""
	for _, want := range mcpInjectionFieldNames {
		for _, k := range keys {
			if strings.EqualFold(k, want) {
				if _, ok := args[k].(string); ok {
					chosen = k
					break
				}
			}
		}
		if chosen != "" {
			break
		}
	}
	if chosen == "" {
		longest := -1
		for _, k := range keys {
			if s, ok := args[k].(string); ok && len(s) > longest {
				longest = len(s)
				chosen = k
			}
		}
	}

	value, _ := args[chosen].(string)
	hints := make([]string, 0, len(keys))
	if chosen != "" {
		hints = append(hints, chosen)
	}
	for _, k := range keys {
		if k != chosen {
			hints = append(hints, k)
		}
	}
	return value, hints
}

// marshalMCPToolsEnvelope re-marshals the discovered tools into the JSON-RPC
// result envelope an HTTP tools/list response would carry, so template matchers
// and json-path extractors (result.tools.#.name) operate identically over MCP.
func marshalMCPToolsEnvelope(tools []mcp.Tool) string {
	env := map[string]any{
		"result": map[string]any{
			"tools": tools,
		},
	}
	b, err := json.Marshal(env)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// mcpTemplateHeaders collects authentication-style headers declared by a
// template's steps (excluding Content-Type, which is irrelevant to the MCP
// client) so authenticated MCP servers can be reached. Returns nil when none.
func mcpTemplateHeaders(tmpl *Template, vars map[string]string) http.Header {
	h := http.Header{}
	collect := func(headers map[string]string) {
		for k, v := range headers {
			if strings.EqualFold(k, "Content-Type") {
				continue
			}
			h.Set(k, interpolate(v, vars))
		}
	}
	for _, s := range tmpl.Detect {
		collect(s.Headers)
	}
	for _, c := range tmpl.Checks {
		collect(c.Headers)
	}
	if len(h) == 0 {
		return nil
	}
	return h
}
