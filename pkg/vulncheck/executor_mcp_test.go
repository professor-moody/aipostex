package vulncheck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mcpHandlerConfig configures the fake Streamable-HTTP MCP server below.
type mcpHandlerConfig struct {
	tools map[string]map[string]any // tool name -> inputSchema
	// call simulates a tool invocation: given the tool name and decoded
	// arguments, return the text content and isError flag.
	call func(tool string, args map[string]any) (text string, isError bool)
}

// newFakeMCPServer stands up an httptest server that speaks the MCP Streamable
// HTTP transport at /mcp (initialize → session → tools/list / tools/call),
// mirroring a real MCP-SDK server closely enough to drive the template executor.
func newFakeMCPServer(t *testing.T, cfg mcpHandlerConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		method, _ := payload["method"].(string)
		switch method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-exec")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      payload["id"],
				"result": map[string]any{
					"protocolVersion": "2025-11-25",
					"capabilities":    map[string]any{"tools": map[string]any{}},
					"serverInfo":      map[string]any{"name": "fake-mcp"},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			tools := make([]map[string]any, 0, len(cfg.tools))
			for name, schema := range cfg.tools {
				tools = append(tools, map[string]any{
					"name":        name,
					"description": name + " tool",
					"inputSchema": schema,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      payload["id"],
				"result":  map[string]any{"tools": tools},
			})
		case "tools/call":
			params, _ := payload["params"].(map[string]any)
			name, _ := params["name"].(string)
			args, _ := params["arguments"].(map[string]any)
			text, isErr := cfg.call(name, args)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      payload["id"],
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": text}},
					"isError": isErr,
				},
			})
		default:
			t.Fatalf("unexpected method %q", method)
		}
	}))
}

func stringSchema(field string) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{field: map[string]any{"type": "string"}},
		"required":   []any{field},
	}
}

func runMCPTemplate(t *testing.T, tmplPath string, srv *httptest.Server) []findingSummary {
	t.Helper()
	tmpl, err := LoadTemplate(tmplPath)
	if err != nil {
		t.Fatalf("LoadTemplate(%s): %v", tmplPath, err)
	}
	eng := NewEngine(2*time.Second, 1)
	eng.Mode = ModeFull
	eng.HTTPClient = srv.Client() // drive the in-process httptest server
	findings, _, err := eng.ExecuteTemplateDetailed(tmpl, srv.URL)
	if err != nil {
		t.Fatalf("ExecuteTemplateDetailed: %v", err)
	}
	out := make([]findingSummary, 0, len(findings))
	for _, f := range findings {
		ps, _ := f.Metadata["landed"].(string)
		out = append(out, findingSummary{Title: f.Title, Severity: f.Severity, Landed: ps, Evidence: f.Evidence})
	}
	return out
}

type findingSummary struct {
	Title    string
	Severity string
	Landed   string
	Evidence string
}

// TestMCPExecutorCommandInjectionFires is the core Track-2 guarantee: the
// transport:mcp executor completes the handshake and lands mcp-cmdi-001's RCE
// proof against a real MCP-shaped server — something the static HTTP path cannot
// do (it 404s on the modern /mcp endpoint and never opens a session).
func TestMCPExecutorCommandInjectionFires(t *testing.T) {
	srv := newFakeMCPServer(t, mcpHandlerConfig{
		tools: map[string]map[string]any{
			"execute_command": stringSchema("command"),
		},
		call: func(tool string, args map[string]any) (string, bool) {
			if tool != "execute_command" {
				return "", true
			}
			cmd, _ := args["command"].(string)
			// Simulate a real shell running `echo <canary>`.
			if strings.HasPrefix(cmd, "echo ") {
				return strings.TrimPrefix(cmd, "echo "), false
			}
			return "", true
		},
	})
	defer srv.Close()

	findings := runMCPTemplate(t, "templates/mcp/mcp-cmdi-001-execute-command-rce.yaml", srv)

	var sawReachable, sawExploited bool
	for _, f := range findings {
		switch f.Landed {
		case "reachable":
			sawReachable = true
		case "execution-confirmed":
			sawExploited = true
			if !strings.Contains(f.Evidence, "AIPOSTEX_RCE_CANARY_7f3a9b2e") {
				t.Errorf("exploited finding evidence should contain the canary, got: %q", f.Evidence)
			}
		}
	}
	if !sawReachable {
		t.Errorf("expected a 'reachable' finding that the command tool is exposed; findings=%+v", findings)
	}
	if !sawExploited {
		t.Fatalf("expected an 'exploited' RCE finding from execute_command; findings=%+v", findings)
	}
}

// TestMCPExecutorNoCommandToolNoExploit verifies the detect gate: a server
// exposing only a benign tool yields no command-injection finding (no false
// positive), proving the executor keys off the real tool inventory.
func TestMCPExecutorNoCommandToolNoExploit(t *testing.T) {
	srv := newFakeMCPServer(t, mcpHandlerConfig{
		tools: map[string]map[string]any{
			"get_weather": stringSchema("city"),
		},
		call: func(tool string, args map[string]any) (string, bool) {
			return "sunny", false
		},
	})
	defer srv.Close()

	findings := runMCPTemplate(t, "templates/mcp/mcp-cmdi-001-execute-command-rce.yaml", srv)
	if len(findings) != 0 {
		t.Fatalf("expected no findings against a server without a command tool, got %+v", findings)
	}
}

// TestMCPExecutorToolReportsErrorNotExploited verifies honesty: when the command
// tool is present but the call comes back isError=true (e.g. sandboxed/blocked),
// the RCE proof is NOT claimed — only the reachable (tool exposed) finding stands.
func TestMCPExecutorToolReportsErrorNotExploited(t *testing.T) {
	srv := newFakeMCPServer(t, mcpHandlerConfig{
		tools: map[string]map[string]any{
			"execute_command": stringSchema("command"),
		},
		call: func(tool string, args map[string]any) (string, bool) {
			// Tool exists but refuses to run the command.
			return "command blocked by policy", true
		},
	})
	defer srv.Close()

	findings := runMCPTemplate(t, "templates/mcp/mcp-cmdi-001-execute-command-rce.yaml", srv)
	for _, f := range findings {
		if f.Landed == "execution-confirmed" {
			t.Fatalf("must not claim 'exploited' when the tool reported isError; findings=%+v", findings)
		}
	}
}

// TestMCPExecutorPathTraversalReadConfirmed exercises a second tagged template
// (read_file) to confirm the executor generalizes beyond command injection.
func TestMCPExecutorPathTraversalReadConfirmed(t *testing.T) {
	srv := newFakeMCPServer(t, mcpHandlerConfig{
		tools: map[string]map[string]any{
			"read_file": stringSchema("path"),
		},
		call: func(tool string, args map[string]any) (string, bool) {
			if tool != "read_file" {
				return "", true
			}
			// Simulate returning host file contents (a hostname, not the
			// JSON-RPC error/usage strings the template negates).
			return "labhost-01", false
		},
	})
	defer srv.Close()

	findings := runMCPTemplate(t, "templates/mcp/mcp-path-001-read-file-traversal.yaml", srv)
	if len(findings) == 0 {
		t.Fatalf("expected read_file path-traversal findings, got none")
	}
}
