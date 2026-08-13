package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/internal/mcpserver"
)

// callTool drives one MCP tools/call through a server built from registerServeTools
// and returns the text content and isError flag.
func callTool(t *testing.T, name string, args map[string]interface{}) (string, bool) {
	t.Helper()
	srv := mcpserver.New("aipostex-test", "test")
	registerServeTools(srv)

	req := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]interface{}{"name": name, "arguments": args},
	}
	line, _ := json.Marshal(req)
	var out strings.Builder
	if err := srv.Serve(context.Background(), strings.NewReader(string(line)+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, out.String())
	}
	if len(resp.Result.Content) == 0 {
		return "", resp.Result.IsError
	}
	return resp.Result.Content[0].Text, resp.Result.IsError
}

func TestServeTool_AgentProbe(t *testing.T) {
	serveTimeout = 5 * time.Second
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"response": "I'm the helpdesk agent."})
	}))
	defer srv.Close()

	text, isErr := callTool(t, "agent_probe", map[string]interface{}{"target": srv.URL + "/chat"})
	if isErr {
		t.Fatalf("agent_probe errored: %s", text)
	}
	if !strings.Contains(text, "helpdesk agent") {
		t.Errorf("probe text = %q", text)
	}
}

func TestServeTool_RagPoisonGatedWithoutConfirm(t *testing.T) {
	serveTimeout = 5 * time.Second
	// No target contact should happen — the gate refuses before any network call.
	text, isErr := callTool(t, "rag_poison", map[string]interface{}{
		"target": "http://127.0.0.1:1/", "title": "x", "content": "y",
	})
	if !isErr {
		t.Fatal("rag_poison without confirm should be an error result")
	}
	if !strings.Contains(text, "confirm") {
		t.Errorf("expected a confirm-required refusal, got %q", text)
	}
}

func TestServeTool_RagQuery(t *testing.T) {
	serveTimeout = 5 * time.Second
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"answer":  "see the inventory",
			"sources": []map[string]any{{"title": "AD_Server_Inventory.md", "chunk_id": "c0", "text": "DC01, FILE01", "score": 4.2}},
		})
	}))
	defer srv.Close()

	text, isErr := callTool(t, "rag_query", map[string]interface{}{"target": srv.URL, "query": "servers"})
	if isErr {
		t.Fatalf("rag_query errored: %s", text)
	}
	if !strings.Contains(text, "AD_Server_Inventory.md") || !strings.Contains(text, "DC01") {
		t.Errorf("rag_query text = %q", text)
	}
}

// TestServeRegistersInfrastructureTools guards the surface itself: `serve` covered only the
// model and agent layer for a long time, which made "an agent can drive aipostex" true only
// for bespoke agents. These are the infrastructure tools that closed that gap.
func TestServeRegistersInfrastructureTools(t *testing.T) {
	srv := mcpserver.New("aipostex-test", "test")
	registerServeTools(srv)
	registerServeInfraTools(srv)

	got := map[string]bool{}
	for _, name := range srv.ToolNames() {
		got[name] = true
	}
	for _, want := range []string{
		"mcp_enum", "mcp_read", "mcp_auth_posture",
		"ollama_enum", "ollama_prompts",
		"mlflow_experiments", "mlflow_runs",
		"ray_jobs", "k8s_posture",
	} {
		if !got[want] {
			t.Errorf("serve does not register the %q tool", want)
		}
	}
	// The model/agent tools must survive alongside them.
	for _, want := range []string{"fingerprint_model", "agent_probe", "rag_query", "rag_poison"} {
		if !got[want] {
			t.Errorf("serve lost the %q tool", want)
		}
	}
}
