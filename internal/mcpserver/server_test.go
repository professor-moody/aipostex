package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// drive feeds newline-delimited requests through the server and returns the
// decoded responses (one per non-notification request).
func drive(t *testing.T, s *Server, requests ...string) []map[string]interface{} {
	t.Helper()
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out strings.Builder
	if err := s.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decoding response %q: %v", line, err)
		}
		resps = append(resps, m)
	}
	return resps
}

func newTestServer() *Server {
	s := New("aipostex-test", "0.0.0")
	s.Register(Tool{
		Name:        "echo",
		Description: "echo back the message arg",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"message": map[string]interface{}{"type": "string"}}},
		Handler: func(_ context.Context, args map[string]interface{}) (string, bool) {
			return "echo: " + StringArg(args, "message"), false
		},
	})
	s.Register(Tool{
		Name: "danger", Description: "a mutating tool", Mutating: true,
		Handler: func(_ context.Context, args map[string]interface{}) (string, bool) {
			if !BoolArg(args, "confirm") {
				return "refused: this mutating action requires confirm=true", true
			}
			return "did the dangerous thing", false
		},
	})
	s.Register(Tool{
		Name: "boom", Description: "panics",
		Handler: func(_ context.Context, _ map[string]interface{}) (string, bool) { panic("kaboom") },
	})
	return s
}

func TestInitialize(t *testing.T) {
	resps := drive(t, newTestServer(), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if len(resps) != 1 {
		t.Fatalf("want 1 response, got %d", len(resps))
	}
	result := resps[0]["result"].(map[string]interface{})
	if result["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v", result["protocolVersion"])
	}
	if result["serverInfo"].(map[string]interface{})["name"] != "aipostex-test" {
		t.Errorf("serverInfo.name wrong")
	}
}

func TestToolsList(t *testing.T) {
	resps := drive(t, newTestServer(), `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := resps[0]["result"].(map[string]interface{})["tools"].([]interface{})
	if len(tools) != 3 {
		t.Fatalf("want 3 tools, got %d", len(tools))
	}
	// The mutating tool must carry the destructive annotation.
	var sawDanger bool
	for _, ti := range tools {
		tm := ti.(map[string]interface{})
		if tm["name"] == "danger" {
			sawDanger = true
			ann, ok := tm["annotations"].(map[string]interface{})
			if !ok || ann["destructiveHint"] != true {
				t.Errorf("danger tool missing destructiveHint annotation")
			}
		}
	}
	if !sawDanger {
		t.Error("danger tool not listed")
	}
}

func TestToolsCall_Echo(t *testing.T) {
	resps := drive(t, newTestServer(),
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"}}}`)
	result := resps[0]["result"].(map[string]interface{})
	if result["isError"] != false {
		t.Errorf("isError = %v", result["isError"])
	}
	content := result["content"].([]interface{})[0].(map[string]interface{})
	if content["text"] != "echo: hi" {
		t.Errorf("text = %v", content["text"])
	}
}

func TestToolsCall_GatingRefusesWithoutConfirm(t *testing.T) {
	resps := drive(t, newTestServer(),
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"danger","arguments":{}}}`)
	result := resps[0]["result"].(map[string]interface{})
	if result["isError"] != true {
		t.Errorf("expected isError=true for unconfirmed mutating call")
	}
	text := result["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if !strings.Contains(text, "requires confirm") {
		t.Errorf("expected refusal text, got %q", text)
	}
}

func TestToolsCall_GatingAllowsWithConfirm(t *testing.T) {
	resps := drive(t, newTestServer(),
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"danger","arguments":{"confirm":true}}}`)
	result := resps[0]["result"].(map[string]interface{})
	if result["isError"] != false {
		t.Errorf("expected success with confirm=true")
	}
}

func TestToolsCall_UnknownTool(t *testing.T) {
	resps := drive(t, newTestServer(),
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if resps[0]["error"] == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestToolsCall_PanicRecovered(t *testing.T) {
	resps := drive(t, newTestServer(),
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"boom","arguments":{}}}`)
	result := resps[0]["result"].(map[string]interface{})
	if result["isError"] != true {
		t.Errorf("expected isError=true from a panicking tool")
	}
	if resps[0]["error"] != nil {
		t.Errorf("panic should become an isError result, not a JSON-RPC error")
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	// initialized notification (no id) must produce no output line.
	resps := drive(t, newTestServer(),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":8,"method":"ping"}`)
	if len(resps) != 1 {
		t.Fatalf("notification should yield no response; got %d responses", len(resps))
	}
	if resps[0]["id"].(float64) != 8 {
		t.Errorf("only the ping should have responded")
	}
}

func TestUnknownMethod(t *testing.T) {
	resps := drive(t, newTestServer(), `{"jsonrpc":"2.0","id":9,"method":"does/not/exist"}`)
	if resps[0]["error"] == nil {
		t.Fatal("expected method-not-found error")
	}
	e := resps[0]["error"].(map[string]interface{})
	if int(e["code"].(float64)) != errMethodNotFound {
		t.Errorf("code = %v, want %d", e["code"], errMethodNotFound)
	}
}
