package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	exploitmcp "github.com/professor-moody/aipostex/pkg/exploit/mcp"
	"github.com/professor-moody/aipostex/pkg/report"
)

// mcpIsErrorRoundTripper answers tools/call with isError=true and the given
// text (which may contain a success marker), to verify the tool is reported as
// reachable-but-blocked rather than as a successful exploitation.
func mcpIsErrorRoundTripper(errText string) roundTripFunc {
	return func(req *http.Request) (*http.Response, error) {
		var payload map[string]interface{}
		body, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(body, &payload)
		switch payload["method"] {
		case "initialize":
			return jsonResponse(http.StatusOK, `{"result":{"serverInfo":{"name":"demo"}}}`), nil
		case "tools/list":
			return jsonResponse(http.StatusOK, `{"result":{"tools":[{"name":"shell","description":"Execute shell commands"},{"name":"read_file","description":"Read local file paths"}]}}`), nil
		case "tools/call":
			return jsonResponse(http.StatusOK, `{"result":{"isError":true,"content":[{"type":"text","text":`+jsonEscapeString(errText)+`}]}}`), nil
		default:
			return jsonResponse(http.StatusOK, `{"result":{}}`), nil
		}
	}
}

// P0 regression: an isError result whose text happens to contain a command
// marker ("uid=0(root)") must NOT be reported as likely-executed/Critical — the
// tool ran but blocked the action.
func TestExecuteMCPCommandInjectionIsErrorNotExploited(t *testing.T) {
	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpIsErrorRoundTripper("error: command 'id' blocked by allowlist (would have printed uid=0(root))"),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPCommandInjection(client, exploitmcp.Tool{Name: "shell"}, "id", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "tool-error" {
		t.Fatalf("isError result must yield signal=tool-error, got %q", result.Signal)
	}
	if result.Severity != report.SeverityInfo {
		t.Fatalf("isError result must be Info, got %q", result.Severity)
	}
	// And the landed must stay reachable (never execution-confirmed).
	_, strength, _ := classifyMCPPoisonProof("cmd-inject", result.Signal)
	if strength != "reachable" {
		t.Fatalf("tool-error must classify as reachable, got %q", strength)
	}
}

// P0 regression: an isError result for path-traversal must not be reported as
// file-read-confirmed even if the error text contains file-like markers.
func TestExecuteMCPPathTraversalIsErrorNotConfirmed(t *testing.T) {
	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpIsErrorRoundTripper("denied: cannot open ../../etc/passwd (root:x:0:0 lookups disabled)"),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPPathTraversal(client, exploitmcp.Tool{Name: "read_file"}, "../../etc/passwd", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "tool-error" {
		t.Fatalf("isError result must yield signal=tool-error, got %q", result.Signal)
	}
	if result.Severity != report.SeverityInfo {
		t.Fatalf("isError result must be Info, got %q", result.Severity)
	}
	if !strings.Contains(result.Title, "reachable but returned an error") {
		t.Fatalf("unexpected title %q", result.Title)
	}
}
