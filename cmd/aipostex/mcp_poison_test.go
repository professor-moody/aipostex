package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	exploitmcp "github.com/professor-moody/aipostex/pkg/exploit/mcp"
)

func TestClassifyMCPPoisonProofGeneric(t *testing.T) {
	stage, strength, labels := classifyMCPPoisonProof("generic", "payload-accepted")
	if stage != "impact" || strength != "influenced" {
		t.Fatalf("expected proof/influenced, got %s/%s", stage, strength)
	}
	if len(labels) != 2 || labels[0] != "prompt-influence" {
		t.Fatalf("expected generic labels, got %v", labels)
	}
}

func TestClassifyMCPPoisonProofSSRFWithProviderMarker(t *testing.T) {
	stage, strength, _ := classifyMCPPoisonProof("ssrf-cloud", "provider-marker")
	if stage != "impact" || strength != "read-confirmed" {
		t.Fatalf("expected proof/read-confirmed, got %s/%s", stage, strength)
	}
}

func TestClassifyMCPPoisonProofSSRFWithoutMarker(t *testing.T) {
	stage, strength, _ := classifyMCPPoisonProof("ssrf-cloud", "no-signal")
	if stage != "impact" || strength != "reachable" {
		t.Fatalf("expected proof/reachable, got %s/%s", stage, strength)
	}
}

func TestClassifyMCPPoisonProofCmdInjectExecuted(t *testing.T) {
	stage, strength, labels := classifyMCPPoisonProof("cmd-inject", "likely-executed")
	// A command-output marker is strong heuristic evidence but not nonce-confirmed
	// execution, so the "likely" hedge in the title must be matched by an honest
	// proof/influenced classification — never an execution-confirmed/takeover claim.
	if stage != "impact" || strength != "influenced" {
		t.Fatalf("expected proof/influenced, got %s/%s", stage, strength)
	}
	found := false
	for _, l := range labels {
		if l == "command-injection" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected command-injection label, got %v", labels)
	}
}

func TestClassifyMCPPoisonProofPathTraversalConfirmed(t *testing.T) {
	stage, strength, _ := classifyMCPPoisonProof("path-traversal", "file-read-confirmed")
	if stage != "impact" || strength != "read-confirmed" {
		t.Fatalf("expected proof/read-confirmed, got %s/%s", stage, strength)
	}
}

func TestClassifyMCPPoisonProofUnknownMode(t *testing.T) {
	stage, strength, _ := classifyMCPPoisonProof("unknown-mode", "")
	if stage != "impact" || strength != "reachable" {
		t.Fatalf("expected proof/reachable for unknown mode, got %s/%s", stage, strength)
	}
}

func TestExecuteMCPCloudSSRFValidationRequiresTarget(t *testing.T) {
	prevAlias := mcpTargetAlias
	prevURL := mcpURL
	defer func() {
		mcpTargetAlias = prevAlias
		mcpURL = prevURL
	}()

	mcpTargetAlias = ""
	mcpURL = ""
	_, err := resolveMCPCloudTarget()
	if err == nil {
		t.Fatal("expected error when neither alias nor URL provided")
	}
}

func TestExecuteMCPCloudSSRFResolvesAlias(t *testing.T) {
	prevAlias := mcpTargetAlias
	prevURL := mcpURL
	defer func() {
		mcpTargetAlias = prevAlias
		mcpURL = prevURL
	}()

	mcpTargetAlias = "aws-imds"
	mcpURL = ""
	target, err := resolveMCPCloudTarget()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Alias != "aws-imds" {
		t.Fatalf("expected aws-imds alias, got %q", target.Alias)
	}
}

func TestCommandVariantsAreUniqueAndMinimal(t *testing.T) {
	variants := commandVariants("id")
	seen := make(map[string]struct{})
	for _, v := range variants {
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate variant: %q", v)
		}
		seen[v] = struct{}{}
	}
	if len(variants) < 3 {
		t.Fatalf("expected at least 3 variants, got %d", len(variants))
	}
	// The plain payload MUST be first: on a direct-exec tool it is the variant that runs
	// cleanly and returns the arithmetic proof marker. If it sorts behind the breakout
	// prefixes, a low --attempts budget cuts it off and execution is never confirmed.
	if variants[0] != "id" {
		t.Fatalf("expected plain command first, got %q (full: %v)", variants[0], variants)
	}
}

func TestTraversalCandidatesContainOriginalPath(t *testing.T) {
	candidates := traversalCandidates("../../etc/passwd")
	found := false
	for _, c := range candidates {
		if c == "../../etc/passwd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected original path in candidates, got %v", candidates)
	}
}

func TestCloudProviderLabelMapsCorrectly(t *testing.T) {
	tests := []struct {
		alias string
		want  string
	}{
		{"aws-imds", "AWS"},
		{"gcp-metadata", "GCP"},
		{"azure-imds", "Azure"},
		{"custom", "cloud metadata"},
	}
	for _, tc := range tests {
		got := cloudProviderLabel(mcpCloudTarget{Alias: tc.alias})
		if got != tc.want {
			t.Errorf("cloudProviderLabel(%q) = %q, want %q", tc.alias, got, tc.want)
		}
	}
}

func TestLimitedStringsRespectsMax(t *testing.T) {
	input := []string{"a", "b", "c", "d"}
	got := limitedStrings(input, 2)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("expected [a b], got %v", got)
	}

	all := limitedStrings(input, 10)
	if len(all) != 4 {
		t.Fatalf("expected all 4 items, got %d", len(all))
	}
}

func TestContainsChoiceFindsAndMisses(t *testing.T) {
	choices := []string{"generic", "ssrf-cloud", "cmd-inject"}
	if !containsChoice(choices, "generic") {
		t.Fatal("expected to find generic")
	}
	if containsChoice(choices, "missing") {
		t.Fatal("did not expect to find missing")
	}
}

func mcpPoisonRoundTripper(toolResponse string) roundTripFunc {
	return func(req *http.Request) (*http.Response, error) {
		var payload map[string]interface{}
		body, _ := io.ReadAll(req.Body)
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}
		switch payload["method"] {
		case "initialize":
			return jsonResponse(http.StatusOK, `{"result":{"serverInfo":{"name":"demo"}}}`), nil
		case "tools/list":
			return jsonResponse(http.StatusOK, `{"result":{"tools":[{"name":"fetch","description":"HTTP fetch tool"},{"name":"shell","description":"Execute shell commands"},{"name":"read_file","description":"Read local file paths"}]}}`), nil
		case "tools/call":
			return jsonResponse(http.StatusOK, `{"result":{"content":[{"type":"text","text":`+jsonEscapeString(toolResponse)+`}]}}`), nil
		default:
			return jsonResponse(http.StatusOK, `{"result":{}}`), nil
		}
	}
}

func jsonEscapeString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestExecuteMCPCloudSSRFProviderMarker(t *testing.T) {
	prevAlias := mcpTargetAlias
	prevURL := mcpURL
	defer func() {
		mcpTargetAlias = prevAlias
		mcpURL = prevURL
	}()

	mcpTargetAlias = "aws-imds"
	mcpURL = ""

	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpPoisonRoundTripper("ami-0123456789abcdef0 instance-id i-abc123"),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPCloudSSRF(client, "fetch")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "provider-marker" {
		t.Fatalf("expected provider-marker signal, got %q", result.Signal)
	}
	if result.Severity != "high" {
		t.Fatalf("expected high severity, got %q", result.Severity)
	}
	if !strings.Contains(result.Title, "AWS") {
		t.Fatalf("expected AWS in title, got %q", result.Title)
	}
}

func TestExecuteMCPCloudSSRFNoSignal(t *testing.T) {
	prevAlias := mcpTargetAlias
	prevURL := mcpURL
	defer func() {
		mcpTargetAlias = prevAlias
		mcpURL = prevURL
	}()

	mcpTargetAlias = ""
	mcpURL = "http://169.254.169.254/custom"

	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpPoisonRoundTripper("some unrelated response text"),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPCloudSSRF(client, "fetch")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "no-signal" {
		t.Fatalf("expected no-signal, got %q", result.Signal)
	}
	if result.Severity != "medium" {
		t.Fatalf("expected medium severity, got %q", result.Severity)
	}
}

func TestExecuteMCPCommandInjectionLikelyExecuted(t *testing.T) {
	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpPoisonRoundTripper("uid=1000(user) gid=1000(user) groups=1000(user)"),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPCommandInjection(client, exploitmcp.Tool{Name: "shell"}, "id", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "likely-executed" {
		t.Fatalf("expected likely-executed signal, got %q", result.Signal)
	}
	if result.Severity != "critical" {
		t.Fatalf("expected critical severity, got %q", result.Severity)
	}
	if !strings.Contains(result.Title, "command-injection signal observed") {
		t.Fatalf("expected command-injection signal title, got %q", result.Title)
	}
}

func TestExecuteMCPCommandInjectionPossibleEcho(t *testing.T) {
	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpPoisonRoundTripper("you sent: ;id as input"),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPCommandInjection(client, exploitmcp.Tool{Name: "shell"}, "id", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "possible-echo" {
		t.Fatalf("expected possible-echo signal, got %q", result.Signal)
	}
	if result.Severity != "medium" {
		t.Fatalf("expected medium severity, got %q", result.Severity)
	}
}

func TestExecuteMCPCommandInjectionNoSignal(t *testing.T) {
	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpPoisonRoundTripper("Nothing relevant here."),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPCommandInjection(client, exploitmcp.Tool{Name: "shell"}, "id", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "no-signal" {
		t.Fatalf("expected no-signal, got %q", result.Signal)
	}
}

func TestExecuteMCPPathTraversalFileReadConfirmed(t *testing.T) {
	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpPoisonRoundTripper("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPPathTraversal(client, exploitmcp.Tool{Name: "read_file"}, "../../etc/passwd", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "file-read-confirmed" {
		t.Fatalf("expected file-read-confirmed signal, got %q", result.Signal)
	}
	if result.Severity != "high" {
		t.Fatalf("expected high severity, got %q", result.Severity)
	}
}

func TestExecuteMCPPathTraversalPathDisclosure(t *testing.T) {
	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpPoisonRoundTripper("Error: file not found at ../../etc/passwd"),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPPathTraversal(client, exploitmcp.Tool{Name: "read_file"}, "../../etc/passwd", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "path-disclosure" {
		t.Fatalf("expected path-disclosure signal, got %q", result.Signal)
	}
}

func TestExecuteMCPPathTraversalNoSignal(t *testing.T) {
	client, err := exploitmcp.NewClient(context.Background(), "http://127.0.0.1:3000/message", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = &http.Client{
		Transport: mcpPoisonRoundTripper("Access denied."),
	}
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}

	result, err := executeMCPPathTraversal(client, exploitmcp.Tool{Name: "read_file"}, "../../etc/shadow", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signal != "no-signal" {
		t.Fatalf("expected no-signal, got %q", result.Signal)
	}
}

func TestRunMCPPoisonSSRFCloudEndToEnd(t *testing.T) {
	prevTarget := mcpTarget
	prevFactory := mcpClientFactory
	prevErr := stderrWriter
	prevMode := mcpMode
	prevAlias := mcpTargetAlias
	prevURL := mcpURL
	prevAttempts := mcpAttempts
	prevTool := mcpTool
	defer func() {
		mcpTarget = prevTarget
		mcpClientFactory = prevFactory
		stderrWriter = prevErr
		mcpMode = prevMode
		mcpTargetAlias = prevAlias
		mcpURL = prevURL
		mcpAttempts = prevAttempts
		mcpTool = prevTool
	}()

	withTestConfig(t, func() {
		mcpTarget = "http://127.0.0.1:3000/message"
		mcpMode = "ssrf-cloud"
		mcpTargetAlias = "aws-imds"
		mcpURL = ""
		mcpAttempts = 1
		mcpTool = ""
		cfg.ForceExploit = true
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ssrf-cloud.jsonl")
		var stderr bytes.Buffer
		stderrWriter = &stderr
		mcpClientFactory = func() (*exploitmcp.Client, error) {
			client, err := exploitmcp.NewClient(context.Background(), mcpTarget, cfg.Timeout, nil)
			if err != nil {
				return nil, err
			}
			client.HTTPClient = &http.Client{
				Transport: mcpPoisonRoundTripper("ami-0abcdef1234567890 iam/security-credentials"),
			}
			return client, nil
		}

		err := runMCPPoison(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}

		data, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(data)
		if !strings.Contains(out, "ssrf") || !strings.Contains(out, "provider-marker") {
			t.Fatalf("expected ssrf/provider-marker finding, got %s", out)
		}
	})
}

func TestRunMCPPoisonCmdInjectEndToEnd(t *testing.T) {
	prevTarget := mcpTarget
	prevFactory := mcpClientFactory
	prevErr := stderrWriter
	prevMode := mcpMode
	prevCommand := mcpCommand
	prevAttempts := mcpAttempts
	prevTool := mcpTool
	defer func() {
		mcpTarget = prevTarget
		mcpClientFactory = prevFactory
		stderrWriter = prevErr
		mcpMode = prevMode
		mcpCommand = prevCommand
		mcpAttempts = prevAttempts
		mcpTool = prevTool
	}()

	withTestConfig(t, func() {
		mcpTarget = "http://127.0.0.1:3000/message"
		mcpMode = "cmd-inject"
		mcpCommand = "id"
		mcpAttempts = 3
		mcpTool = ""
		cfg.ForceExploit = true
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "cmd-inject.jsonl")
		var stderr bytes.Buffer
		stderrWriter = &stderr
		mcpClientFactory = func() (*exploitmcp.Client, error) {
			client, err := exploitmcp.NewClient(context.Background(), mcpTarget, cfg.Timeout, nil)
			if err != nil {
				return nil, err
			}
			client.HTTPClient = &http.Client{
				Transport: mcpPoisonRoundTripper("uid=0(root) gid=0(root)"),
			}
			return client, nil
		}

		err := runMCPPoison(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}

		data, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(data)
		if !strings.Contains(out, "cmd-inject") || !strings.Contains(out, "likely-executed") {
			t.Fatalf("expected cmd-inject/likely-executed finding, got %s", out)
		}
	})
}

func TestRunMCPPoisonPathTraversalEndToEnd(t *testing.T) {
	prevTarget := mcpTarget
	prevFactory := mcpClientFactory
	prevErr := stderrWriter
	prevMode := mcpMode
	prevPath := mcpPath
	prevAttempts := mcpAttempts
	prevTool := mcpTool
	defer func() {
		mcpTarget = prevTarget
		mcpClientFactory = prevFactory
		stderrWriter = prevErr
		mcpMode = prevMode
		mcpPath = prevPath
		mcpAttempts = prevAttempts
		mcpTool = prevTool
	}()

	withTestConfig(t, func() {
		mcpTarget = "http://127.0.0.1:3000/message"
		mcpMode = "path-traversal"
		mcpPath = "../../etc/passwd"
		mcpAttempts = 3
		mcpTool = ""
		cfg.ForceExploit = true
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "path-traversal.jsonl")
		var stderr bytes.Buffer
		stderrWriter = &stderr
		mcpClientFactory = func() (*exploitmcp.Client, error) {
			client, err := exploitmcp.NewClient(context.Background(), mcpTarget, cfg.Timeout, nil)
			if err != nil {
				return nil, err
			}
			client.HTTPClient = &http.Client{
				Transport: mcpPoisonRoundTripper("root:x:0:0:root:/root:/bin/bash"),
			}
			return client, nil
		}

		err := runMCPPoison(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}

		data, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(data)
		if !strings.Contains(out, "path-traversal") || !strings.Contains(out, "file-read-confirmed") {
			t.Fatalf("expected path-traversal/file-read-confirmed finding, got %s", out)
		}
	})
}

func TestClassifyCloudMetadataResponse(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		markers    []string
		wantSignal string
		wantMatch  string
	}{
		{"matches ami marker", "ami-0123456789abcdef0", []string{"ami-"}, "provider-marker", "ami-"},
		{"matches iam marker", "iam/security-credentials/role", []string{"iam/security-credentials"}, "provider-marker", "iam/security-credentials"},
		{"no markers match", "hello world", []string{"ami-", "compute"}, "no-signal", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signal, matched := classifyCloudMetadataResponse(tc.response, tc.markers)
			if signal != tc.wantSignal {
				t.Fatalf("signal = %q, want %q", signal, tc.wantSignal)
			}
			if matched != tc.wantMatch {
				t.Fatalf("matched = %q, want %q", matched, tc.wantMatch)
			}
		})
	}
}

func TestClassifyCommandResponse(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		response   string
		wantSignal string
	}{
		{"uid marker means executed", "id", "uid=1000(user) gid=1000(user)", "likely-executed"},
		{"root marker means executed", "whoami", "root", "likely-executed"},
		{"echo of command", "id", "you sent: ;id", "possible-echo"},
		{"no match", "id", "nothing relevant", "no-signal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signal, _ := classifyCommandResponse(tc.command, tc.response)
			if signal != tc.wantSignal {
				t.Fatalf("signal = %q, want %q", signal, tc.wantSignal)
			}
		})
	}
}

func TestClassifyTraversalResponse(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		response   string
		wantSignal string
	}{
		{"passwd content", "../../etc/passwd", "root:x:0:0:root:/root:/bin/bash", "file-read-confirmed"},
		{"ssh key content", "../../.ssh/id_rsa", "-----begin openssh private key-----", "file-read-confirmed"},
		{"path echoed back", "../../etc/passwd", "Cannot read ../../etc/passwd", "path-disclosure"},
		{"no match", "../../etc/hosts", "access denied", "no-signal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signal, _ := classifyTraversalResponse(tc.path, tc.response)
			if signal != tc.wantSignal {
				t.Fatalf("signal = %q, want %q", signal, tc.wantSignal)
			}
		})
	}
}

func TestGenericPayloadCandidatesLimit(t *testing.T) {
	candidates := genericPayloadCandidates("test payload", 2)
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
}

func TestValidateMCPPoisonInputs(t *testing.T) {
	prevAttempts := mcpAttempts
	defer func() { mcpAttempts = prevAttempts }()

	mcpAttempts = 0
	if err := validateMCPPoisonInputs("generic"); err == nil {
		t.Fatal("expected error for zero attempts")
	}

	mcpAttempts = -1
	if err := validateMCPPoisonInputs("generic"); err == nil {
		t.Fatal("expected error for negative attempts")
	}
}
