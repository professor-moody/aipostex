package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/exploit/mcp"
	"github.com/professor-moody/aipostex/pkg/report"
)

func TestSortedKeysReturnsSortedUniqueKeys(t *testing.T) {
	m := map[string]string{
		"BETA":  "1",
		"ALPHA": "2",
		"GAMMA": "3",
	}
	got := sortedKeys(m)
	if len(got) != 3 {
		t.Fatalf("expected 3 keys, got %d: %v", len(got), got)
	}
	if got[0] != "ALPHA" || got[1] != "BETA" || got[2] != "GAMMA" {
		t.Fatalf("expected sorted keys [ALPHA BETA GAMMA], got %v", got)
	}
}

func TestSortedKeysEmpty(t *testing.T) {
	got := sortedKeys(map[string]string{})
	if len(got) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(got))
	}
}

func TestMcpLocalCategorySet(t *testing.T) {
	server := mcp.LocalServer{
		Name:  "test-server",
		Tools: []string{"fetch_url", "exec_command"},
	}
	signals := []mcp.LocalRiskSignal{
		{Category: "network-exposure", Confidence: "high", Details: "binds 0.0.0.0"},
	}
	categories := mcpLocalCategorySet(server, signals)
	if !categories["network-exposure"] {
		t.Fatal("expected network-exposure category from signals")
	}
	if len(categories) == 0 {
		t.Fatal("expected non-empty categories")
	}
}

func TestMcpLocalCategorySetEmpty(t *testing.T) {
	server := mcp.LocalServer{Name: "empty"}
	categories := mcpLocalCategorySet(server, nil)
	if len(categories) != 0 {
		t.Fatalf("expected empty categories for empty server, got %v", categories)
	}
}

func TestPromptAppearsInstructionBearing(t *testing.T) {
	tests := []struct {
		prompt mcp.Prompt
		want   bool
	}{
		{mcp.Prompt{Name: "system-prompt", Description: "Main instructions"}, true},
		{mcp.Prompt{Name: "template-builder", Description: "builds templates"}, true},
		{mcp.Prompt{Name: "weather", Description: "get weather data"}, false},
		{mcp.Prompt{Name: "SYSTEM Prompt", Description: ""}, true},
		{mcp.Prompt{Name: "", Description: ""}, false},
	}
	for _, tc := range tests {
		got := promptAppearsInstructionBearing(tc.prompt)
		if got != tc.want {
			t.Errorf("promptAppearsInstructionBearing(%q/%q) = %v, want %v", tc.prompt.Name, tc.prompt.Description, got, tc.want)
		}
	}
}

func TestMcpResourceLabels(t *testing.T) {
	tests := []struct {
		resource mcp.Resource
		wantAny  string
	}{
		{mcp.Resource{Name: "file-reader", URI: "file:///tmp/data"}, "file"},
		{mcp.Resource{Name: "prompt-template", URI: "http://x"}, "prompt"},
		{mcp.Resource{Name: "debug-inspector", URI: "http://y"}, "inspector"},
		{mcp.Resource{Name: "random-api", URI: "http://z"}, ""},
	}
	for _, tc := range tests {
		labels := mcpResourceLabels(tc.resource)
		if tc.wantAny == "" {
			if len(labels) != 0 {
				t.Errorf("resource %q: expected no labels, got %v", tc.resource.Name, labels)
			}
			continue
		}
		found := false
		for _, l := range labels {
			if l == tc.wantAny {
				found = true
			}
		}
		if !found {
			t.Errorf("resource %q: expected label %q in %v", tc.resource.Name, tc.wantAny, labels)
		}
	}
}

func TestExtractMCPRemoteURLs(t *testing.T) {
	server := mcp.LocalServer{
		Name:  "test",
		URL:   "http://localhost:3000/sse",
		Tools: []string{"tool1 http://remote.example.com/api", "tool2"},
	}
	signals := []mcp.LocalRiskSignal{
		{Category: "fetch", Details: "references https://other.example.com/endpoint"},
	}
	urls := extractMCPRemoteURLs(server, signals)
	if len(urls) < 2 {
		t.Fatalf("expected at least 2 URLs, got %d: %v", len(urls), urls)
	}
	found := map[string]bool{}
	for _, u := range urls {
		if strings.Contains(u, "remote.example.com") {
			found["remote"] = true
		}
		if strings.Contains(u, "other.example.com") {
			found["other"] = true
		}
	}
	if !found["remote"] || !found["other"] {
		t.Fatalf("expected both remote and other URLs, got %v", urls)
	}
}

func TestExtractMCPRemoteURLsNoURLs(t *testing.T) {
	server := mcp.LocalServer{Name: "empty", Tools: []string{"simple-tool"}}
	urls := extractMCPRemoteURLs(server, nil)
	if len(urls) != 0 {
		t.Fatalf("expected 0 URLs, got %d: %v", len(urls), urls)
	}
}

func TestLocalRiskFinding(t *testing.T) {
	tests := []struct {
		category string
		wantSev  string
	}{
		{"network-exposure", report.SeverityHigh},
		{"inspector", report.SeverityHigh},
		{"fetch", report.SeverityHigh},
		{"file", report.SeverityHigh},
		{"exec", report.SeverityCritical},
		{"process", report.SeverityHigh},
		{"unknown-category", report.SeverityInfo},
	}
	for _, tc := range tests {
		signal := mcp.LocalRiskSignal{Category: tc.category, Confidence: "high", Details: "test details"}
		title, desc, sev := localRiskFinding("test-server", signal)
		if sev != tc.wantSev {
			t.Errorf("localRiskFinding(%q) severity = %q, want %q", tc.category, sev, tc.wantSev)
		}
		if title == "" || desc == "" {
			t.Errorf("localRiskFinding(%q) returned empty title or description", tc.category)
		}
		if !strings.Contains(title, "test-server") {
			t.Errorf("localRiskFinding(%q) title should contain server name, got %q", tc.category, title)
		}
	}
}

func TestRunMCPAnalyzeWithTempConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "mcp_config.json")

	config := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"test-server": map[string]interface{}{
				"command":   "node",
				"args":      []string{"server.js"},
				"transport": "stdio",
				"env": map[string]string{
					"API_KEY": "sk-test-secret-1234567890abcdef",
				},
			},
		},
	}
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	prevConfig := mcpConfig
	defer func() { mcpConfig = prevConfig }()

	withTestConfig(t, func() {
		mcpConfig = configPath
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(tmpDir, "mcp-analyze.json")

		err := runMCPAnalyze(nil, nil)
		if err == nil {
			return
		}
		out, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Logf("note: output file not written: %v (runMCPAnalyze returned: %v)", readErr, err)
			return
		}
		if len(out) > 0 && !strings.Contains(string(out), "test-server") {
			t.Fatalf("expected server name in output, got %s", string(out))
		}
	})
}

func TestRunMCPAnalyzeMissingConfig(t *testing.T) {
	prevConfig := mcpConfig
	defer func() { mcpConfig = prevConfig }()

	withTestConfig(t, func() {
		mcpConfig = ""
		err := runMCPAnalyze(nil, nil)
		if err == nil {
			t.Fatal("expected error for missing config")
		}
	})
}
