package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/pkg/exploit/mcp"
)

func TestRunMCPConfigHijackWritesCommandEntryAndFinding(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "mcp.json")
	writeJSONFile(t, configPath, map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"existing": map[string]interface{}{
				"command":   "node",
				"args":      []string{"existing.js"},
				"transport": "stdio",
			},
		},
	})

	outputPath := filepath.Join(tmpDir, "findings.jsonl")
	withMCPConfigHijackTestState(t, func() {
		withTestConfig(t, func() {
			cfg.Format = "jsonl"
			cfg.OutputFile = outputPath
			cfg.ForceExploit = true
			cfg.Quiet = true

			mcpConfig = configPath
			mcpHijackServer = "aipostex-hijack"
			mcpHijackCommand = "python"
			mcpHijackArgs = []string{"server.py", "--root", "/tmp"}
			mcpHijackEnv = []string{"API_KEY=secret-value"}

			if err := runMCPConfigHijack(nil, nil); err != nil {
				if _, ok := err.(*exitcode.FindingsError); !ok {
					t.Fatalf("expected FindingsError, got %v", err)
				}
			}
		})
	})

	server := loadMCPServerByName(t, configPath, "aipostex-hijack")
	if server.Command != "python" || server.Transport != "stdio" {
		t.Fatalf("unexpected server command/transport: %+v", server)
	}
	if !sameStringSet(server.Args, []string{"server.py", "--root", "/tmp"}) {
		t.Fatalf("unexpected args: %+v", server.Args)
	}
	if server.Env["API_KEY"] != "secret-value" {
		t.Fatalf("expected env value to survive parser reload, got %+v", server.Env)
	}

	backups, err := filepath.Glob(configPath + ".aipostex-bak-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("expected one backup, got %v err=%v", backups, err)
	}
	backupRaw, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatalf("reading backup: %v", err)
	}
	if !strings.Contains(string(backupRaw), "existing.js") {
		t.Fatalf("backup did not contain original config: %s", string(backupRaw))
	}

	findings := readFindingsJSONL(t, outputPath)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	meta := findings[0].Metadata
	if meta["action"] != "config-hijack" || meta["stage"] != "impact" || meta["landed"] != "influenced" {
		t.Fatalf("unexpected metadata: %#v", meta)
	}
	if meta["verified"] != true || meta["layout"] != "mcpServers" {
		t.Fatalf("expected verified mcpServers metadata, got %#v", meta)
	}
	if _, ok := meta["workflow"].(map[string]interface{}); !ok {
		t.Fatalf("expected workflow metadata, got %#v", meta["workflow"])
	}
}

func TestRunMCPConfigHijackReplacesArrayURLEntry(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "mcp-array.json")
	writeJSONFile(t, configPath, map[string]interface{}{
		"servers": []map[string]interface{}{
			{
				"name":      "remote",
				"url":       "http://old.example/mcp",
				"transport": "http",
			},
		},
	})

	outputPath := filepath.Join(tmpDir, "findings.jsonl")
	withMCPConfigHijackTestState(t, func() {
		withTestConfig(t, func() {
			cfg.Format = "jsonl"
			cfg.OutputFile = outputPath
			cfg.ForceExploit = true
			cfg.Quiet = true

			mcpConfig = configPath
			mcpHijackServer = "remote"
			mcpHijackURL = "http://127.0.0.1:3000/sse"

			if err := runMCPConfigHijack(nil, nil); err != nil {
				if _, ok := err.(*exitcode.FindingsError); !ok {
					t.Fatalf("expected FindingsError, got %v", err)
				}
			}
		})
	})

	server := loadMCPServerByName(t, configPath, "remote")
	if server.URL != "http://127.0.0.1:3000/sse" || server.Transport != "sse" {
		t.Fatalf("unexpected server URL/transport: %+v", server)
	}

	findings := readFindingsJSONL(t, outputPath)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	meta := findings[0].Metadata
	if meta["replaced"] != true || meta["layout"] != "servers" {
		t.Fatalf("expected replacement metadata for array layout, got %#v", meta)
	}
	if !strings.Contains(findings[0].Evidence, `"url": "http://127.0.0.1:3000/sse"`) {
		t.Fatalf("expected evidence to include new entry JSON, got %s", findings[0].Evidence)
	}
}

func TestRunMCPConfigHijackRequiresForceExploit(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "mcp.json")
	writeJSONFile(t, configPath, map[string]interface{}{"mcpServers": map[string]interface{}{}})

	withMCPConfigHijackTestState(t, func() {
		withTestConfig(t, func() {
			cfg.ForceExploit = false
			mcpConfig = configPath
			mcpHijackServer = "aipostex-hijack"
			mcpHijackURL = "http://127.0.0.1:3000/mcp"

			err := runMCPConfigHijack(nil, nil)
			if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
				t.Fatalf("expected --force-exploit error, got %v", err)
			}
		})
	})
}

func TestMCPConfigHijackPreservesFlatDottedLayoutWhenMCPObjectExists(t *testing.T) {
	root := map[string]interface{}{
		"mcp": map[string]interface{}{
			"enabled": true,
		},
		"mcp.servers": map[string]interface{}{
			"existing": map[string]interface{}{
				"url":       "http://old.example/mcp",
				"transport": "http",
			},
		},
	}

	layout, replaced, err := upsertMCPConfigServerEntry(root, "aipostex-hijack", map[string]interface{}{
		"url":       "http://127.0.0.1:3000/mcp",
		"transport": "http",
	})
	if err != nil {
		t.Fatalf("upsertMCPConfigServerEntry: %v", err)
	}
	if layout != "mcp.servers" || replaced {
		t.Fatalf("expected flat dotted layout without replacement, got layout=%q replaced=%v", layout, replaced)
	}
	nested := root["mcp"].(map[string]interface{})
	if _, ok := nested["mcpServers"]; ok {
		t.Fatalf("did not expect unrelated mcp object to gain nested mcpServers: %#v", nested)
	}
	servers := root["mcp.servers"].(map[string]interface{})
	if _, ok := servers["aipostex-hijack"]; !ok {
		t.Fatalf("expected new server in flat dotted layout: %#v", servers)
	}
}

func withMCPConfigHijackTestState(t *testing.T, fn func()) {
	t.Helper()
	prevConfig := mcpConfig
	prevServer := mcpHijackServer
	prevCommand := mcpHijackCommand
	prevArgs := append([]string(nil), mcpHijackArgs...)
	prevEnv := append([]string(nil), mcpHijackEnv...)
	prevURL := mcpHijackURL
	prevTransport := mcpHijackTransport
	defer func() {
		mcpConfig = prevConfig
		mcpHijackServer = prevServer
		mcpHijackCommand = prevCommand
		mcpHijackArgs = prevArgs
		mcpHijackEnv = prevEnv
		mcpHijackURL = prevURL
		mcpHijackTransport = prevTransport
	}()

	mcpConfig = ""
	mcpHijackServer = "aipostex-hijack"
	mcpHijackCommand = ""
	mcpHijackArgs = nil
	mcpHijackEnv = nil
	mcpHijackURL = ""
	mcpHijackTransport = ""
	fn()
}

func writeJSONFile(t *testing.T, path string, value interface{}) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshaling json: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing json: %v", err)
	}
}

func loadMCPServerByName(t *testing.T, path, name string) mcp.LocalServer {
	t.Helper()
	servers, err := mcp.LoadConfig(path)
	if err != nil {
		t.Fatalf("loading MCP config: %v", err)
	}
	for _, server := range servers {
		if server.Name == name {
			return server
		}
	}
	t.Fatalf("server %q not found in %+v", name, servers)
	return mcp.LocalServer{}
}
