package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/pkg/exploit/mcp"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

var mcpAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze a local MCP config file",
	Long:  "Analyze a local MCP config file for transport choices, remote exposure, embedded credentials, declared tool capabilities, and tool-collision risk.",
	Example: strings.Join([]string{
		formatCommandExample("mcp analyze --config ~/.config/Claude/claude_desktop_config.json"),
		"# Proof: surfaces plaintext secrets, non-loopback bindings, and risky declared capabilities.",
	}, "\n"),
	RunE: runMCPAnalyze,
}

func runMCPAnalyze(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(mcpConfig) == "" {
		return missingFlagError("config", formatCommandExample("mcp analyze --config ~/.config/Claude/claude_desktop_config.json"))
	}
	servers, err := mcp.LoadConfig(mcpConfig)
	if err != nil {
		return fmt.Errorf("loading MCP config: %w", err)
	}

	findings := make([]report.Finding, 0, len(servers))
	workflowPlans := make([]workflowPlan, 0)
	for _, server := range servers {
		signals := mcp.AnalyzeLocalServer(server)
		categorySet := mcpLocalCategorySet(server, signals)
		inspectorLike := categorySet["inspector"]
		baseMetadata := map[string]interface{}{
			"module":        "mcp",
			"action":        "analyze",
			"mutating":      false,
			"provider":      "mcp",
			"config_source": mcpConfig,
			"server":        server.Name,
			"transport":     server.Transport,
			"url":           server.URL,
			"command":       server.Command,
			"env_keys":      joinPreview(sortedKeys(server.Env), 10),
			"tool_count":    len(server.Tools),
		}
		baseMetadata = applyStageLanded(baseMetadata, "recon", "reachable", "mcp-analyze", "config-entry")
		findings = append(findings, newExploitFinding(
			report.SourceMCP,
			mcpConfig,
			fmt.Sprintf("MCP config entry analyzed: %s", server.Name),
			report.SeverityInfo,
			fmt.Sprintf("Configured MCP server %s uses %s transport", server.Name, server.Transport),
			baseMetadata,
		))

		if strings.TrimSpace(server.Command) != "" {
			cmdFinding := newExploitFinding(
				report.SourceMCP,
				mcpConfig,
				fmt.Sprintf("MCP config launches local command: %s", server.Name),
				report.SeverityHigh,
				fmt.Sprintf("Configured MCP server %s launches local command %s", server.Name, server.Command),
				map[string]interface{}{
					"module":        "mcp",
					"action":        "analyze",
					"mutating":      false,
					"provider":      "mcp",
					"config_source": mcpConfig,
					"server":        server.Name,
					"transport":     server.Transport,
					"command":       server.Command,
					"capability":    "process",
					"confidence":    "high",
				},
			)
			cmdFinding.Evidence = fmt.Sprintf("server=%s\ncommand=%s\nargs=%s\nenv_keys=%s",
				server.Name, server.Command, strings.Join(server.Args, " "), joinPreview(sortedKeys(server.Env), 10))
			findings = append(findings, cmdFinding)
		}

		if strings.TrimSpace(server.URL) != "" {
			plan := buildMCPAnalyzeRemotePlan(server.URL, categorySet, inspectorLike)
			finding := newExploitFinding(
				report.SourceMCP,
				mcpConfig,
				fmt.Sprintf("MCP config points to remote URL: %s", server.Name),
				report.SeverityMedium,
				fmt.Sprintf("Configured MCP server %s references remote endpoint %s", server.Name, server.URL),
				map[string]interface{}{
					"module":        "mcp",
					"action":        "analyze",
					"mutating":      false,
					"provider":      "mcp",
					"config_source": mcpConfig,
					"server":        server.Name,
					"transport":     server.Transport,
					"url":           server.URL,
				},
			)
			finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "mcp-analyze", "remote-url", summarizeCapabilityLabels(mapKeysBool(categorySet)...))
			finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
			findings = append(findings, finding)
			workflowPlans = append(workflowPlans, plan)
		}

		for _, secret := range mcp.ExtractCredentialEnv(server.Env) {
			finding := newExploitFinding(
				report.SourceMCP,
				mcpConfig,
				fmt.Sprintf("MCP config embeds plaintext credential: %s", secret.Key),
				report.SeverityHigh,
				fmt.Sprintf("Configured MCP server %s embeds plaintext credential material in %s", server.Name, secret.Key),
				map[string]interface{}{
					"module":           "mcp",
					"action":           "analyze",
					"mutating":         false,
					"provider":         "mcp",
					"config_source":    mcpConfig,
					"server":           server.Name,
					"env_key":          secret.Key,
					"console_evidence": secret.Value,
				},
			)
			finding.Evidence = secret.Value
			finding.Metadata["extracted_credentials"] = lootCredentialRecord("mcp-config-secret", secret.Key, secret.Value, mcpConfig, fmt.Sprintf("server %s config env", server.Name))
			findings = append(findings, finding)
		}

		for _, signal := range signals {
			title, description, severity := localRiskFinding(server.Name, signal)
			riskFinding := newExploitFinding(
				report.SourceMCP,
				mcpConfig,
				title,
				severity,
				description,
				map[string]interface{}{
					"module":        "mcp",
					"action":        "analyze",
					"mutating":      false,
					"provider":      "mcp",
					"config_source": mcpConfig,
					"server":        server.Name,
					"transport":     server.Transport,
					"capability":    signal.Category,
					"confidence":    signal.Confidence,
				},
			)
			riskFinding.Evidence = fmt.Sprintf("server=%s\ncategory=%s\nconfidence=%s\ndetails=%s",
				server.Name, signal.Category, signal.Confidence, signal.Details)
			findings = append(findings, riskFinding)
		}
		for _, remoteURL := range extractMCPRemoteURLs(server, signals) {
			if canonicalServiceURL(remoteURL) == canonicalServiceURL(server.URL) {
				continue
			}
			plan := buildMCPAnalyzeRemotePlan(remoteURL, categorySet, inspectorLike)
			finding := newExploitFinding(
				report.SourceMCP,
				mcpConfig,
				fmt.Sprintf("MCP config correlates remote workflow: %s", server.Name),
				report.SeverityMedium,
				fmt.Sprintf("Inspector or tool metadata for %s referenced remote MCP workflow %s", server.Name, remoteURL),
				map[string]interface{}{
					"module":        "mcp",
					"action":        "analyze",
					"mutating":      false,
					"provider":      "mcp",
					"config_source": mcpConfig,
					"server":        server.Name,
					"url":           remoteURL,
					"capability":    summarizeCapabilityLabels(mapKeysBool(categorySet)...),
				},
			)
			finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "mcp-analyze", "remote-workflow")
			finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
			findings = append(findings, finding)
			workflowPlans = append(workflowPlans, plan)
		}
	}

	for _, collision := range mcp.FindToolCollisions(servers) {
		findings = append(findings, newExploitFinding(
			report.SourceMCP,
			mcpConfig,
			fmt.Sprintf("MCP tool shadowing risk: %s", collision.Name),
			report.SeverityMedium,
			fmt.Sprintf("Multiple MCP servers advertise tool name %s (%s), creating a tool shadowing trust-boundary risk", collision.Name, strings.Join(collision.Servers, ", ")),
			map[string]interface{}{
				"module":        "mcp",
				"action":        "analyze",
				"mutating":      false,
				"provider":      "mcp",
				"config_source": mcpConfig,
				"tool":          collision.Name,
				"collision":     strings.Join(collision.Servers, ", "),
			},
		))
	}

	infof("Analyzed %d MCP config server entries", len(servers))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "mcp",
		Action:              "analyze",
		ResourcesEnumerated: len(servers),
		PartialFailures:     0,
		Mutating:            false,
		WorkflowPlans:       workflowPlans,
	})
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return uniqueSortedStrings(keys)
}

func mcpLocalCategorySet(server mcp.LocalServer, signals []mcp.LocalRiskSignal) map[string]bool {
	out := make(map[string]bool)
	for _, tool := range server.Tools {
		for _, capability := range mcp.ClassifyToolDetailed(mcp.Tool{Name: tool, Description: tool}) {
			out[capability.Category] = true
		}
	}
	for _, signal := range signals {
		out[signal.Category] = true
	}
	return out
}

func promptAppearsInstructionBearing(prompt mcp.Prompt) bool {
	haystack := strings.ToLower(strings.TrimSpace(prompt.Name + " " + prompt.Description))
	return stringutil.ContainsAny(haystack, "prompt", "instruction", "template", "system")
}

func mcpResourceLabels(resource mcp.Resource) []string {
	haystack := strings.ToLower(strings.TrimSpace(resource.Name + " " + resource.URI))
	labels := make([]string, 0, 3)
	if stringutil.ContainsAny(haystack, "file://", "/tmp/", "/var/", "/home/", "file", "path", "directory") {
		labels = append(labels, "file")
	}
	if stringutil.ContainsAny(haystack, "prompt", "instruction", "template") {
		labels = append(labels, "prompt")
	}
	if stringutil.ContainsAny(haystack, "debug", "inspect", "inspector") {
		labels = append(labels, "inspector")
	}
	return uniqueSortedStrings(labels)
}

func extractMCPRemoteURLs(server mcp.LocalServer, signals []mcp.LocalRiskSignal) []string {
	out := make([]string, 0, 4)
	for _, signal := range signals {
		out = append(out, mcpURLPattern.FindAllString(signal.Details, -1)...)
	}
	for _, tool := range server.Tools {
		out = append(out, mcpURLPattern.FindAllString(tool, -1)...)
	}
	if strings.TrimSpace(server.URL) != "" {
		out = append(out, server.URL)
	}
	return uniqueSortedStrings(out)
}

func localRiskFinding(serverName string, signal mcp.LocalRiskSignal) (string, string, string) {
	switch signal.Category {
	case "network-exposure":
		return fmt.Sprintf("MCP config exposes server beyond localhost: %s", serverName), signal.Details, report.SeverityHigh
	case "inspector":
		return fmt.Sprintf("MCP config references inspector/debug workflow: %s", serverName), signal.Details, report.SeverityHigh
	case "fetch":
		return fmt.Sprintf("MCP config declares fetch-capable tooling: %s", serverName), signal.Details, report.SeverityHigh
	case "file":
		return fmt.Sprintf("MCP config declares file-access tooling: %s", serverName), signal.Details, report.SeverityHigh
	case "exec":
		return fmt.Sprintf("MCP config declares exec-capable tooling: %s", serverName), signal.Details, report.SeverityCritical
	case "process":
		return fmt.Sprintf("MCP config declares process-launch tooling: %s", serverName), signal.Details, report.SeverityHigh
	default:
		return fmt.Sprintf("MCP config risk signal: %s", serverName), signal.Details, report.SeverityInfo
	}
}
