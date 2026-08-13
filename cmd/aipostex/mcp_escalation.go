package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	mcpEscapePathArg       string
	mcpEscapeAllowedPrefix string
	mcpEscapeTarget        string
	mcpSSTIArg             string
)

var mcpSandboxEscapeCmd = &cobra.Command{
	Use:         "sandbox-escape",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Probe an MCP filesystem tool for a path-based sandbox escape (requires --force-exploit)",
	Long: `Test whether an MCP filesystem read tool enforces its advertised directory boundary. Sends a
prefix-check-bypass path (allowed-prefix + traversal) and a bare absolute path, and checks whether
the tool returns content from outside the sandbox (e.g. /etc/passwd) — the class of flaw assigned
CVE-2025-53109 / CVE-2025-53110. Auto-detects a read-like tool if --tool is not given.

Reads only, but gated because it deliberately reaches outside the advertised sandbox.`,
	Example: formatCommandExample("mcp --target http://127.0.0.1:3000 sandbox-escape --allowed-prefix /data/documents --force-exploit"),
	RunE:    runMCPSandboxEscape,
}

var mcpSSTICmd = &cobra.Command{
	Use:         "ssti",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Probe an MCP rendering/formatting tool for server-side template injection (requires --force-exploit)",
	Long: `Send template-injection payloads to an MCP rendering/formatting tool and check the output for
evaluation. Prioritizes the Jinja2 lipsum.__globals__ signal — which only exists inside the
server's Python runtime, so it cannot be hallucinated — over bare arithmetic. A globals leak
confirms an SSTI that reaches the Python runtime (a code-execution surface). Auto-detects a
render-like tool if --tool is not given.

Read-only, but gated because it probes for a code-execution surface.`,
	Example: formatCommandExample("mcp --target http://127.0.0.1:3000 ssti --tool render_report --arg report_data --force-exploit"),
	RunE:    runMCPSSTI,
}

func init() {
	mcpSandboxEscapeCmd.Flags().StringVar(&mcpTool, "tool", "", "Filesystem read tool name (auto-detected if empty)")
	mcpSandboxEscapeCmd.Flags().StringVar(&mcpEscapePathArg, "path-arg", "path", "Name of the tool's path argument")
	mcpSandboxEscapeCmd.Flags().StringVar(&mcpEscapeAllowedPrefix, "allowed-prefix", "/data/documents", "The tool's advertised allowed directory")
	mcpSandboxEscapeCmd.Flags().StringVar(&mcpEscapeTarget, "escape-target", "/etc/passwd", "File outside the sandbox to try to read")

	mcpSSTICmd.Flags().StringVar(&mcpTool, "tool", "", "Rendering/formatting tool name (auto-detected if empty)")
	mcpSSTICmd.Flags().StringVar(&mcpSSTIArg, "arg", "content", "Name of the tool argument that gets rendered")

	mcpCmd.AddCommand(mcpSandboxEscapeCmd, mcpSSTICmd)
}

func runMCPSandboxEscape(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("mcp sandbox-escape"); err != nil {
		return err
	}
	if !strings.EqualFold(mcpTransport, "stdio") && strings.TrimSpace(mcpTarget) == "" {
		return missingFlagError("target", formatCommandExample("mcp --target http://127.0.0.1:3000 sandbox-escape --force-exploit"))
	}
	client, err := mcpClientFactory()
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Initialize(); err != nil {
		return err
	}
	res, err := client.SandboxEscape(mcpTool, mcpEscapePathArg, mcpEscapeAllowedPrefix, mcpEscapeTarget)
	if err != nil {
		return fmt.Errorf("mcp sandbox-escape: %w", err)
	}

	severity := report.SeverityInfo
	stage, landed := "recon", "reachable"
	title := fmt.Sprintf("MCP filesystem tool %q enforces its sandbox on %s", res.Tool, mcpTarget)
	desc := "The filesystem read tool rejected path-traversal and absolute-path escapes; no content outside the advertised sandbox was returned."
	if res.Escaped {
		severity = report.SeverityHigh
		stage, landed = "impact", "read-confirmed"
		title = fmt.Sprintf("MCP filesystem sandbox escaped via %s on %s", res.Technique, mcpTarget)
		desc = fmt.Sprintf("The %q tool returned %s content from outside its advertised directory using a %s payload — a path-validation flaw that lets an attacker read arbitrary files.", res.Tool, mcpEscapeTarget, res.Technique)
	}

	finding := newExploitFinding(report.SourceMCP, mcpTarget, title, severity, desc,
		map[string]interface{}{
			"module": "mcp", "action": "sandbox-escape", "mutating": false, "provider": "mcp",
			"tool":             res.Tool,
			"escaped":          res.Escaped,
			"escape_technique": res.Technique,
		})
	finding.Evidence = res.Evidence
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "mcp-sandbox-escape", "filesystem")
	escapePlan := buildMCPEscalationWorkflowPlan(mcpTarget, "sandbox-escape")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, escapePlan)
	infof("MCP sandbox-escape: tool=%s escaped=%t", res.Tool, res.Escaped)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module: "mcp", Action: "sandbox-escape", ResourcesEnumerated: 1, Mutating: false,
		WorkflowPlans: []workflowPlan{escapePlan},
	})
}

func runMCPSSTI(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("mcp ssti"); err != nil {
		return err
	}
	if !strings.EqualFold(mcpTransport, "stdio") && strings.TrimSpace(mcpTarget) == "" {
		return missingFlagError("target", formatCommandExample("mcp --target http://127.0.0.1:3000 ssti --force-exploit"))
	}
	client, err := mcpClientFactory()
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Initialize(); err != nil {
		return err
	}
	res, err := client.SSTIProbe(mcpTool, mcpSSTIArg)
	if err != nil {
		return fmt.Errorf("mcp ssti: %w", err)
	}

	severity := report.SeverityInfo
	stage, landed := "recon", "reachable"
	title := fmt.Sprintf("MCP tool %q not template-injectable on %s", res.Tool, mcpTarget)
	desc := "The rendering tool returned the template payloads as literal text; no server-side template evaluation was observed."
	if res.Confirmed {
		if strings.Contains(res.Signal, "globals") {
			severity = report.SeverityHigh
			stage, landed = "impact", "read-confirmed"
		} else {
			severity = report.SeverityMedium
			stage, landed = "impact", "influenced"
		}
		title = fmt.Sprintf("MCP tool %q is template-injectable (SSTI) on %s", res.Tool, mcpTarget)
		desc = fmt.Sprintf("The %q tool evaluated an injected template payload — %s. This is a server-side template injection reachable through the tool's rendered argument.", res.Tool, res.Signal)
	}

	finding := newExploitFinding(report.SourceMCP, mcpTarget, title, severity, desc,
		map[string]interface{}{
			"module": "mcp", "action": "ssti", "mutating": false, "provider": "mcp",
			"tool":           res.Tool,
			"ssti_confirmed": res.Confirmed,
			"ssti_signal":    res.Signal,
		})
	finding.Evidence = res.Evidence
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "mcp-ssti", "template-engine")
	sstiPlan := buildMCPEscalationWorkflowPlan(mcpTarget, "ssti")
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, sstiPlan)
	infof("MCP ssti: tool=%s confirmed=%t", res.Tool, res.Confirmed)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module: "mcp", Action: "ssti", ResourcesEnumerated: 1, Mutating: false,
		WorkflowPlans: []workflowPlan{sstiPlan},
	})
}

// buildMCPEscalationWorkflowPlan chains a confirmed sandbox escape / SSTI into the
// other code-exec surface and dossier review. Empty target (stdio) yields no plan.
func buildMCPEscalationWorkflowPlan(target, action string) workflowPlan {
	if strings.TrimSpace(target) == "" {
		return workflowPlan{}
	}
	base := "mcp --target " + target + " "
	var recs []workflowRecommendation
	switch action {
	case "sandbox-escape":
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"ssti --force-exploit"), "Probe a rendering/formatting tool for server-side template injection (a code-execution surface).", true, 10),
			newWorkflowRecommendation(formatCommandExample("report view <dossier-dir> --credentials"), "Review any credentials the escaped file reads surfaced — save runs with --format dossier -o <dir>.", false, 20),
		}
	case "ssti":
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"sandbox-escape --force-exploit"), "Test a filesystem read tool for a path-based sandbox escape.", true, 10),
			newWorkflowRecommendation(formatCommandExample("report view <dossier-dir> --credentials"), "Review credentials surfaced from the injected template output — save runs with --format dossier -o <dir>.", false, 20),
		}
	default:
		return workflowPlan{}
	}
	return workflowPlan{
		Target:          target,
		Stage:           "impact",
		Landed:          "read-confirmed",
		ChainSource:     "mcp-" + action,
		Rationale:       "Chain the confirmed escape/injection into the other code-execution surface, then review looted credentials.",
		Recommendations: recs,
	}
}
