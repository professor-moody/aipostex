package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

const (
	workflowGroupID   = "workflow"
	servicesGroupID   = "services"
	operationsGroupID = "operations"
	utilitiesGroupID  = "utilities"
)

var discoverCmd = &cobra.Command{
	Use:     "discover",
	Short:   "Discover AI services and artifacts",
	GroupID: workflowGroupID,
}

var scanCmd = &cobra.Command{
	Use:     "scan",
	Short:   "Run targeted vulnerability scanning workflows",
	GroupID: workflowGroupID,
	RunE:    subcommandRequired("aipostex scan", "aipostex scan targets http://127.0.0.1:11434"),
}

var assessCmd = &cobra.Command{
	Use:     "assess",
	Short:   "Run full assessment workflows",
	GroupID: workflowGroupID,
}

var templatesCmd = &cobra.Command{
	Use:     "templates",
	Short:   "List and inspect vulnerability templates",
	GroupID: utilitiesGroupID,
	RunE:    subcommandRequired("aipostex templates", "aipostex templates list"),
}

var reportCmd = &cobra.Command{
	Use:     "report",
	Short:   "Render and analyze engagement outputs",
	GroupID: utilitiesGroupID,
	RunE:    subcommandRequired("aipostex report", "aipostex report render findings.json"),
}

var engagementCmd = &cobra.Command{
	Use:     "engagement",
	Short:   "Combine and package engagement artifacts",
	GroupID: utilitiesGroupID,
}

func subcommandRequired(name, example string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("%s requires a subcommand\nexample: %s", name, example)
	}
}

// scanNetworkAliasCmd and scanAllAliasCmd are registered under `scan` purely so that
// `scan network` / `scan all` — which users reach for by analogy with `discover
// network` / `assess network` — redirect loudly to the real commands instead of
// silently printing the parent `scan` help (cobra's default for an unknown subcommand
// invoked with --help).
// Hidden + DisableFlagParsing + SilenceUsage so these redirect with ONLY the helpful
// error: hidden keeps them out of the `scan` listing, DisableFlagParsing swallows a
// stray `-t`/`--ports` (no "unknown shorthand flag"), and SilenceUsage stops cobra from
// dumping a usage block that contradicts the "not a command" message.
var scanNetworkAliasCmd = &cobra.Command{
	Use:                "network [targets...]",
	Short:              "Not a command — use `discover network` or `assess network`",
	Hidden:             true,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	Long: "`aipostex scan network` is not a command.\n\n" +
		"Use one of:\n" +
		"  aipostex discover network <targets>   # detect AI/ML services (no exploitation)\n" +
		"  aipostex assess network <targets>     # full assessment (detect + scan + enumerate)\n" +
		"  aipostex scan targets <urls>          # run vulnerability templates against specific URLs",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("`scan network` is not a command; use `aipostex discover network <targets>` (detect) or `aipostex assess network <targets>` (full assessment)")
	},
}

var scanAllAliasCmd = &cobra.Command{
	Use:                "all [targets...]",
	Short:              "Not a command — use `assess network`",
	Hidden:             true,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	Long:               "`aipostex scan all` is not a command. Use `aipostex assess network <targets>` for a full assessment (discover + scan + enumerate).",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("`scan all` is not a command; use `aipostex assess network <targets>` for a full assessment")
	},
}
