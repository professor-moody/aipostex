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
	Example: formatCommandExample("discover network 10.0.0.0/24"),
	Long: `Discover AI services and artifacts.

The reconnaissance entry point: find what AI infrastructure exists on a network
or host before touching any of it. Subcommands sweep network ranges for AI
service fingerprints and search local filesystems for models, notebooks, and
configuration artifacts.

Read-only.`,
	GroupID: workflowGroupID,
}

var scanCmd = &cobra.Command{
	Use:     "scan",
	Short:   "Run targeted vulnerability scanning workflows",
	Example: formatCommandExample("scan targets http://127.0.0.1:11434"),
	Long: `Run targeted vulnerability scanning workflows.

Applies the vulnerability template corpus to discovered services — the step
between "an AI service is here" and "this specific weakness is present on it".
Scanning is detection-oriented; anything that mutates a target lives behind a
module verb and --force-exploit.`,
	GroupID: workflowGroupID,
	RunE:    subcommandRequired("aipostex scan", "aipostex scan targets http://127.0.0.1:11434"),
}

var assessCmd = &cobra.Command{
	Use:     "assess",
	Short:   "Run full assessment workflows",
	Example: formatCommandExample("assess targets http://127.0.0.1:11434"),
	Long: `Run full assessment workflows.

Chains discovery, fingerprinting, and template scanning into one pass over a
target set, so a whole estate is covered without driving each stage by hand.
Assess finds more than discover alone because it enumerates each identified
service's own surface rather than stopping at the port.`,
	GroupID: workflowGroupID,
}

var templatesCmd = &cobra.Command{
	Use:     "templates",
	Short:   "List and inspect vulnerability templates",
	Example: formatCommandExample("templates list"),
	Long: `List and inspect the vulnerability template corpus.

Templates are the declarative detection rules aipostex applies during scanning.
Use these subcommands to see what is available, filter by tag, and lint the
corpus for safety and advisory metadata.`,
	GroupID: utilitiesGroupID,
	RunE:    subcommandRequired("aipostex templates", "aipostex templates list"),
}

var reportCmd = &cobra.Command{
	Use:     "report",
	Short:   "Render and analyze engagement outputs",
	Example: formatCommandExample("report view findings.jsonl --credentials"),
	Long: `Render and analyze engagement outputs.

Turns raw findings into an operator-facing deliverable: rendered reports, the
credential index, the attack-chain board, the threat model, and the handoff
dossier. This is where a JSONL of findings becomes something you can act on or
hand to a client.`,
	GroupID: utilitiesGroupID,
	RunE:    subcommandRequired("aipostex report", "aipostex report render findings.json"),
}

var engagementCmd = &cobra.Command{
	Use:     "engagement",
	Short:   "Combine and package engagement artifacts",
	Example: formatCommandExample("engagement combine run-a.jsonl run-b.jsonl -o combined.jsonl"),
	Long: `Combine and package engagement artifacts.

Merges findings captured across separate runs and hosts into a single engagement
set, so a multi-day or multi-operator effort produces one coherent body of
evidence rather than scattered output files.`,
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
