package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/config"
	"github.com/professor-moody/aipostex/internal/mcpserver"
)

var serveTimeout time.Duration

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run aipostex as an MCP server (stdio) so an LLM/agent can drive it",
	Long: `Expose every aipostex verb as a Model Context Protocol tool over stdio, so an LLM or
agent framework can drive the whole tool rather than a curated slice of it.

The surface is generated from the command tree: each verb becomes a tool named
<module>_<verb>, carrying that verb's own flags, documentation, and gating. A verb added
to the CLI is a tool the next time the server starts.

Safety model:
  - Read-only verbs are exposed directly.
  - Gated verbs (those requiring --force-exploit) refuse unless called with "confirm": true,
    and are marked with the MCP destructiveHint annotation. The server adds --force-exploit
    itself; a model cannot set it as a flag.
  - Every tool call is audit-logged to stderr (stdout is the protocol channel).

Wire it into an MCP client (e.g. Claude) as a stdio server running "aipostex serve".`,
	Example: formatCommandExample("serve"),
	RunE:    runServe,
}

func init() {
	serveCmd.Flags().DurationVar(&serveTimeout, "timeout", 90*time.Second, "Per-call HTTP timeout for tool handlers")
	serveCmd.GroupID = operationsGroupID
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	srv := mcpserver.New("aipostex", config.Version)
	srv.Logf = func(format string, a ...interface{}) {
		fmt.Fprintf(os.Stderr, "[aipostex-mcp] "+format+"\n", a...)
	}
	registerAllVerbTools(srv)
	registerLegacyAliases(srv)
	fmt.Fprintln(os.Stderr, "[aipostex-mcp] serving on stdio; tools registered. Ctrl-C to stop.")
	return srv.Serve(currentContext(), os.Stdin, os.Stdout)
}
