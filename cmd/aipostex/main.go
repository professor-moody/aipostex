package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/config"
	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/internal/output"
)

// WARNING: package-level mutable state. Do not use t.Parallel() in tests that read/write cfg.
var cfg = config.DefaultConfig()

// Whether the user explicitly passed -o/-f on this invocation. Set in the root
// PersistentPreRunE; read by getWriterMode to decide if the active session's
// engagement dossier should become the default output.
var (
	outputFlagChanged bool
	formatFlagChanged bool
)

var rootCmd = &cobra.Command{
	Use:   "aipostex",
	Short: "AI Infrastructure Offensive Security Framework",
	Long: `aipostex - Discover, assess, and exploit AI infrastructure

  Workflow commands for discovery, targeted scanning, and full assessment
  Post-exploitation modules for Ollama, vector databases, MCP, Jupyter
  Reporting and engagement packaging for assessment outputs

  https://github.com/professor-moody/aipostex`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if cfg.Concurrency < 1 {
			return fmt.Errorf("--concurrency must be at least 1, got %d", cfg.Concurrency)
		}
		if cfg.FingerprintTimeout <= 0 {
			return fmt.Errorf("--fingerprint-timeout must be greater than 0, got %s", cfg.FingerprintTimeout)
		}
		if cfg.DialTimeout <= 0 {
			return fmt.Errorf("--dial-timeout must be greater than 0, got %s", cfg.DialTimeout)
		}
		if cfg.MaxHosts < 0 {
			return fmt.Errorf("--max-hosts must be non-negative, got %d", cfg.MaxHosts)
		}
		validFormats := map[string]bool{
			"console": true, "json": true, "jsonl": true,
			"csv": true, "html": true, "sarif": true,
			"markdown": true, "md": true, "pdf": true, "dossier": true,
		}
		if cfg.Format != "" && !validFormats[cfg.Format] {
			return fmt.Errorf("--format %q is not valid; choose from: console, json, jsonl, csv, html, sarif, markdown, pdf, dossier", cfg.Format)
		}
		if cfg.Width < 0 {
			return fmt.Errorf("--width must be non-negative, got %d", cfg.Width)
		}
		// Push console presentation flags into the output package before any writer is built.
		output.SetConsoleWidth(cfg.Width)
		output.SetNoBanner(cfg.NoBanner || cfg.Quiet)
		// Record whether the user explicitly set -o/-f so the active-session
		// auto-dossier (see getWriterMode) only kicks in when they didn't.
		outputFlagChanged = cmd.Flags().Changed("output")
		formatFlagChanged = cmd.Flags().Changed("format")
		return nil
	}

	installWrappingHelp(rootCmd)

	rootCmd.AddGroup(
		&cobra.Group{ID: workflowGroupID, Title: "Workflow Commands"},
		&cobra.Group{ID: servicesGroupID, Title: "Service Modules"},
		&cobra.Group{ID: operationsGroupID, Title: "Operations"},
		&cobra.Group{ID: utilitiesGroupID, Title: "Utilities"},
	)

	bindScanWorkflowFlags(scanCmd)
	bindDiscoveryNetworkFlags(discoverNetworkCmd)
	bindDiscoveryFilesFlags(discoverFilesCmd)
	bindAssessmentFlags(assessNetworkCmd)
	bindTemplateLookupFlags(templatesCmd)
	bindReportOutputFlags(reportCmd)
	bindEngagementOutputFlags(engagementCmd)

	// Accept -v/--verbose consistently on the reporting/read-only command groups
	// (these previously errored with "unknown shorthand flag: 'v'").
	bindVerboseFlag(reportCmd)
	bindVerboseFlag(templatesCmd)
	bindVerboseFlag(sessionsCmd)

	bindServiceModuleFlags(ollamaCmd)
	bindServiceModuleFlags(vectordbCmd)
	bindServiceModuleFlags(jupyterCmd)
	bindServiceModuleFlags(mcpCmd)
	bindServiceModuleFlags(openAICompatCmd)
	bindServiceModuleFlags(rayCmd)
	bindServiceModuleFlags(mlflowCmd)
	bindServiceModuleFlags(gradioCmd)
	bindServiceModuleFlags(bentomlCmd)
	bindServiceModuleFlags(tritonCmd)
	bindServiceModuleFlags(torchserveCmd)
	bindServiceModuleFlags(litellmCmd)
	bindServiceModuleFlags(tfservingCmd)
	bindServiceModuleFlags(a2aCmd)
	bindServiceModuleFlags(wandbCmd)
	bindServiceModuleFlags(huggingfaceCmd)
	bindServiceModuleFlags(kubeflowCmd)
	bindServiceModuleFlags(k8sCmd)
	bindServiceModuleFlags(agentCmd)
	bindServiceModuleFlags(ragCmd)
	ollamaCmd.GroupID = servicesGroupID
	vectordbCmd.GroupID = servicesGroupID
	jupyterCmd.GroupID = servicesGroupID
	mcpCmd.GroupID = servicesGroupID
	openAICompatCmd.GroupID = servicesGroupID
	rayCmd.GroupID = servicesGroupID
	mlflowCmd.GroupID = servicesGroupID
	gradioCmd.GroupID = servicesGroupID
	bentomlCmd.GroupID = servicesGroupID
	tritonCmd.GroupID = servicesGroupID
	torchserveCmd.GroupID = servicesGroupID
	litellmCmd.GroupID = servicesGroupID
	tfservingCmd.GroupID = servicesGroupID
	a2aCmd.GroupID = servicesGroupID
	wandbCmd.GroupID = servicesGroupID
	huggingfaceCmd.GroupID = servicesGroupID
	kubeflowCmd.GroupID = servicesGroupID
	k8sCmd.GroupID = servicesGroupID

	scanCmd.AddCommand(scanTargetsCmd, scanNetworkAliasCmd, scanAllAliasCmd)
	discoverCmd.AddCommand(discoverNetworkCmd, discoverFilesCmd)
	assessCmd.AddCommand(assessNetworkCmd)
	templatesCmd.AddCommand(templatesListCmd, templatesInfoCmd, templatesLintCmd)
	reportCmd.AddCommand(reportRenderCmd, reportSummaryCmd, reportGraphCmd, reportViewCmd)
	engagementCmd.AddCommand(engagementMergeCmd, engagementBundleCmd)

	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(assessCmd)
	rootCmd.AddCommand(templatesCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(engagementCmd)
	rootCmd.AddCommand(ollamaCmd)
	rootCmd.AddCommand(vectordbCmd)
	rootCmd.AddCommand(jupyterCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(openAICompatCmd)
	rootCmd.AddCommand(rayCmd)
	rootCmd.AddCommand(mlflowCmd)
	rootCmd.AddCommand(gradioCmd)
	rootCmd.AddCommand(bentomlCmd)
	rootCmd.AddCommand(tritonCmd)
	rootCmd.AddCommand(torchserveCmd)
	rootCmd.AddCommand(litellmCmd)
	rootCmd.AddCommand(tfservingCmd)
	rootCmd.AddCommand(a2aCmd)
	rootCmd.AddCommand(wandbCmd)
	rootCmd.AddCommand(huggingfaceCmd)
	rootCmd.AddCommand(kubeflowCmd)
	rootCmd.AddCommand(k8sCmd)
	agentCmd.GroupID = servicesGroupID
	rootCmd.AddCommand(agentCmd)
	ragCmd.GroupID = servicesGroupID
	rootCmd.AddCommand(ragCmd)

	bindForceExploitFlag(listenCmd)
	listenCmd.GroupID = operationsGroupID
	rootCmd.AddCommand(listenCmd)

	// Operator console: the top-level `request` primitive plus a per-module
	// `request` verb on each HTTP service module (both share the runner in request.go).
	requestCmd.Flags().StringVarP(&requestTarget, "target", "t", "", "Service base URL (omit if PATH is a full URL)")
	requestCmd.Flags().StringSliceVar(&requestHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format")
	requestCmd.Flags().StringVar(&requestAPIKey, "api-key", "", "Bearer API key convenience flag (use --header for other schemes)")
	bindRequestBodyFlags(requestCmd)
	bindFindingsOutputFlags(requestCmd)
	bindNetworkRuntimeFlags(requestCmd)
	rootCmd.AddCommand(requestCmd)
	registerModuleConsoleRequests()
	registerModuleConsoleShells()

	rootCmd.AddCommand(sessionsCmd)

	bindLocalAnalysisFlags(modelScanCmd)
	modelScanCmd.GroupID = utilitiesGroupID
	rootCmd.AddCommand(modelScanCmd)
	bindVerboseFlag(versionCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Print version information",
	Example: formatCommandExample("version"),
	Long: `Print version information.

Reports the aipostex version and build time. Add --verbose to include the Go
toolchain version and target os/arch — useful when reporting an issue or
confirming which build is deployed on an operator box.`,
	GroupID: utilitiesGroupID,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("aipostex %s (built %s)\n", config.Version, config.BuildTime)
		if cfg.Verbose {
			// -v adds the build environment so every command answers -v consistently
			// instead of `version -v` erroring with "unknown shorthand flag: 'v'".
			fmt.Printf("  go:      %s\n", runtime.Version())
			fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		}
	},
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "Interrupted")
			os.Exit(exitcode.Error)
		}
		code := exitcode.Code(err)
		if code == exitcode.FindingsPartial {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			os.Exit(exitcode.FindingsPartial)
		}
		if code == exitcode.Findings {
			os.Exit(exitcode.Findings)
		}
		if code == exitcode.PartialFailure {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			os.Exit(exitcode.PartialFailure)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitcode.Error)
	}
}
