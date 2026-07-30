package main

import "github.com/spf13/cobra"

func bindFindingsOutputFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&cfg.OutputFile, "output", "o", "", "Output file path, or dossier directory for --format dossier (default: stdout)")
	cmd.PersistentFlags().StringVarP(&cfg.Format, "format", "f", "console", "Output format: console, json, jsonl, csv, html, sarif, markdown, pdf, dossier (dossier writes an operator folder to -o <dir>)")
	cmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output (descriptions, dedupe details, full untruncated evidence)")
	cmd.PersistentFlags().BoolVar(&cfg.NoBanner, "no-banner", false, "Suppress the startup banner")
	cmd.PersistentFlags().BoolVar(&cfg.Quiet, "quiet", false, "Findings only: suppress the module summary and evidence hint (implies --no-banner)")
	// Console output auto-detects the terminal width; --width is an internal knob to
	// pin an exact framing width for deterministic recording/CI, kept out of --help.
	cmd.PersistentFlags().IntVar(&cfg.Width, "width", 0, "Pin console framing width in columns (0 = auto-detect)")
	_ = cmd.PersistentFlags().MarkHidden("width")
}

func bindNetworkRuntimeFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&cfg.Stealth, "stealth", false, "Reduced speed/parallelism for OPSEC")
	cmd.PersistentFlags().DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "HTTP request timeout")
	cmd.PersistentFlags().StringVar(&cfg.Proxy, "proxy", "", "Proxy URL for HTTP/S, or SOCKS5 traffic")
	cmd.PersistentFlags().BoolVar(&cfg.Insecure, "insecure", false, "Skip TLS certificate verification for HTTPS requests")
}

func bindConcurrencyFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().IntVar(&cfg.Concurrency, "concurrency", 10, "Parallel workers")
}

func bindFingerprintTimeoutFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().DurationVar(&cfg.FingerprintTimeout, "fingerprint-timeout", cfg.FingerprintTimeout, "Per-port fingerprint HTTP budget")
	cmd.PersistentFlags().DurationVar(&cfg.DialTimeout, "dial-timeout", cfg.DialTimeout, "TCP dial timeout for port scanning")
}

func bindMaxHostsFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().IntVar(&cfg.MaxHosts, "max-hosts", cfg.MaxHosts, "Maximum hosts to expand before aborting (0 disables the guardrail)")
}

func bindForceExploitFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&cfg.ForceExploit, "force-exploit", false, "Enable mutating or execution-oriented exploit actions")
}

func bindScanWorkflowFlags(cmd *cobra.Command) {
	bindFindingsOutputFlags(cmd)
	bindNetworkRuntimeFlags(cmd)
	bindConcurrencyFlag(cmd)
}

func bindDiscoveryNetworkFlags(cmd *cobra.Command) {
	bindFindingsOutputFlags(cmd)
	bindNetworkRuntimeFlags(cmd)
	bindConcurrencyFlag(cmd)
	bindFingerprintTimeoutFlag(cmd)
	bindMaxHostsFlag(cmd)
	bindAutoChainFlag(cmd)
}

func bindDiscoveryFilesFlags(cmd *cobra.Command) {
	bindFindingsOutputFlags(cmd)
	cmd.PersistentFlags().BoolVar(&cfg.Stealth, "stealth", false, "Reduced speed/parallelism for OPSEC")
	cmd.PersistentFlags().IntVar(&cfg.Concurrency, "concurrency", 10, "Parallel workers")
}

func bindAutoChainFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&cfg.AutoChain, "auto-chain", false, "Generate follow-up command suggestions using discovered credentials")
}

func bindAssessmentFlags(cmd *cobra.Command) {
	bindFindingsOutputFlags(cmd)
	bindNetworkRuntimeFlags(cmd)
	bindConcurrencyFlag(cmd)
	bindFingerprintTimeoutFlag(cmd)
	bindMaxHostsFlag(cmd)
	bindAutoChainFlag(cmd)
}

func bindTemplateLookupFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&scanTemplDir, "templates-dir", "", "Additional templates directory")
}

func bindReportOutputFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&cfg.OutputFile, "output", "o", "", "Output file (default: stdout)")
}

// bindVerboseFlag adds -v/--verbose to read-only / reporting command groups (report,
// sessions, templates) that otherwise rejected it with "unknown shorthand flag: 'v'".
// The workflow and service modules already bind -v via bindFindingsOutputFlags; this
// makes verbosity accepted consistently across every findings-producing command.
// (Purpose-specific --format flags on report render/graph and sessions export are left
// as-is; a generic --format would collide with and override those.)
func bindVerboseFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")
}

func bindEngagementOutputFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&cfg.OutputFile, "output", "o", "", "Output file (default: stdout)")
}

func bindCallbackFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&cfg.CallbackURL, "callback-url", "", "Out-of-band callback URL (http(s)://... for webhook, tcp://host:port for reverse shell)")
	cmd.PersistentFlags().StringVar(&cfg.SessionID, "session", "", "Session ID to tag findings with (auto-detects active session if omitted)")
}

func bindServiceModuleFlags(cmd *cobra.Command) {
	bindFindingsOutputFlags(cmd)
	bindNetworkRuntimeFlags(cmd)
	bindForceExploitFlag(cmd)
	bindCallbackFlags(cmd)
}

func bindLocalAnalysisFlags(cmd *cobra.Command) {
	bindFindingsOutputFlags(cmd)
	cmd.PersistentFlags().StringVar(&cfg.SessionID, "session", "", "Session ID to tag findings with (auto-detects active session if omitted)")
}
