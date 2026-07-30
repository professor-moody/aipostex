package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestScanAliasesRedirect guards the release blocker where `scan network` / `scan all`
// silently printed the parent `scan` help. They must now redirect loudly to the real
// commands.
func TestScanAliasesRedirect(t *testing.T) {
	if err := scanNetworkAliasCmd.RunE(scanNetworkAliasCmd, nil); err == nil || !strings.Contains(err.Error(), "discover network") {
		t.Errorf("`scan network` must redirect to discover/assess network; got: %v", err)
	}
	if err := scanAllAliasCmd.RunE(scanAllAliasCmd, nil); err == nil || !strings.Contains(err.Error(), "assess network") {
		t.Errorf("`scan all` must redirect to assess network; got: %v", err)
	}
	// Both must be registered under `scan` so `--help` reaches them (not the parent help).
	names := map[string]bool{}
	for _, c := range scanCmd.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"network", "all", "targets"} {
		if !names[want] {
			t.Errorf("`scan` should register subcommand %q", want)
		}
	}
}

// TestVerboseAcceptedOnReadOnlyCommands guards that -v/--verbose is accepted consistently
// on the reporting/read-only command groups that previously errored with
// "unknown shorthand flag: 'v'".
func TestVerboseAcceptedOnReadOnlyCommands(t *testing.T) {
	for _, c := range []*cobra.Command{reportCmd, templatesCmd, sessionsCmd} {
		if c.PersistentFlags().Lookup("verbose") == nil {
			t.Errorf("%s should accept -v/--verbose", c.Name())
		}
	}
}

// TestVersionAcceptsVerbose documents that `version -v` prints extra build detail (Go
// version, OS/arch) so -v behaves consistently across every command instead of erroring
// with "unknown shorthand flag: 'v'".
func TestVersionAcceptsVerbose(t *testing.T) {
	if versionCmd.Flags().Lookup("verbose") == nil && versionCmd.PersistentFlags().Lookup("verbose") == nil {
		t.Error("version should accept -v/--verbose and print build detail")
	}
}
