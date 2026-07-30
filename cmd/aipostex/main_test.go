package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommandRegistersImplementedSubcommands(t *testing.T) {
	expected := map[string]bool{
		"discover":      false,
		"scan":          false,
		"assess":        false,
		"templates":     false,
		"report":        false,
		"engagement":    false,
		"ollama":        false,
		"vectordb":      false,
		"jupyter":       false,
		"mcp":           false,
		"openai-compat": false,
		"ray":           false,
		"mlflow":        false,
		"gradio":        false,
		"bentoml":       false,
		"triton":        false,
		"torchserve":    false,
		"litellm":       false,
		"tfserving":     false,
		"a2a":           false,
		"wandb":         false,
		"huggingface":   false,
		"kubeflow":      false,
		"k8s":           false,
		"version":       false,
	}

	for _, cmd := range rootCmd.Commands() {
		if cmd.Hidden {
			continue
		}
		if _, ok := expected[cmd.Name()]; ok {
			expected[cmd.Name()] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Fatalf("expected subcommand %q to be registered", name)
		}
	}
}

func TestServiceCommandsExposeSharedOperationalFlags(t *testing.T) {
	requiredFlags := []string{
		"format",
		"output",
		"timeout",
		"proxy",
		"insecure",
		"force-exploit",
		"callback-url",
		"session",
	}

	for _, cmd := range rootCmd.Commands() {
		if cmd.Hidden || cmd.GroupID != servicesGroupID {
			continue
		}
		for _, flagName := range requiredFlags {
			if cmd.Flag(flagName) == nil {
				t.Fatalf("service command %q is missing shared flag --%s", cmd.Name(), flagName)
			}
		}
	}
}

func TestConcurrencyRejectsInvalidValues(t *testing.T) {
	withTestConfig(t, func() {
		for _, val := range []string{"0", "-1", "-100"} {
			cmd := *rootCmd
			cmd.SetArgs([]string{"scan", "targets", "http://127.0.0.1:11434", "--concurrency", val})
			if err := cmd.Execute(); err == nil {
				t.Fatalf("expected error for --concurrency %s, got nil", val)
			}
		}
	})
}

func TestFingerprintTimeoutRejectsInvalidValues(t *testing.T) {
	withTestConfig(t, func() {
		for _, val := range []string{"0s", "-1s"} {
			cmd := *rootCmd
			cmd.SetArgs([]string{"discover", "network", "127.0.0.1", "--fingerprint-timeout", val})
			if err := cmd.Execute(); err == nil {
				t.Fatalf("expected error for --fingerprint-timeout %s, got nil", val)
			}
		}
	})
}

func TestDialTimeoutRejectsInvalidValues(t *testing.T) {
	withTestConfig(t, func() {
		for _, val := range []string{"0s", "-1s"} {
			cmd := *rootCmd
			cmd.SetArgs([]string{"discover", "network", "127.0.0.1", "--dial-timeout", val})
			if err := cmd.Execute(); err == nil {
				t.Fatalf("expected error for --dial-timeout %s, got nil", val)
			}
		}
	})
}

func TestKeyCommandsIncludeExamples(t *testing.T) {
	commands := []*cobra.Command{
		scanTargetsCmd,
		discoverFilesCmd,
		discoverNetworkCmd,
		templatesListCmd,
		templatesInfoCmd,
		templatesLintCmd,
		reportRenderCmd,
		reportSummaryCmd,
		reportGraphCmd,
		engagementMergeCmd,
		engagementBundleCmd,
		assessNetworkCmd,
		ollamaCmd,
		vectordbCmd,
		jupyterCmd,
		mcpCmd,
		openAICompatCmd,
		rayCmd,
		mlflowCmd,
		gradioCmd,
		bentomlCmd,
		tritonCmd,
		torchserveCmd,
		ollamaPoisonCmd,
		jupyterExecCmd,
		mcpPoisonCmd,
		openAICompatThroughputCmd,
		openAICompatProxyTestCmd,
		raySubmitCmd,
	}

	for _, cmd := range commands {
		if strings.TrimSpace(cmd.Example) == "" {
			t.Fatalf("expected %s to include examples", cmd.CommandPath())
		}
	}

	for _, cmd := range []*cobra.Command{ollamaPoisonCmd, jupyterExecCmd, mcpPoisonCmd, openAICompatThroughputCmd, openAICompatProxyTestCmd, raySubmitCmd, bentoPredictCmd, tritonInferCmd, tsPredictCmd, tsRegisterCmd} {
		if !strings.Contains(cmd.Example, "--force-exploit") && !strings.Contains(cmd.Long, "--force-exploit") {
			t.Fatalf("expected mutating command %s to mention --force-exploit", cmd.CommandPath())
		}
	}
}

func TestCanonicalHelpUsesNewFlagNames(t *testing.T) {
	tests := []struct {
		args    []string
		must    []string
		mustNot []string
	}{
		{
			args:    []string{"discover", "network", "--help"},
			must:    []string{"--target", "--fingerprint-timeout", "aipostex discover network"},
			mustNot: []string{"--targets"},
		},
		{
			args:    []string{"assess", "network", "--help"},
			must:    []string{"--fingerprint-timeout", "aipostex assess network"},
			mustNot: []string{"--targets"},
		},
		{
			args:    []string{"report", "render", "--help"},
			must:    []string{"--format"},
			mustNot: []string{"--report-format"},
		},
		{
			args:    []string{"report", "graph", "--help"},
			must:    []string{"--format"},
			mustNot: []string{"--graph-format"},
		},
	}

	for _, tc := range tests {
		var stdout bytes.Buffer
		prevOut := rootCmd.OutOrStdout()
		prevErr := rootCmd.ErrOrStderr()
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stdout)
		rootCmd.SetArgs(tc.args)
		err := rootCmd.Execute()
		rootCmd.SetOut(prevOut)
		rootCmd.SetErr(prevErr)
		if err != nil {
			t.Fatalf("%v: unexpected help error: %v", tc.args, err)
		}
		rendered := stdout.String()
		for _, want := range tc.must {
			if !strings.Contains(rendered, want) {
				t.Fatalf("%v: expected help to contain %q, got %q", tc.args, want, rendered)
			}
		}
		for _, banned := range tc.mustNot {
			if strings.Contains(rendered, banned) {
				t.Fatalf("%v: expected help to omit %q, got %q", tc.args, banned, rendered)
			}
		}
	}
}
