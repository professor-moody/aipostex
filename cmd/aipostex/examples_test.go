package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Every command carries an Example, and an operator will paste it verbatim. A
// previous change shipped three `vectordb` examples using a `--provider` flag that
// does not exist (the flag is `--type`), which `--help` rendered happily and no
// test caught: checking that the *subcommand* exists is not enough, because a bad
// flag fails just as hard at the prompt.
//
// This walks every example in the command tree, resolves the command it names, and
// asserts that each flag it uses actually exists on that command.

// splitExample splits an example command line, honouring double quotes so a
// quoted payload containing spaces stays a single argument.
func splitExample(line string) []string {
	var args []string
	var cur strings.Builder
	inQuote := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

// exampleLines returns the runnable command lines in an Example block, skipping
// comment lines and any leading "aipostex " prefix.
func exampleLines(example string) []string {
	var out []string
	for _, raw := range strings.Split(example, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "aipostex ")
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// flagExists reports whether cmd accepts the given long flag, including flags
// inherited from its parents.
func flagExists(cmd *cobra.Command, name string) bool {
	if cmd.Flags().Lookup(name) != nil {
		return true
	}
	if cmd.InheritedFlags().Lookup(name) != nil {
		return true
	}
	if cmd.PersistentFlags().Lookup(name) != nil {
		return true
	}
	// Walk parents explicitly: InheritedFlags is only populated once a command
	// has been executed or its flags resolved.
	for p := cmd.Parent(); p != nil; p = p.Parent() {
		if p.PersistentFlags().Lookup(name) != nil || p.Flags().Lookup(name) != nil {
			return true
		}
	}
	return false
}

func walkCommands(cmd *cobra.Command, fn func(*cobra.Command)) {
	fn(cmd)
	for _, c := range cmd.Commands() {
		walkCommands(c, fn)
	}
}

func TestEveryExampleUsesRealCommandsAndFlags(t *testing.T) {
	var checked int
	walkCommands(rootCmd, func(cmd *cobra.Command) {
		if cmd.Example == "" || cmd.Hidden {
			return
		}
		for _, line := range exampleLines(cmd.Example) {
			args := splitExample(line)
			if len(args) == 0 {
				continue
			}
			// Let cobra resolve the command: examples routinely place flags before
			// the subcommand ("a2a --target ... task-send --message ..."), and
			// cobra's Find already knows which flags consume a following value.
			target, _, err := rootCmd.Find(args)
			if err != nil || target == nil {
				t.Errorf("%s: example names a command that does not resolve: %q (%v)", cmd.CommandPath(), line, err)
				continue
			}
			checked++
			for i := 0; i < len(args); i++ {
				a := args[i]
				if !strings.HasPrefix(a, "--") {
					continue
				}
				name := strings.TrimPrefix(a, "--")
				if idx := strings.Index(name, "="); idx >= 0 {
					name = name[:idx]
				}
				if name == "" {
					continue
				}
				if !flagExists(target, name) {
					t.Errorf("%s: example uses --%s, which %s does not accept:\n    %s",
						cmd.CommandPath(), name, target.CommandPath(), line)
				}
			}
		}
	})
	if checked == 0 {
		t.Fatal("no examples were checked — the walker is broken, not the examples")
	}
	t.Logf("validated %d example invocation(s)", checked)
}
