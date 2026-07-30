package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

// wrapHelpText word-wraps prose (a command's Long description or Examples block) to the
// current frame width, preserving blank lines. Fixes help output that ran past 100
// columns.
func wrapHelpText(s string) string {
	width := output.FrameWidth()
	out := make([]string, 0, 8)
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			out = append(out, "")
			continue
		}
		out = append(out, stringutil.WrapWords(line, width)...)
	}
	return strings.Join(out, "\n")
}

// flagUsagesWrapped renders a flag set's usage lines wrapped to the frame width so long
// --flag descriptions don't overflow the terminal.
func flagUsagesWrapped(fs *pflag.FlagSet) string {
	return fs.FlagUsagesWrapped(output.FrameWidth())
}

// installWrappingHelp registers the width-aware template functions and applies the
// usage/help templates to the root command; cobra propagates them to every subcommand.
func installWrappingHelp(root *cobra.Command) {
	cobra.AddTemplateFunc("wrapText", wrapHelpText)
	cobra.AddTemplateFunc("flagUsages", flagUsagesWrapped)
	root.SetUsageTemplate(wrappingUsageTemplate)
	root.SetHelpTemplate(wrappingHelpTemplate)
}

// wrappingHelpTemplate is cobra's default help template with the Long/Short block routed
// through wrapText.
const wrappingHelpTemplate = `{{with (or .Long .Short)}}{{. | wrapText | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

// wrappingUsageTemplate is cobra's default usage template with Examples routed through
// wrapText and the Flags/Global Flags sections through flagUsages (width-aware).
const wrappingUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example | wrapText}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags | flagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags | flagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
