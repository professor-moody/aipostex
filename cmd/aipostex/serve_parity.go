package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/professor-moody/aipostex/internal/mcpserver"
)

// Full parity: every CLI verb is an MCP tool.
//
// The tool surface is generated from the command tree rather than hand-written, so
// it cannot drift: a verb added to the CLI is a tool the next time the server runs,
// with its flags, its documentation, and its gating already correct. Hand-written
// tools covered 17 of 201 verbs and silently fell behind every release.
//
// Each tool re-executes this binary as a subprocess rather than calling the command
// in-process. That is deliberate:
//
//   - stdout is the MCP protocol channel. A command writing findings to stdout
//     in-process would corrupt the stream.
//   - cobra flag state is global and persists between invocations, so consecutive
//     in-process calls would leak arguments into each other.
//
// The subprocess gets the same argv a human would type, and the tool returns exactly
// what the CLI printed — findings, summary, and next actions included.

// gatedAnnotation marks a command that refuses to run without --force-exploit. It is
// declared on the command itself so gating is machine-readable: the MCP surface, the
// shipped skill, and the tests all read the same source of truth rather than guessing
// from help text.
const gatedAnnotation = "aipostex.gated"

// maxToolOutputBytes caps what a single call returns, so one enumeration of a large
// estate cannot flood the model's context.
const maxToolOutputBytes = 60_000

// flagsToSkip are global or output-plumbing flags that a model should not be setting:
// they change how results are written rather than what is assessed, and the MCP
// transport already handles delivery.
var flagsToSkip = map[string]bool{
	"help":     true,
	"output":   true, // findings come back in the tool result
	"format":   true, // the console format is what the caller reads
	"no-color": true,
	"quiet":    true,
	"width":    true,
	"verbose":  true,
	// --force-exploit is never model-settable: gated tools require "confirm" and the
	// server adds the flag itself, so a model cannot authorise mutation by guessing
	// a flag name.
	"force-exploit": true,
}

// toolNameFor renders a command path as an MCP tool name (mcp enum -> mcp_enum).
func toolNameFor(group, verb string) string {
	name := group + "_" + verb
	return strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(name)
}

// schemaForCommand builds the JSON Schema for a verb from its flags.
func schemaForCommand(cmd *cobra.Command, gated bool) map[string]interface{} {
	props := map[string]interface{}{}
	var required []string

	add := func(f *pflag.Flag) {
		if f.Hidden || flagsToSkip[f.Name] {
			return
		}
		typ := "string"
		switch f.Value.Type() {
		case "bool":
			typ = "boolean"
		case "int", "int64", "count":
			typ = "integer"
		case "stringSlice", "stringArray":
			// Rendered as a comma-joined string; cobra parses it back into a slice.
			typ = "string"
		}
		desc := f.Usage
		if def := f.DefValue; def != "" && def != "false" && def != "0" && def != "[]" {
			desc = fmt.Sprintf("%s (default %s)", desc, def)
		}
		props[f.Name] = map[string]interface{}{"type": typ, "description": desc}
		if strings.Contains(strings.ToLower(f.Usage), "(required)") {
			required = append(required, f.Name)
		}
	}
	cmd.Flags().VisitAll(add)
	cmd.InheritedFlags().VisitAll(add)
	for p := cmd.Parent(); p != nil; p = p.Parent() {
		p.PersistentFlags().VisitAll(add)
	}

	if gated {
		props["confirm"] = map[string]interface{}{
			"type": "boolean",
			"description": "Must be true to authorise this action. It changes target state or drives " +
				"execution, and is refused without explicit confirmation.",
		}
	}
	if cmd.Args != nil {
		props["args"] = map[string]interface{}{
			"type":        "string",
			"description": "Positional arguments, space separated (this verb accepts them).",
		}
	}
	sort.Strings(required)
	schema := map[string]interface{}{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// describeCommand builds a tool description from the verb's own documentation,
// keeping it short enough to be useful in a tool listing.
func describeCommand(cmd *cobra.Command, group, verb string, gated bool) string {
	desc := strings.TrimSpace(cmd.Short)
	if long := strings.TrimSpace(cmd.Long); long != "" {
		if para := strings.SplitN(long, "\n\n", 2)[0]; len(para) > len(desc) {
			desc = strings.Join(strings.Fields(para), " ")
		}
	}
	if len(desc) > 600 {
		desc = desc[:600] + "…"
	}
	prefix := fmt.Sprintf("aipostex %s %s — ", group, verb)
	if gated {
		return prefix + desc + " GATED: changes target state or drives execution; refused unless called with \"confirm\": true."
	}
	return prefix + desc
}

// argvFor turns tool arguments into the argv a human would type.
func argvFor(group, verb string, cmd *cobra.Command, a map[string]interface{}, gated bool) []string {
	argv := []string{group, verb}
	names := make([]string, 0, len(a))
	for k := range a {
		names = append(names, k)
	}
	sort.Strings(names) // deterministic argv makes the audit log readable
	for _, k := range names {
		if k == "confirm" || k == "args" {
			continue
		}
		if flagsToSkip[k] {
			continue // a model cannot smuggle in --force-exploit or redirect output
		}
		f := cmd.Flags().Lookup(k)
		if f == nil {
			f = cmd.InheritedFlags().Lookup(k)
		}
		if f == nil {
			for p := cmd.Parent(); p != nil && f == nil; p = p.Parent() {
				f = p.PersistentFlags().Lookup(k)
			}
		}
		if f == nil {
			continue // unknown flag: drop it rather than let cobra fail the whole call
		}
		switch v := a[k].(type) {
		case bool:
			if v {
				argv = append(argv, "--"+k)
			}
		case float64:
			argv = append(argv, "--"+k, strconv.FormatFloat(v, 'f', -1, 64))
		case string:
			if v != "" {
				argv = append(argv, "--"+k, v)
			}
		default:
			argv = append(argv, "--"+k, fmt.Sprint(v))
		}
	}
	if gated {
		argv = append(argv, "--force-exploit")
	}
	if pos, ok := a["args"].(string); ok && strings.TrimSpace(pos) != "" {
		argv = append(argv, strings.Fields(pos)...)
	}
	return argv
}

// registerAllVerbTools exposes every non-hidden CLI verb as an MCP tool.
func registerAllVerbTools(srv *mcpserver.Server) {
	self, err := os.Executable()
	if err != nil || self == "" {
		self = "aipostex"
	}

	for _, group := range rootCmd.Commands() {
		if group.Hidden || group.Name() == "completion" || group.Name() == "help" {
			continue
		}
		groupName := strings.Fields(group.Use)[0]
		if groupName == "serve" {
			continue // a server that can start itself is not useful
		}
		for _, sub := range group.Commands() {
			if sub.Hidden || sub.Name() == "help" {
				continue
			}
			verb := strings.Fields(sub.Use)[0]
			gated := sub.Annotations[gatedAnnotation] == "true"
			conditional := sub.Annotations[gatedAnnotation] == "conditional"
			cmd, g, v := sub, groupName, verb

			srv.Register(mcpserver.Tool{
				Name:        toolNameFor(g, v),
				Description: describeCommand(cmd, g, v, gated || conditional),
				InputSchema: schemaForCommand(cmd, gated || conditional),
				Mutating:    gated || conditional,
				Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
					if (gated || conditional) && !mcpserver.BoolArg(a, "confirm") {
						return fmt.Sprintf(
							"refused: `aipostex %s %s` changes target state or drives execution. "+
								"Call again with \"confirm\": true to authorise it.", g, v), true
					}
					argv := argvFor(g, v, cmd, a, gated)
					out, err := exec.CommandContext(ctx, self, argv...).CombinedOutput() //nolint:gosec // argv is built from this binary's own flag set
					text := string(out)
					if len(text) > maxToolOutputBytes {
						text = text[:maxToolOutputBytes] + "\n[output truncated]"
					}
					if err != nil {
						// aipostex exits 2 with findings and 4 with findings plus a
						// partial failure; neither is an error worth flagging.
						if code, ok := exitCodeOf(err); ok && (code == 2 || code == 4) {
							return text, false
						}
						if strings.TrimSpace(text) == "" {
							return "error: " + err.Error(), true
						}
						return text, true
					}
					return text, false
				},
			})
		}
	}
}

// legacyToolAliases keep tool names that existed before the surface was generated
// working. `fingerprint_model` in particular shipped publicly for several releases,
// and a model that learned the old name should not meet "unknown tool".
//
// These are thin redirects to a generated tool, not second implementations — the
// behaviour lives in one place.
var legacyToolAliases = map[string]struct {
	target string
	extra  map[string]interface{}
}{
	"fingerprint_model": {target: "openai_compat_fingerprint"},
	"mcp_auth_posture":  {target: "mcp_auth"},
	"mcp_read":          {target: "mcp_enum", extra: map[string]interface{}{"read": true}},
	"k8s_posture":       {target: "k8s_rbac_probe"},
}

// registerLegacyAliases adds the pre-parity tool names as deprecated redirects.
func registerLegacyAliases(srv *mcpserver.Server) {
	byName := map[string]mcpserver.Tool{}
	for _, t := range srv.Tools() {
		byName[t.Name] = t
	}
	for alias, spec := range legacyToolAliases {
		target, ok := byName[spec.target]
		if !ok {
			continue // the verb it pointed at no longer exists; nothing to alias
		}
		extra := spec.extra
		inner := target.Handler
		srv.Register(mcpserver.Tool{
			Name: alias,
			Description: fmt.Sprintf("DEPRECATED alias for %s — use that name instead. %s",
				spec.target, target.Description),
			InputSchema: target.InputSchema,
			Mutating:    target.Mutating,
			Handler: func(ctx context.Context, a map[string]interface{}) (string, bool) {
				merged := make(map[string]interface{}, len(a)+len(extra))
				for k, v := range a {
					merged[k] = v
				}
				for k, v := range extra {
					merged[k] = v
				}
				return inner(ctx, merged)
			},
		})
	}
}

func exitCodeOf(err error) (int, bool) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	return 0, false
}
