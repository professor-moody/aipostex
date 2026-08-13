package main

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/mcpserver"
)

// `serve` exposes every CLI verb, generated from the command tree. These tests hold that
// promise: full parity, gating carried through, and no way for a model to authorise a
// mutating action by guessing a flag name.

func parityServer(t *testing.T) *mcpserver.Server {
	t.Helper()
	srv := mcpserver.New("aipostex-test", "test")
	registerAllVerbTools(srv)
	return srv
}

func TestServeExposesEveryVerb(t *testing.T) {
	srv := parityServer(t)
	got := map[string]bool{}
	for _, name := range srv.ToolNames() {
		got[name] = true
	}
	missing := 0
	for group, subs := range commandGroups() {
		if group == "serve" {
			continue // a server that can start itself is not useful
		}
		for verb := range subs {
			if !got[toolNameFor(group, verb)] {
				t.Errorf("%s %s has no MCP tool (expected %q)", group, verb, toolNameFor(group, verb))
				missing++
			}
		}
	}
	if missing == 0 && len(got) < 100 {
		t.Errorf("only %d tools registered — parity should expose the whole command tree", len(got))
	}
}

func TestServeMarksGatedVerbsAndRequiresConfirm(t *testing.T) {
	srv := parityServer(t)
	names := map[string]bool{}
	for _, n := range srv.ToolNames() {
		names[n] = true
	}
	checked := 0
	for group, subs := range commandGroups() {
		for verb, cmd := range subs {
			if cmd.Annotations[gatedAnnotation] == "" {
				continue
			}
			name := toolNameFor(group, verb)
			if !names[name] {
				continue
			}
			schema := schemaForCommand(cmd, true)
			props, _ := schema["properties"].(map[string]interface{})
			if _, ok := props["confirm"]; !ok {
				t.Errorf("%s is gated but its schema has no confirm argument", name)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no gated verbs were checked — the walker is broken, not the commands")
	}
}

// TestServeNeverLetsAModelSetForceExploit is the safety-critical one: authorisation must
// come from "confirm", which the server records, not from a flag the model can guess.
func TestServeNeverLetsAModelSetForceExploit(t *testing.T) {
	for group, subs := range commandGroups() {
		for verb, cmd := range subs {
			schema := schemaForCommand(cmd, true)
			props, _ := schema["properties"].(map[string]interface{})
			if _, ok := props["force-exploit"]; ok {
				t.Errorf("%s %s exposes --force-exploit as a model-settable argument", group, verb)
			}
			argv := argvFor(group, verb, cmd, map[string]interface{}{"force-exploit": true}, false)
			for _, a := range argv {
				if a == "--force-exploit" {
					t.Errorf("%s %s: a model-supplied force-exploit argument reached argv", group, verb)
				}
			}
		}
	}
}

func TestServeAddsForceExploitOnlyForGatedVerbs(t *testing.T) {
	groups := commandGroups()
	// A gated verb gets the flag from the server itself.
	gatedFound := false
	for group, subs := range groups {
		for verb, cmd := range subs {
			if cmd.Annotations[gatedAnnotation] != "true" {
				continue
			}
			argv := argvFor(group, verb, cmd, map[string]interface{}{}, true)
			if !strings.Contains(strings.Join(argv, " "), "--force-exploit") {
				t.Errorf("%s %s is gated but argv omits --force-exploit", group, verb)
			}
			gatedFound = true
			break
		}
		if gatedFound {
			break
		}
	}
	if !gatedFound {
		t.Fatal("no gated verb found to check")
	}
	// A read-only verb never gets it.
	for group, subs := range groups {
		for verb, cmd := range subs {
			if cmd.Annotations[gatedAnnotation] != "" {
				continue
			}
			argv := argvFor(group, verb, cmd, map[string]interface{}{}, false)
			if strings.Contains(strings.Join(argv, " "), "--force-exploit") {
				t.Errorf("read-only %s %s got --force-exploit", group, verb)
			}
			return
		}
	}
}

func TestToolNameFor(t *testing.T) {
	for _, tc := range []struct{ group, verb, want string }{
		{"mcp", "enum", "mcp_enum"},
		{"k8s", "secret-read", "k8s_secret_read"},
		{"openai-compat", "prompt-extract", "openai_compat_prompt_extract"},
	} {
		if got := toolNameFor(tc.group, tc.verb); got != tc.want {
			t.Errorf("toolNameFor(%q,%q) = %q, want %q", tc.group, tc.verb, got, tc.want)
		}
	}
}
