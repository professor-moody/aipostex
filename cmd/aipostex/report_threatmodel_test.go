package main

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestAtlasFor(t *testing.T) {
	cases := []struct{ module, action, tactic, id string }{
		{"agent", "inject", "Defense Evasion", "AML.T0051"},
		{"agent", "crescendo", "Defense Evasion", "AML.T0051"},
		{"agent", "guardrail", "Defense Evasion", "AML.T0054"},
		{"agent", "session-probe", "Discovery", ""},
		{"agent", "extract", "Collection", ""},
		{"mlflow", "bulk-download", "Exfiltration", ""},
		{"jupyter", "exec", "Execution", ""},
		{"mystery", "unknown-verb", "Discovery", ""}, // fallback
	}
	for _, c := range cases {
		m := atlasFor(c.module, c.action)
		if m.tactic != c.tactic || m.id != c.id {
			t.Errorf("atlasFor(%s,%s) = %q/%q, want %q/%q", c.module, c.action, m.tactic, m.id, c.tactic, c.id)
		}
	}
}

func TestRenderThreatModel(t *testing.T) {
	findings := []report.Finding{
		{Target: "http://h:8112", Title: "review token leak", Metadata: map[string]interface{}{"module": "agent", "action": "extract", "stage": "access", "landed": "read-confirmed"}},
		{Target: "http://h:3000", Title: "MCP RCE", Metadata: map[string]interface{}{"module": "mcp", "action": "shell", "stage": "own", "landed": "execution-confirmed"}},
		{Target: "http://h:8112", Title: "crescendo injection", Metadata: map[string]interface{}{"module": "agent", "action": "crescendo", "stage": "impact", "landed": "influenced"}},
		{Target: "http://h:8112", Title: "session enum", Metadata: map[string]interface{}{"module": "agent", "action": "session-probe", "stage": "recon", "landed": "reachable"}},
	}
	out := captureStdout(t, func() { renderThreatModel(findings) })
	for _, want := range []string{
		"Kill-chain coverage", "Crown jewels", "execution-confirmed",
		"Defense Evasion", "Discovery", "AML.T0051", "MITRE ATLAS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("threat-model output missing %q:\n%s", want, out)
		}
	}
	// The MCP RCE target reached the deepest landed (execution-confirmed) — it must be
	// listed as a crown jewel.
	if !strings.Contains(out, ":3000") {
		t.Errorf("crown jewels should list the execution-confirmed :3000 target:\n%s", out)
	}
}
