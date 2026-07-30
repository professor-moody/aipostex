package main

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// A looted, chainable credential emitted via structured extracted_credentials must
// produce follow-on recommendations even when its (hyphenated) value is invisible to
// the loose pattern extractors — mcp env-extract used to show "0 follow-on guidance".
func TestEnrichDirectWorkflowPlansFromStructuredCreds(t *testing.T) {
	f := report.Finding{
		ID:     "mcp-1",
		Source: report.SourceMCP,
		Target: "http://10.0.0.5:3000",
		Metadata: map[string]interface{}{
			"module": "mcp",
			"action": "env-extract",
			"extracted_credentials": []map[string]interface{}{{
				"type":       "openai-api-key",
				"name":       "OPENAI_API_KEY",
				"value":      "sk-proj-FAKE-mcp-env-openai-0123456789",
				"target_url": "http://10.0.0.5:3000",
				"chainable":  true,
			}},
		},
	}
	plans := enrichDirectWorkflowPlansWithCredentials(nil, []report.Finding{f})
	total := 0
	for _, p := range plans {
		total += len(p.Recommendations)
	}
	if total == 0 {
		t.Fatal("a chainable looted credential must produce follow-on recommendations")
	}
	// The suggestion must carry a runnable follow-on for the looted key.
	if !strings.Contains(plans[0].Recommendations[0].Command, "openai-compat") {
		t.Fatalf("expected an openai-compat follow-on, got %q", plans[0].Recommendations[0].Command)
	}
}
