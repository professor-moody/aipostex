package main

import (
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// TestAnnotateFindingsForOutputEnsuresStageLanded is the regression guard for the
// "~40% of findings missing stage/landed metadata" release blocker: every finding that
// reaches output must carry stage AND landed, and any legacy token a module still emits
// must be normalized onto the canonical vocabulary. Enum/fingerprint/listing paths never
// set them, so the shared normalization pass defaults the honest floor (recon/reachable)
// without overriding stronger claims a module already made.
func TestAnnotateFindingsForOutputEnsuresStageLanded(t *testing.T) {
	in := []report.Finding{
		// no metadata at all (fingerprint / port observation)
		{Source: report.SourceFingerprint, Target: "host:1", Title: "port open", Severity: report.SeverityInfo},
		// enum finding with action but no stage/landed fields
		{Source: report.SourceJupyter, Target: "http://h:8888", Title: "notebook", Severity: report.SeverityHigh,
			Metadata: map[string]interface{}{"action": "notebooks"}},
		// stage set, landed missing
		{Source: report.SourceVectorDB, Target: "http://h:8000", Title: "hit", Severity: report.SeverityMedium,
			Metadata: map[string]interface{}{"stage": "impact"}},
		// both already present (canonical) — must be preserved untouched
		{Source: report.SourceMLflow, Target: "http://h:5000", Title: "artifact", Severity: report.SeverityInfo,
			Metadata: map[string]interface{}{"stage": "impact", "landed": "read-confirmed"}},
		// legacy tokens present — must be normalized onto the canonical vocabulary
		{Source: report.SourceMCP, Target: "http://h:3000", Title: "legacy", Severity: report.SeverityHigh,
			Metadata: map[string]interface{}{"stage": "proof", "landed": "exploited"}},
	}

	out := annotateFindingsForOutput(in)
	for i, f := range out {
		if s, _ := f.Metadata["stage"].(string); s == "" {
			t.Errorf("finding %d (%s): stage missing after normalization", i, f.Source)
		}
		if s, _ := f.Metadata["landed"].(string); s == "" {
			t.Errorf("finding %d (%s): landed missing after normalization", i, f.Source)
		}
	}

	// Honest floor applied where absent.
	if got := out[0].Metadata["stage"]; got != "recon" {
		t.Errorf("fingerprint default stage = %v, want recon", got)
	}
	if got := out[0].Metadata["landed"]; got != "reachable" {
		t.Errorf("fingerprint default landed = %v, want reachable", got)
	}
	// Existing (stronger) values preserved, never overridden.
	if got := out[2].Metadata["stage"]; got != "impact" {
		t.Errorf("preserved stage = %v, want impact", got)
	}
	if got := out[3].Metadata["landed"]; got != "read-confirmed" {
		t.Errorf("preserved landed = %v, want read-confirmed", got)
	}
	// Legacy tokens normalized: proof -> impact, exploited -> execution-confirmed.
	if got := out[4].Metadata["stage"]; got != "impact" {
		t.Errorf("legacy stage 'proof' normalized = %v, want impact", got)
	}
	if got := out[4].Metadata["landed"]; got != "execution-confirmed" {
		t.Errorf("legacy landed 'exploited' normalized = %v, want execution-confirmed", got)
	}
}
