package report

import "testing"

// The five canonical landed values and four canonical stages. Every value the tool
// emits must normalize onto these — no module may leak a non-canonical token to output.
var canonicalLanded = map[string]bool{
	"reachable": true, "influenced": true, "read-confirmed": true,
	"execution-confirmed": true, "takeover-capable": true,
}

var canonicalStage = map[string]bool{
	StageRecon: true, StageAccess: true, StageImpact: true, StageOwn: true,
}

func TestNormalizeLandedMapsEveryEmittedTokenToCanonical(t *testing.T) {
	// Left side: every landed token any module handler / template actually emits
	// (audited across cmd/, pkg/, internal/ and pkg/vulncheck/templates). Right side:
	// the canonical value it must collapse to. If a handler starts emitting a new
	// token, add it here AND to NormalizeLanded — output must never carry a stray value.
	cases := map[string]string{
		// canonical values pass through unchanged
		"reachable":           "reachable",
		"influenced":          "influenced",
		"read-confirmed":      "read-confirmed",
		"execution-confirmed": "execution-confirmed",
		"takeover-capable":    "takeover-capable",
		// legacy / descriptive tokens map honestly
		"exploited":             "execution-confirmed",
		"shell-deployed":        "execution-confirmed",
		"confirmed":             "read-confirmed",
		"confirmed-usable":      "read-confirmed",
		"partial-persistence":   "read-confirmed",
		"submission-accepted":   "influenced",
		"note":                  "influenced",
		"injection-only":        "influenced",
		"inconclusive":          "reachable",
		"persistence-deployed":  "takeover-capable",
		"persistence-confirmed": "takeover-capable",
		"llm-confirmed":         "takeover-capable",
	}
	for in, want := range cases {
		got := NormalizeLanded(in)
		if got != want {
			t.Errorf("NormalizeLanded(%q) = %q, want %q", in, got, want)
		}
		if !canonicalLanded[got] {
			t.Errorf("NormalizeLanded(%q) = %q, which is NOT one of the five canonical landed values", in, got)
		}
	}
}

func TestNormalizeStageMapsEveryEmittedTokenToCanonical(t *testing.T) {
	// Left side: every stage token the finding-metadata path historically set. Right
	// side: the canonical kill-chain stage it must collapse to. (The workflow-plan
	// Stage axis — discovery/correlation/proof/takeover/model — is a separate field
	// and is intentionally NOT normalized here.)
	cases := map[string]string{
		StageRecon:       StageRecon,
		StageAccess:      StageAccess,
		StageImpact:      StageImpact,
		StageOwn:         StageOwn,
		"discovery":      StageRecon,
		"probe":          StageRecon,
		"enum":           StageRecon,
		"attempted":      StageRecon,
		"correlation":    StageAccess,
		"submission":     StageAccess,
		"proof":          StageImpact,
		"exploited":      StageImpact,
		"confirmed":      StageImpact,
		"rag-round-trip": StageImpact,
		"takeover":       StageOwn,
	}
	for in, want := range cases {
		got := NormalizeStage(in)
		if got != want {
			t.Errorf("NormalizeStage(%q) = %q, want %q", in, got, want)
		}
		if !canonicalStage[got] {
			t.Errorf("NormalizeStage(%q) = %q, which is NOT one of the four canonical stages", in, got)
		}
	}
}
