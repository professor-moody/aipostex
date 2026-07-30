package report

import (
	"strings"
	"testing"
	"time"
)

func TestIsValidSeverity(t *testing.T) {
	for _, s := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if !IsValidSeverity(s) {
			t.Errorf("IsValidSeverity(%q) = false", s)
		}
	}
	if IsValidSeverity("nope") {
		t.Fatal("expected invalid severity")
	}
	if !IsValidSeverity("  HIGH  ") {
		t.Fatal("expected case-insensitive trim match")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	if got := NormalizeSeverity("HIGH"); got != SeverityHigh {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeSeverity("unknown"); got != SeverityInfo {
		t.Fatalf("unknown should map to info, got %q", got)
	}
}

func TestFindingCollectionStatsNormalizesSeverity(t *testing.T) {
	fc := &FindingCollection{
		Findings: []Finding{
			{Severity: "HIGH"},
			{Severity: "critical"},
			{Severity: "bogus"},
		},
	}
	st := fc.Stats()
	if st[SeverityHigh] != 1 || st[SeverityCritical] != 1 || st[SeverityInfo] != 1 {
		t.Fatalf("unexpected stats: %#v", st)
	}
}

func TestFindingCollectionAddSetsTimestamp(t *testing.T) {
	fc := NewCollection()
	f := Finding{Title: "x", Severity: SeverityInfo}
	fc.Add(f)
	if fc.Findings[0].Timestamp.IsZero() {
		t.Fatal("expected timestamp set")
	}
}

func TestNewFindingIDFormat(t *testing.T) {
	id := NewFindingID(SourceOllama)
	if !strings.HasPrefix(id, SourceOllama+"-") {
		t.Fatalf("expected prefix %s-, got %s", SourceOllama, id)
	}
	parts := strings.Split(id, "-")
	if len(parts) < 6 {
		t.Fatalf("expected uuid-like suffix, got %s", id)
	}
}

func TestDisplayKeysForSource(t *testing.T) {
	keys := DisplayKeysForSource(SourceMCP)
	if len(keys) == 0 {
		t.Fatal("expected mcp keys")
	}
	fingerprintKeys := DisplayKeysForSource(SourceFingerprint)
	foundMatchKind := false
	foundConfidence := false
	for _, key := range fingerprintKeys {
		if key == "match_kind" {
			foundMatchKind = true
		}
		if key == "confidence" {
			foundConfidence = true
		}
	}
	if !foundMatchKind || !foundConfidence {
		t.Fatalf("expected fingerprint display keys to include match_kind/confidence, got %v", fingerprintKeys)
	}
	fallback := DisplayKeysForSource("unknown-module-xyz")
	if len(fallback) == 0 {
		t.Fatal("expected fallback keys")
	}
}

func TestFindingCollectionToJSONSetsEndTime(t *testing.T) {
	fc := NewCollection()
	fc.Add(Finding{Title: "t", Severity: SeverityInfo})
	start := fc.StartTime
	time.Sleep(2 * time.Millisecond)
	data, err := fc.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !fc.EndTime.After(start) && !fc.EndTime.Equal(start) {
		t.Fatal("expected EndTime updated")
	}
	if !strings.Contains(string(data), `"findings"`) {
		t.Fatal("expected findings in JSON")
	}
}
