package main

import (
	"strings"
	"testing"
)

func TestMaybeWarnJSONLForLongRunningOnlyForFileBackedJSON(t *testing.T) {
	withTestConfig(t, func() {
		cfg.OutputFile = "findings.json"
		cfg.Format = "json"

		var out strings.Builder
		original := stderrWriter
		stderrWriter = &out
		defer func() { stderrWriter = original }()

		maybeWarnJSONLForLongRunning("scan")
		if !strings.Contains(out.String(), "jsonl is safer") {
			t.Fatalf("expected jsonl guidance, got %q", out.String())
		}
	})
}

func TestScanNetworkHonorsMaxHostsGuardrail(t *testing.T) {
	withTestConfig(t, func() {
		cfg.MaxHosts = 10

		err := validateExpandedHosts(256)
		if err == nil || !strings.Contains(err.Error(), "exceeds --max-hosts") {
			t.Fatalf("expected max-hosts error, got %v", err)
		}
	})
}

func TestScanNetworkAllowsUnlimitedHostsWhenDisabled(t *testing.T) {
	withTestConfig(t, func() {
		cfg.MaxHosts = 0
		if err := validateExpandedHosts(1_000_000); err != nil {
			t.Fatalf("expected disabled max-hosts guardrail, got %v", err)
		}
	})
}

func TestValidatePortNumberRejectsOutOfRangeValues(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		if err := validatePortNumber(port); err == nil {
			t.Fatalf("expected out-of-range port %d to fail", port)
		}
	}
	if err := validatePortNumber(443); err != nil {
		t.Fatalf("expected 443 to be valid, got %v", err)
	}
}

func TestNormalizeAndWarnTargetWarnsOnMalformedInput(t *testing.T) {
	var out strings.Builder
	original := stderrWriter
	stderrWriter = &out
	defer func() { stderrWriter = original }()

	normalized := normalizeAndWarnTarget("http://")
	if normalized == "" {
		t.Fatal("expected normalized target to be returned")
	}
	if !strings.Contains(out.String(), "appears malformed") {
		t.Fatalf("expected malformed warning, got %q", out.String())
	}
}
