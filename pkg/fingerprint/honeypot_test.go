package fingerprint

import (
	"testing"
)

func TestDetectHoneypotSignals_HighOpenRatio(t *testing.T) {
	// 9 out of 10 ports open → 90% → should trigger
	obs := make([]PortObservation, 9)
	for i := range obs {
		obs[i] = PortObservation{Host: "10.0.0.1", Port: 1000 + i, PortState: "open"}
	}
	signals := DetectHoneypotSignals(obs, 10)
	found := false
	for _, s := range signals {
		if s.Host == "10.0.0.1" && contains(s.Reason, "90%") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected high open-port ratio signal, got %v", signals)
	}
}

func TestDetectHoneypotSignals_BelowThreshold(t *testing.T) {
	// 5 out of 10 ports open → 50% → should NOT trigger ratio warning
	obs := make([]PortObservation, 5)
	for i := range obs {
		obs[i] = PortObservation{Host: "10.0.0.1", Port: 8000 + i, PortState: "open"}
	}
	signals := DetectHoneypotSignals(obs, 10)
	for _, s := range signals {
		if contains(s.Reason, "scanned ports are open") {
			t.Errorf("should not trigger ratio warning at 50%%, got %v", s)
		}
	}
}

func TestDetectHoneypotSignals_NoRatioWarningForTargetedFewPortScan(t *testing.T) {
	obs := []PortObservation{{Host: "10.0.0.1", Port: 5432, PortState: "open"}}
	signals := DetectHoneypotSignals(obs, 1)
	for _, s := range signals {
		if contains(s.Reason, "scanned ports are open") {
			t.Fatalf("targeted one-port scan should not trigger ratio warning, got %v", signals)
		}
	}
}

func TestDetectHoneypotSignals_AIOnNonAIPort(t *testing.T) {
	obs := []PortObservation{
		{
			Host: "10.0.0.1", Port: 21, PortState: "open",
			FingerprintStatus: MatchKindConfirmed,
			Results: []Result{
				{Service: "ollama", MatchKind: MatchKindConfirmed},
			},
		},
		{
			Host: "10.0.0.1", Port: 7, PortState: "open",
			FingerprintStatus: MatchKindSuspected,
			Results: []Result{
				{Service: "vllm", MatchKind: MatchKindSuspected},
			},
		},
	}
	signals := DetectHoneypotSignals(obs, 100)
	if len(signals) < 2 {
		t.Fatalf("expected at least 2 signals for AI on non-AI ports, got %d: %v", len(signals), signals)
	}
	foundOllama, foundVllm := false, false
	for _, s := range signals {
		if contains(s.Reason, "ollama") && contains(s.Reason, "21/ftp") {
			foundOllama = true
		}
		if contains(s.Reason, "vllm") && contains(s.Reason, "7/echo") {
			foundVllm = true
		}
	}
	if !foundOllama {
		t.Error("expected signal for ollama on port 21/ftp")
	}
	if !foundVllm {
		t.Error("expected signal for vllm on port 7/echo")
	}
}

func TestDetectHoneypotSignals_AIOnNormalPort(t *testing.T) {
	obs := []PortObservation{
		{
			Host: "10.0.0.1", Port: 11434, PortState: "open",
			FingerprintStatus: MatchKindConfirmed,
			Results: []Result{
				{Service: "ollama", MatchKind: MatchKindConfirmed},
			},
		},
	}
	signals := DetectHoneypotSignals(obs, 100)
	for _, s := range signals {
		if contains(s.Reason, "non-AI port") {
			t.Errorf("should not flag AI on normal port 11434, got %v", s)
		}
	}
}

func TestDetectHoneypotSignals_CleanHost(t *testing.T) {
	obs := []PortObservation{
		{Host: "10.0.0.1", Port: 8080, PortState: "open"},
		{Host: "10.0.0.1", Port: 11434, PortState: "open",
			FingerprintStatus: MatchKindConfirmed,
			Results:           []Result{{Service: "ollama", MatchKind: MatchKindConfirmed}},
		},
	}
	signals := DetectHoneypotSignals(obs, 20)
	if len(signals) != 0 {
		t.Errorf("expected no signals for clean host, got %v", signals)
	}
}

func TestDetectHoneypotSignals_Empty(t *testing.T) {
	signals := DetectHoneypotSignals(nil, 10)
	if signals != nil {
		t.Errorf("expected nil for empty observations, got %v", signals)
	}
	signals = DetectHoneypotSignals([]PortObservation{}, 0)
	if signals != nil {
		t.Errorf("expected nil for zero ports scanned, got %v", signals)
	}
}

func TestDetectHoneypotSignals_MultiHost(t *testing.T) {
	// Host A: 9/10 open (honeypot), Host B: 2/10 open (clean)
	obs := make([]PortObservation, 0, 11)
	for i := 0; i < 9; i++ {
		obs = append(obs, PortObservation{Host: "10.0.0.1", Port: 1000 + i, PortState: "open"})
	}
	obs = append(obs, PortObservation{Host: "10.0.0.2", Port: 8080, PortState: "open"})
	obs = append(obs, PortObservation{Host: "10.0.0.2", Port: 11434, PortState: "open"})

	signals := DetectHoneypotSignals(obs, 10)
	foundA, foundB := false, false
	for _, s := range signals {
		if s.Host == "10.0.0.1" && contains(s.Reason, "90%") {
			foundA = true
		}
		if s.Host == "10.0.0.2" {
			foundB = true
		}
	}
	if !foundA {
		t.Error("expected honeypot signal for host 10.0.0.1")
	}
	if foundB {
		t.Error("should not flag clean host 10.0.0.2")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && len(substr) > 0 && containsImpl(s, substr)
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
