package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/listener"
	"github.com/professor-moody/aipostex/pkg/report"
)

// A callback must be persisted to the operator's configured output file (as a
// JSONL line), not only echoed to stderr, so canary hits land in the findings
// sink for later correlation.
func TestListenerOnEventPersistsToOutputFile(t *testing.T) {
	withTestConfig(t, func() {
		outPath := filepath.Join(t.TempDir(), "callbacks.jsonl")
		cfg.OutputFile = outPath

		cb := listenerOnEvent("http")
		cb(listener.CallbackEvent{
			Timestamp:  time.Unix(1_700_000_000, 0).UTC(),
			Protocol:   "http",
			RemoteAddr: "10.1.2.3:44321",
			Body:       "GET /a1b2c3-canary HTTP/1.1",
			RawSize:    64,
		})

		raw, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("read output file: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) != 1 {
			t.Fatalf("expected 1 JSONL line, got %d: %q", len(lines), string(raw))
		}

		var f report.Finding
		if err := json.Unmarshal([]byte(lines[0]), &f); err != nil {
			t.Fatalf("unmarshal finding: %v", err)
		}
		if f.Source != report.SourceListener {
			t.Errorf("source = %q, want %q", f.Source, report.SourceListener)
		}
		if f.Evidence != "GET /a1b2c3-canary HTTP/1.1" {
			t.Errorf("evidence = %q, want the raw callback body", f.Evidence)
		}
		if f.Metadata["remote_addr"] != "10.1.2.3:44321" {
			t.Errorf("remote_addr metadata = %v, want 10.1.2.3:44321", f.Metadata["remote_addr"])
		}
	})
}

// With no output file configured, the callback must not error or create files;
// stderr echo is the only sink.
func TestListenerOnEventNoOutputFileIsSafe(t *testing.T) {
	withTestConfig(t, func() {
		cfg.OutputFile = ""
		cb := listenerOnEvent("dns")
		cb(listener.CallbackEvent{
			Timestamp:  time.Unix(1_700_000_000, 0).UTC(),
			Protocol:   "dns",
			RemoteAddr: "10.9.9.9:53",
			Body:       "canary.example.com",
			RawSize:    18,
		})
	})
}
