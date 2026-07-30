package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/fingerprint"
	"github.com/professor-moody/aipostex/pkg/report"
)

type stubWriter struct{}

func (stubWriter) WriteFinding(report.Finding) error { return nil }
func (stubWriter) WriteHeader() error                { return nil }
func (stubWriter) WriteFooter(map[string]int) error  { return nil }
func (stubWriter) Close() error                      { return nil }

func TestRunScanReturnsPartialFailureWithoutFindings(t *testing.T) {
	prevTargets := scanTargets
	prevTags := scanTags
	prevTemplDir := scanTemplDir
	prevMode := scanMode
	prevErr := stderrWriter
	defer func() {
		scanTargets = prevTargets
		scanTags = prevTags
		scanTemplDir = prevTemplDir
		scanMode = prevMode
		stderrWriter = prevErr
	}()

	templateDir := t.TempDir()
	template := `id: unit-request-error
info:
  name: "Unit request error"
  severity: info
  author: test
  description: "test request error template"
  tags:
    - unit-request-error
checks:
  - name: "request-error"
    method: GET
    path: /health
    matchers:
      - type: status
        value: "200"
    finding:
      title: "unexpected finding"
      description: "should not match"
`
	if err := os.WriteFile(filepath.Join(templateDir, "unit-request-error.yaml"), []byte(template), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	withTestConfig(t, func() {
		scanTargets = []string{"http://127.0.0.1:1"}
		scanTags = []string{"unit-request-error"}
		scanTemplDir = templateDir
		scanMode = "detect"
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "findings.jsonl")
		cfg.Concurrency = 1
		var stderr bytes.Buffer
		stderrWriter = &stderr

		err := runScan(nil, nil)
		var partialErr *exitcode.PartialError
		if !errors.As(err, &partialErr) {
			t.Fatalf("expected PartialError, got %v", err)
		}
		if partialErr.Failed != 1 {
			t.Fatalf("expected Failed=1, got %+v", partialErr)
		}
		if !strings.Contains(partialErr.Error(), "request errors") {
			t.Fatalf("expected request-error cause, got %v", partialErr)
		}
	})
}

func TestPrintScanSummaryIncludesTemplateErrors(t *testing.T) {
	var out bytes.Buffer
	printScanSummary(&out, scanSummary{
		TargetsAttempted:          1,
		TargetsWithTemplateErrors: 1,
		TargetsWithFailures:       1,
	}, map[string]int{})

	if !strings.Contains(out.String(), "1 target(s) with template errors") {
		t.Fatalf("expected template-error summary, got %q", out.String())
	}
}

func TestWriteScanAllResultsReturnsPartialFailureWithoutFindings(t *testing.T) {
	prevErr := stderrWriter
	defer func() { stderrWriter = prevErr }()

	var stderr bytes.Buffer
	stderrWriter = &stderr

	err := writeScanAllResults(
		stubWriter{},
		nil,
		[]fingerprint.PortObservation{{Host: "10.0.0.5", Port: 7860, URL: "http://10.0.0.5:7860", PortState: "open", FingerprintStatus: fingerprint.MatchKindConfirmed, Results: []fingerprint.Result{{Service: "gradio", URL: "http://10.0.0.5:7860"}}}},
		[]fingerprint.Result{{Service: "gradio", URL: "http://10.0.0.5:7860"}},
		scanAllSummary{
			ServicesDiscovered:       1,
			TemplateScanAttempts:     1,
			ServicesWithScanFailures: 1,
			TemplateRequestErrors:    2,
			TemplateErrors:           1,
			EnumerationAttempts:      1,
			EnumerationFailures:      1,
		},
	)

	var partialErr *exitcode.PartialError
	if !errors.As(err, &partialErr) {
		t.Fatalf("expected PartialError, got %v", err)
	}
	if !strings.Contains(stderr.String(), "incomplete coverage") {
		t.Fatalf("expected incomplete coverage summary, got %q", stderr.String())
	}
}

func TestWriteScanAllResultsFindingsTakePrecedenceOverPartialFailure(t *testing.T) {
	err := writeScanAllResults(
		stubWriter{},
		[]report.Finding{{
			ID:       "finding-1",
			Source:   report.SourceVulnCheck,
			Target:   "http://10.0.0.5:7860",
			Title:    "Gradio No Auth",
			Severity: report.SeverityHigh,
		}},
		[]fingerprint.PortObservation{{Host: "10.0.0.5", Port: 7860, URL: "http://10.0.0.5:7860", PortState: "open", FingerprintStatus: fingerprint.MatchKindConfirmed, Results: []fingerprint.Result{{Service: "gradio", URL: "http://10.0.0.5:7860"}}}},
		[]fingerprint.Result{{Service: "gradio", URL: "http://10.0.0.5:7860"}},
		scanAllSummary{
			ServicesDiscovered:       1,
			ServicesWithScanFailures: 1,
			EnumerationFailures:      1,
		},
	)

	var fpe *exitcode.FindingsPartialError
	if !errors.As(err, &fpe) {
		t.Fatalf("expected FindingsPartialError, got %v", err)
	}
}

func TestPrintNetworkScanSummaryIncludesIncompleteCoverage(t *testing.T) {
	var out bytes.Buffer
	printNetworkScanSummary(&out, networkScanSummary{
		HostsExpanded:         1,
		OpenPorts:             1,
		ServicesDiscovered:    1,
		FindingsEmitted:       0,
		TemplateScanErrors:    1,
		TemplateRequestErrors: 2,
		TemplateErrors:        3,
	}, map[string]int{}, false)

	if !strings.Contains(out.String(), "incomplete coverage") {
		t.Fatalf("expected incomplete coverage line, got %q", out.String())
	}
}

var _ output.Writer = stubWriter{}
