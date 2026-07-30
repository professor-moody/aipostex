package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestRunReportViewPrintsCredentialsCommandsAndEvidence(t *testing.T) {
	path := writeJSONLFindings(t, []report.Finding{
		{
			ID:       "ray-1",
			Source:   report.SourceRay,
			Target:   "http://172.16.50.20:8265",
			Title:    "Ray job runtime_env secrets exposed: training",
			Severity: report.SeverityCritical,
			Evidence: "MLFLOW_TRACKING_URI=http://localhost:5000\nSTRIPE_BILLING_KEY=sk_live_fake_billing_key_123456",
			Metadata: map[string]interface{}{
				"extracted_credentials": []interface{}{
					map[string]interface{}{
						"type":          "mlflow-url",
						"name":          "MLFLOW_TRACKING_URI",
						"value":         "http://localhost:5000",
						"source_target": "http://172.16.50.20:8265",
						"target_url":    "http://172.16.50.20:5000",
						"chainable":     true,
						"note":          "service URL disclosed by Ray runtime_env",
					},
					map[string]interface{}{
						"type":          "secret",
						"name":          "STRIPE_BILLING_KEY",
						"value":         "sk_live_fake_billing_key_123456",
						"source_target": "http://172.16.50.20:8265",
						"chainable":     false,
						"note":          "sensitive runtime_env value; no concrete aipostex follow-on module inferred",
					},
				},
			},
		},
	})
	resetReportViewFlags(t)
	reportViewCredentials = true
	reportViewCommands = true
	reportViewEvidence = true

	out := captureStdout(t, func() {
		if err := runReportView(nil, []string{path}); err != nil {
			t.Fatalf("runReportView returned error: %v", err)
		}
	})
	for _, want := range []string{
		"MLFLOW_TRACKING_URI=http://localhost:5000",
		"sk_live_fake_billing_key_123456",
		"aipostex mlflow --target http://172.16.50.20:5000 enum",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "stripe --") {
		t.Fatalf("did not expect unsupported Stripe command:\n%s", out)
	}
	if strings.Index(out, "Credentials") > strings.Index(out, "Evidence") {
		t.Fatalf("expected credentials before full evidence for operator readability:\n%s", out)
	}
}

func resetReportViewFlags(t *testing.T) {
	t.Helper()
	prevSource := reportViewSource
	prevService := reportViewService
	prevTarget := reportViewTarget
	prevSeverity := reportViewSeverity
	prevTitle := reportViewTitleContains
	prevID := reportViewID
	prevEvidence := reportViewEvidence
	prevCredentials := reportViewCredentials
	prevCommands := reportViewCommands
	prevLimit := reportViewLimit
	prevDossierDir := reportViewDossierDir
	reportViewSource = ""
	reportViewService = ""
	reportViewTarget = ""
	reportViewSeverity = ""
	reportViewTitleContains = ""
	reportViewID = ""
	reportViewEvidence = false
	reportViewCredentials = false
	reportViewCommands = false
	reportViewLimit = 0
	reportViewDossierDir = ""
	t.Cleanup(func() {
		reportViewSource = prevSource
		reportViewService = prevService
		reportViewTarget = prevTarget
		reportViewSeverity = prevSeverity
		reportViewTitleContains = prevTitle
		reportViewID = prevID
		reportViewEvidence = prevEvidence
		reportViewCredentials = prevCredentials
		reportViewCommands = prevCommands
		reportViewLimit = prevLimit
		reportViewDossierDir = prevDossierDir
	})
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = old
	})

	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(raw)
}
