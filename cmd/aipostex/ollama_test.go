package main

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{"zero bytes", 0, "0 B"},
		{"small bytes", 512, "512 B"},
		{"exactly 1 KB boundary", 1023, "1023 B"},
		{"1 KB", 1024, "1.0 KB"},
		{"1.5 KB", 1536, "1.5 KB"},
		{"1 MB", 1024 * 1024, "1.0 MB"},
		{"1 GB", 1024 * 1024 * 1024, "1.0 GB"},
		{"1 TB", 1024 * 1024 * 1024 * 1024, "1.0 TB"},
		{"4.7 GB", 5046586573, "4.7 GB"},
		{"negative value", -1, "-1 B"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := humanBytes(tc.bytes)
			if got != tc.want {
				t.Fatalf("humanBytes(%d) = %q, want %q", tc.bytes, got, tc.want)
			}
		})
	}
}

func TestMutatingOllamaFinding(t *testing.T) {
	prevTarget := ollamaTarget
	defer func() { ollamaTarget = prevTarget }()
	ollamaTarget = "http://10.0.0.5:11434"

	tests := []struct {
		name        string
		action      string
		model       string
		description string
	}{
		{"copy action", "copy", "llama3-backup", "Copied llama3 to llama3-backup"},
		{"delete action", "delete", "old-model", "Deleted model old-model"},
		{"create action", "create", "custom-model", "Created model custom-model"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := mutatingOllamaFinding(tc.action, tc.model, tc.description)

			if f.Source != report.SourceOllama {
				t.Fatalf("source = %q, want %q", f.Source, report.SourceOllama)
			}
			if f.Target != "http://10.0.0.5:11434" {
				t.Fatalf("target = %q, want %q", f.Target, "http://10.0.0.5:11434")
			}
			if f.Severity != report.SeverityHigh {
				t.Fatalf("severity = %q, want %q", f.Severity, report.SeverityHigh)
			}
			if f.Description != tc.description {
				t.Fatalf("description = %q, want %q", f.Description, tc.description)
			}
			if !strings.Contains(f.Title, tc.action) || !strings.Contains(f.Title, tc.model) {
				t.Fatalf("title should contain action and model, got %q", f.Title)
			}
			if f.Metadata["action"] != tc.action {
				t.Fatalf("metadata action = %v, want %q", f.Metadata["action"], tc.action)
			}
			if f.Metadata["model"] != tc.model {
				t.Fatalf("metadata model = %v, want %q", f.Metadata["model"], tc.model)
			}
			if f.Metadata["mutating"] != true {
				t.Fatalf("metadata mutating = %v, want true", f.Metadata["mutating"])
			}
			if f.Metadata["module"] != "ollama" {
				t.Fatalf("metadata module = %v, want ollama", f.Metadata["module"])
			}
		})
	}
}

func TestClassifyPromptSeverityEscalatesToCritical(t *testing.T) {
	tests := []struct {
		name         string
		prompt       string
		wantSeverity string
		wantHints    bool
	}{
		{
			name:         "plain prompt stays high",
			prompt:       "You are a helpful assistant.",
			wantSeverity: report.SeverityHigh,
			wantHints:    false,
		},
		{
			name:         "prompt with postgresql connection string stays high",
			prompt:       "Use this DB: postgresql://admin:secret@db.internal:5432/app",
			wantSeverity: report.SeverityHigh,
			wantHints:    true,
		},
		{
			name:         "prompt with OpenAI key",
			prompt:       "API key is sk-proj-FAKE1234567890abcdef",
			wantSeverity: report.SeverityCritical,
			wantHints:    true,
		},
		{
			name:         "prompt with AWS access key",
			prompt:       "Use AKIAFAKE1234EXAMPLE1 for authentication",
			wantSeverity: report.SeverityCritical,
			wantHints:    true,
		},
		{
			name:         "prompt with JWT token",
			prompt:       "Bearer token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8",
			wantSeverity: report.SeverityHigh,
			wantHints:    true,
		},
		{
			name:         "prompt with Slack webhook",
			prompt:       "Alert webhook: hooks.slack.com/services/T0ACME01/B0ALERTS/xyzAlertWebhookToken",
			wantSeverity: report.SeverityHigh,
			wantHints:    true,
		},
		{
			name:         "prompt with password field",
			prompt:       "Database password: SuperSecret123!",
			wantSeverity: report.SeverityHigh,
			wantHints:    true,
		},
		{
			name:         "prompt with Anthropic key escalates to critical",
			prompt:       "Use sk-ant-FAKE-abcdefghijklmnop1234567890 for requests",
			wantSeverity: report.SeverityCritical,
			wantHints:    true,
		},
		{
			name:         "prompt with private key escalates to critical",
			prompt:       "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...",
			wantSeverity: report.SeverityCritical,
			wantHints:    true,
		},
		{
			name:         "prompt with multiple credentials",
			prompt:       "DB: postgresql://admin:pw@host/db\nKey: AKIAFAKE1234EXAMPLE1\nSlack: hooks.slack.com/services/T01/B01/abc",
			wantSeverity: report.SeverityCritical,
			wantHints:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity, hints := classifyPromptSeverity(tt.prompt)
			if severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q", severity, tt.wantSeverity)
			}
			if tt.wantHints && len(hints) == 0 {
				t.Error("expected hints, got none")
			}
			if !tt.wantHints && len(hints) > 0 {
				t.Errorf("expected no hints, got %v", hints)
			}
		})
	}
}
