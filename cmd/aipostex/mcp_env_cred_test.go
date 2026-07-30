package main

import "testing"

// mcp env-extract / chain must emit structured extracted_credentials with the real type,
// the RAW value (no masking), and chainability decided by whether autochain can act on
// the type — so API keys land in Actionable Pivots and service tokens in Viewer-Only.
func TestMCPEnvCredentialRecordStructured(t *testing.T) {
	rec := mcpEnvCredentialRecord("ANTHROPIC_API_KEY", "sk-ant-secret", "http://x:3000", "tool reflection")
	if len(rec) != 1 {
		t.Fatalf("expected 1 record, got %d", len(rec))
	}
	r := rec[0]
	if r["type"] != "anthropic-api-key" {
		t.Fatalf("expected type anthropic-api-key, got %v", r["type"])
	}
	if r["value"] != "sk-ant-secret" {
		t.Fatalf("expected raw value (no masking), got %v", r["value"])
	}
	if r["chainable"] != true {
		t.Fatalf("anthropic-api-key should be chainable, got %v", r["chainable"])
	}

	svc := mcpEnvCredentialRecord("INTERNAL_SERVICE_TOKEN", "abc123", "http://x:3000", "env")[0]
	if svc["type"] != "internal-service-token" {
		t.Fatalf("expected internal-service-token (its real type, not jupyter), got %v", svc["type"])
	}
	if svc["chainable"] != false {
		t.Fatalf("service token should be viewer-only (not chainable), got %v", svc["chainable"])
	}
}
