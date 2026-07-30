package credchain

import (
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// TestJWTNotMisclassifiedAsJupyterToken guards the release blocker where a JWT in a
// finding's evidence was captured only up to its first dot and mislabeled as a
// "jupyter-token" (which then generated a misleading `aipostex jupyter` command
// against a non-Jupyter target). A JWT must be captured whole and typed as a bearer
// token — never as a jupyter token.
func TestJWTNotMisclassifiedAsJupyterToken(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.acme-internal-2024-prod"
	f := report.Finding{
		ID:       "f1",
		Source:   "ollama",
		Target:   "http://172.16.50.10:11434",
		Evidence: "Internal API Gateway: https://api-internal.acme.corp/v2\n  Bearer Token: " + jwt,
	}

	store := ExtractFromFindings([]report.Finding{f})
	creds := store.ForTarget("172.16.50.10:11434")

	var haveBearer, haveJupyter bool
	for _, c := range creds {
		switch c.Type {
		case "jupyter-token":
			haveJupyter = true
		case "bearer-token":
			haveBearer = true
			if c.Value != jwt {
				t.Errorf("JWT truncated: got %q, want full token %q", c.Value, jwt)
			}
		}
	}

	if haveJupyter {
		t.Error("JWT was mis-classified as a jupyter-token")
	}
	if !haveBearer {
		t.Error("JWT was not captured as a bearer-token")
	}
}

// TestJWTInTokenURLNotJupyterToken covers the ?token=<jwt> URL form, which the
// jupyter-URL regex would otherwise truncate at the first dot.
func TestJWTInTokenURLNotJupyterToken(t *testing.T) {
	jwt := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123"
	f := report.Finding{
		ID:       "f2",
		Source:   "vectordb",
		Target:   "http://172.16.50.20:8000",
		Evidence: "callback https://jupyter.acme.internal:8888/?token=" + jwt,
	}

	store := ExtractFromFindings([]report.Finding{f})
	for _, c := range store.ForTarget("172.16.50.20:8000") {
		if c.Type == "jupyter-token" {
			t.Errorf("JWT in token= URL mis-classified as jupyter-token: %q", c.Value)
		}
		if c.Type == "bearer-token" && c.Value != jwt {
			t.Errorf("JWT truncated: got %q, want %q", c.Value, jwt)
		}
	}
}
