package main

import (
	"strings"
	"testing"
)

// classifyVDBCredentialMatch (shared by vectordb search-sensitive and ollama prompts)
// must capture the FULL DSN, not just the scheme, and must reject PII and label-only
// "credentials" so the credential index stays clean.
func TestClassifyVDBCredentialMatch(t *testing.T) {
	cases := []struct {
		name        string
		pattern     string
		context     string
		wantType    string
		wantValue   string // "" means: expect this pattern to be dropped
		valueSubstr string // if set, wantValue is checked with Contains instead of ==
	}{
		{
			name:      "full DSN, not just scheme",
			pattern:   "Connection String",
			context:   "DATABASE_URL=postgresql://admin:Sup3rS3cret@db.acme.com:5432/prod",
			wantType:  "db-connection-string",
			wantValue: "postgresql://admin:Sup3rS3cret@db.acme.com:5432/prod",
		},
		{
			name:      "real bearer token extracted",
			pattern:   "Bearer Token",
			context:   "Authorization: Bearer livetoken0123456789abcdef",
			wantType:  "bearer-token",
			wantValue: "livetoken0123456789abcdef",
		},
		{
			name:    "bearer label rejected",
			pattern: "Bearer Token",
			context: "Bearer Token",
		},
		{
			name:    "email PII is not a credential",
			pattern: "Email Address",
			context: "contact St4g1ngPwd@db-stage-01.acme.internal",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotValue := classifyVDBCredentialMatch(tc.pattern, tc.context)
			if tc.wantType == "" {
				if gotType != "" {
					t.Fatalf("expected %q to be dropped, got type=%q value=%q", tc.pattern, gotType, gotValue)
				}
				return
			}
			if gotType != tc.wantType {
				t.Fatalf("type: got %q want %q (value=%q)", gotType, tc.wantType, gotValue)
			}
			if gotValue != tc.wantValue {
				t.Fatalf("value: got %q want %q", gotValue, tc.wantValue)
			}
		})
	}
}

func TestLooksLikeBearerTokenValue(t *testing.T) {
	good := []string{"livetoken0123456789abcdef", "eyJhbGci.eyJzdWIi.sig01234567", "abcdef0123456789ghij"}
	for _, s := range good {
		if !looksLikeBearerTokenValue(s) {
			t.Errorf("%q should be accepted as a bearer token", s)
		}
	}
	bad := []string{"Token", "Bearer Token", "acceptance_class", "short", "has spaces in it here"}
	for _, s := range bad {
		if looksLikeBearerTokenValue(s) {
			t.Errorf("%q should be rejected (label/short/non-token)", s)
		}
	}
}

// ollamaPromptCredentials must reuse the disciplined classifier: emit real secrets from
// a system prompt but drop emails and label-only matches.
func TestOllamaPromptCredentialsDropsNoise(t *testing.T) {
	defer func() { ollamaTarget = "" }()
	ollamaTarget = "http://10.0.0.1:11434"
	prompt := "Reach admin@corp.internal — the deploy key is hf_abcdefghij0123456789klmno for pulls."
	recs := ollamaPromptCredentials(prompt, "svc-model")
	if len(recs) != 1 {
		t.Fatalf("expected exactly 1 credential (the hf token), got %d: %+v", len(recs), recs)
	}
	rec := recs[0]
	if rec["type"] != "hf-token" {
		t.Fatalf("expected hf-token, got %v", rec["type"])
	}
	if v, _ := rec["value"].(string); !strings.HasPrefix(v, "hf_") {
		t.Fatalf("expected the raw hf token as value, got %q", v)
	}
}
