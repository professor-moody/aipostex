package credchain

import (
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// The auth-sweep finding serializes the "empty-bearer" pattern label adjacent to
// the "acceptance_class" metadata key. The old bearerTokenRe (`bearer\s+…`) matched
// "bearer" (from empty-bearer) across the newline and captured "acceptance_class"
// as a bearer-token credential, which then poisoned Next Actions with
// `--header "Authorization: Bearer acceptance_class"`.
func TestBearerTokenRejectsFieldNameFalsePositive(t *testing.T) {
	f := report.Finding{
		ID:       "t1",
		Target:   "http://10.0.0.1:4000",
		Evidence: "auth_pattern=empty-bearer\nacceptance_class=inference-capable\nfailure_class=none",
	}
	store := ExtractFromFindings([]report.Finding{f})
	for _, c := range store.ForTarget("10.0.0.1:4000") {
		if LooksLikeMetadataKey(c.Value) {
			t.Fatalf("extracted a metadata key as a credential: type=%s value=%q", c.Type, c.Value)
		}
	}
}

// A genuine "Authorization: Bearer <token>" must still be extracted.
func TestBearerTokenStillExtractsRealHeader(t *testing.T) {
	f := report.Finding{
		ID:       "t2",
		Target:   "http://10.0.0.1:4000",
		Evidence: "Authorization: Bearer livetoken0123456789abcdef",
	}
	store := ExtractFromFindings([]report.Finding{f})
	found := false
	for _, c := range store.ForTarget("10.0.0.1:4000") {
		if c.Value == "livetoken0123456789abcdef" {
			found = true
		}
	}
	if !found {
		t.Fatal("a real Bearer token should still be extracted")
	}
}

// A compound word ending in "bearer" (with no real token after it) must not yield a credential.
func TestBearerTokenIgnoresCompoundWord(t *testing.T) {
	f := report.Finding{
		ID:       "t3",
		Target:   "http://10.0.0.1:4000",
		Evidence: "the empty-bearer pattern was accepted by the endpoint",
	}
	store := ExtractFromFindings([]report.Finding{f})
	for _, c := range store.ForTarget("10.0.0.1:4000") {
		if c.Type == "bearer-token" {
			t.Fatalf("compound word 'empty-bearer' must not yield a bearer-token: %q", c.Value)
		}
	}
}

func TestLooksLikeMetadataKey(t *testing.T) {
	for _, s := range []string{"acceptance_class", "auth_pattern", "failure_class", "model_attempts"} {
		if !LooksLikeMetadataKey(s) {
			t.Errorf("%q should be recognized as a metadata key", s)
		}
	}
	for _, s := range []string{"livetoken0123456789abcdef", "sk-live-abc", "AKIAIOSFODNN7", "hf_FAKE_x"} {
		if LooksLikeMetadataKey(s) {
			t.Errorf("%q is a real credential shape, not a metadata key", s)
		}
	}
}
