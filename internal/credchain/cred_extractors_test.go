package credchain

import (
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// credTypesFor runs the heuristic extractors over a single file-discovery finding and
// returns the discovered credentials keyed by type.
func credTypesFor(t *testing.T, target, evidence string) map[string]string {
	t.Helper()
	f := report.Finding{
		ID:       "f-x",
		Target:   "http://" + target,
		Source:   report.SourceFileDiscovery,
		Evidence: evidence,
		Title:    "leak",
		Severity: "high",
	}
	got := map[string]string{}
	for _, c := range ExtractFromFindings([]report.Finding{f}).ForTarget(target) {
		got[c.Type] = c.Value
	}
	return got
}

func TestExtractAWSKeys(t *testing.T) {
	creds := credTypesFor(t, "10.0.0.1:8080",
		"env leak: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	if v, ok := creds["aws-access-key"]; !ok || v != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("expected aws-access-key AKIAIOSFODNN7EXAMPLE, got %q (all: %+v)", v, creds)
	}
	if v, ok := creds["aws-secret-key"]; !ok || v != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Fatalf("expected aws-secret-key, got %q (all: %+v)", v, creds)
	}
}

func TestExtractSlackWebhook(t *testing.T) {
	url := "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
	creds := credTypesFor(t, "10.0.0.1:8080", "webhook: "+url)
	if v, ok := creds["slack-webhook"]; !ok || v != url {
		t.Fatalf("expected slack-webhook %q, got %q (all: %+v)", url, v, creds)
	}
}

// A finding that leaks several webhooks must surface all of them, not just the first.
func TestExtractMultipleSlackWebhooks(t *testing.T) {
	ev := "alerts=https://hooks.slack.com/services/T0ACME01/B0ALERTS/xyzAlertWebhookToken " +
		"deploy=https://hooks.slack.com/services/T0ACME01/B0DEPLOY/xyzDeployWebhookToken"
	f := report.Finding{ID: "f-wh", Target: "http://10.0.0.1:8080", Source: report.SourceOllama, Evidence: ev, Severity: "high"}
	n := 0
	for _, c := range ExtractFromFindings([]report.Finding{f}).ForTarget("10.0.0.1:8080") {
		if c.Type == "slack-webhook" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("expected 2 slack-webhook creds, got %d", n)
	}
}

func TestExtractGitHubPAT(t *testing.T) {
	pat := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	creds := credTypesFor(t, "10.0.0.1:8080", "token: "+pat)
	if v, ok := creds["github-pat"]; !ok || v != pat {
		t.Fatalf("expected github-pat %q, got %q (all: %+v)", pat, v, creds)
	}
}

func TestExtractPagerDuty(t *testing.T) {
	creds := credTypesFor(t, "10.0.0.1:8080", "PAGERDUTY_API_KEY=uA1B2c3D4e5F6g7H8i9")
	if _, ok := creds["pagerduty-key"]; !ok {
		t.Fatalf("expected pagerduty-key, got %+v", creds)
	}
}

// A service token that merely ends in "_TOKEN" must NOT be classified as a Jupyter token
// (which would emit a bogus `jupyter` follow-up command).
func TestServiceTokenNotJupyterToken(t *testing.T) {
	creds := credTypesFor(t, "10.0.0.1:8080", "INTERNAL_SERVICE_TOKEN=abcdef0123456789abcdef0123456789")
	if _, ok := creds["jupyter-token"]; ok {
		t.Fatalf("INTERNAL_SERVICE_TOKEN must not be a jupyter-token; got %+v", creds)
	}
}

// A genuine jupyter_token config key IS a Jupyter token.
func TestJupyterTokenKeyIsJupyterToken(t *testing.T) {
	creds := credTypesFor(t, "10.0.0.1:8888", "jupyter_token=abcdef0123456789abcdef0123456789")
	if _, ok := creds["jupyter-token"]; !ok {
		t.Fatalf("jupyter_token key should be a jupyter-token; got %+v", creds)
	}
}
