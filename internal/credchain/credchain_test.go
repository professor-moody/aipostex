package credchain

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// A stolen k8s SA token must be an Actionable Pivot with a real re-auth follow-on
// (regression for the no-redaction fix: the token is now raw + chainable).
func TestK8SSATokenIsChainable(t *testing.T) {
	if !IsChainableType("k8s-sa-token") {
		t.Fatal("k8s-sa-token must be chainable (Actionable Pivot)")
	}
	actions := actionsForCredential("10.0.1.50:6443", Credential{Type: "k8s-sa-token", Value: "eyJrawtoken"})
	if len(actions) == 0 {
		t.Fatal("expected follow-on actions for k8s-sa-token")
	}
	var joined string
	for _, a := range actions {
		joined += a.Command + "\n"
	}
	if !strings.Contains(joined, "https://10.0.1.50:6443") {
		t.Errorf("k8s follow-on must target the https apiserver, got: %s", joined)
	}
	// The raw token is inlined (no redaction) so each Next Action is a single directly-
	// runnable command.
	if !strings.Contains(joined, "Authorization: Bearer eyJrawtoken") {
		t.Errorf("k8s follow-on must re-auth with the raw token, got: %s", joined)
	}
	if !strings.Contains(joined, "access-review") {
		t.Errorf("expected an access-review follow-on, got: %s", joined)
	}
}

func TestExtractJupyterTokenFromURL(t *testing.T) {
	findings := []report.Finding{{
		ID:       "f-1",
		Target:   "http://10.0.0.5:8888?token=abc123def456ghi789",
		Source:   report.SourceVulnCheck,
		Title:    "Jupyter No Auth",
		Severity: "high",
	}}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.5:8888")
	if len(creds) == 0 {
		t.Fatal("expected credentials for Jupyter target")
	}
	found := false
	for _, c := range creds {
		if c.Type == "jupyter-token" && c.Value == "abc123def456ghi789" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected jupyter-token with value abc123def456ghi789, got %+v", creds)
	}
}

func TestExtractJupyterTokenFromEvidence(t *testing.T) {
	findings := []report.Finding{{
		ID:       "f-2",
		Target:   "http://10.0.0.5:8888",
		Source:   report.SourceVulnCheck,
		Evidence: "Token found in URL: http://10.0.0.5:8888/?token=mysecrettoken1234567890",
		Title:    "Jupyter token exposed",
		Severity: "high",
	}}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.5:8888")
	if len(creds) == 0 {
		t.Fatal("expected credentials from evidence")
	}
	if creds[0].Type != "jupyter-token" {
		t.Fatalf("expected jupyter-token, got %s", creds[0].Type)
	}
}

func TestExtractOpenAIKey(t *testing.T) {
	findings := []report.Finding{{
		ID:       "f-3",
		Target:   "http://10.0.0.1:4000",
		Source:   report.SourceFileDiscovery,
		Evidence: "Content match: OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx",
		Title:    "API key found",
		Severity: "high",
	}}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.1:4000")
	if len(creds) == 0 {
		t.Fatal("expected OpenAI API key")
	}
	found := false
	for _, c := range creds {
		if c.Type == "openai-api-key" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected openai-api-key, got %+v", creds)
	}
}

func TestExtractDBConnString(t *testing.T) {
	findings := []report.Finding{{
		ID:       "f-db",
		Target:   "http://10.0.0.1:3000",
		Source:   report.SourceMCP,
		Evidence: "Connection: postgresql://mcp_svc:McpSvcPr0d!@db-prod-01.acme.internal:5432/acme_hr",
		Title:    "tool leaks DB string",
		Severity: "high",
	}}
	creds := ExtractFromFindings(findings).ForTarget("10.0.0.1:3000")
	found := false
	for _, c := range creds {
		if c.Type == "db-connection-string" && strings.Contains(c.Value, "db-prod-01.acme.internal:5432/acme_hr") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected db-connection-string with embedded creds, got %+v", creds)
	}
}

func TestDBConnStringRequiresEmbeddedCreds(t *testing.T) {
	// A URI WITHOUT embedded user:pass must NOT match (no false positives on plain URLs).
	for _, noauth := range []string{
		"http://db-prod-01.acme.internal:5432/acme_hr",
		"postgresql://db-prod-01.acme.internal:5432/acme_hr",
	} {
		if dbConnStringRe.MatchString(noauth) {
			t.Fatalf("expected %q not to match the DB-cred pattern", noauth)
		}
	}
}

func TestExtractRedisAndSnowflakeConnStrings(t *testing.T) {
	findings := []report.Finding{{
		ID: "f-ray", Target: "http://10.0.0.2:8265", Source: report.SourceMCP, Severity: "high",
		Title:    "ray runtime-env leaks connection strings",
		Evidence: "REDIS_URL=redis://:R3d1sMlC4ch3!@redis-ml.acme.internal:6379/0\nSNOWFLAKE_URI=snowflake://ray_svc:R4ySvcSn0w!@acme.snowflakecomputing.com/ML/FEATURES",
	}}
	creds := ExtractFromFindings(findings).ForTarget("10.0.0.2:8265")
	var sawRedis, sawSnow bool
	for _, c := range creds {
		if c.Type == "db-connection-string" && strings.Contains(c.Value, "redis-ml.acme.internal:6379") {
			sawRedis = true
		}
		if c.Type == "db-connection-string" && strings.Contains(c.Value, "acme.snowflakecomputing.com") {
			sawSnow = true
		}
	}
	if !sawRedis {
		t.Errorf("expected redis:// (empty-user) connection string captured, got %+v", creds)
	}
	if !sawSnow {
		t.Errorf("expected snowflake:// connection string captured, got %+v", creds)
	}
}

func TestRedisNoAuthNotCaptured(t *testing.T) {
	if dbConnStringRe.MatchString("redis://redis-ml.acme.internal:6379/0") {
		t.Fatal("a no-auth redis URI must not match the DB-cred pattern")
	}
}

func TestExtractAWSKeyPair(t *testing.T) {
	findings := []report.Finding{{
		ID: "f-aws", Target: "http://10.0.0.1:11434", Source: report.SourceMCP, Severity: "high",
		Title:    "system prompt leaks AWS key pair",
		Evidence: "AWS Access Key: AKIAFAKE1234EXAMPLE1 / FakeSecretKey+abcdefghijk1234567890",
	}}
	creds := ExtractFromFindings(findings).ForTarget("10.0.0.1:11434")
	found := false
	for _, c := range creds {
		if c.Type == "aws-access-key" && strings.Contains(c.Value, "AKIAFAKE1234EXAMPLE1") && strings.Contains(c.Value, "FakeSecretKey+abcdefghijk1234567890") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a usable AWS access-key+secret pair, got %+v", creds)
	}
}

func TestExtractLabeledSecretsAndPairs(t *testing.T) {
	ev := strings.Join([]string{
		"Jira: svc-jira-bot / J1r4B0t#2024!",
		"SharePoint: sp-admin@acme.corp / Sh4r3P01nt@dm1n",
		"Okta: okta-admin@acme.corp / 0kt4Adm1n!2024",
		"PagerDuty API: pd-api-key-FAKE-abcdef1234567890",
		"CRM API Key: sk-acme-cust-api-99xKf82mNpQ3",
		"Ticket API Key: tkt-api-FAKE-abc123def456",
		"Manager Override Code: ESC-2024-ADMIN",
	}, "\n")
	findings := []report.Finding{{ID: "f-lbl", Target: "http://10.0.0.1:11434", Source: report.SourceMCP, Severity: "high", Title: "system prompt leaks labeled secrets", Evidence: ev}}
	creds := ExtractFromFindings(findings).ForTarget("10.0.0.1:11434")
	for _, w := range []string{"J1r4B0t#2024!", "Sh4r3P01nt@dm1n", "0kt4Adm1n!2024", "pd-api-key-FAKE-abcdef1234567890", "sk-acme-cust-api-99xKf82mNpQ3", "tkt-api-FAKE-abc123def456", "ESC-2024-ADMIN"} {
		found := false
		for _, c := range creds {
			if strings.Contains(c.Value, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected a credential containing %q, got %+v", w, creds)
		}
	}
}

func TestExtractHyphenServiceToken(t *testing.T) {
	findings := []report.Finding{{ID: "f-mcp", Target: "http://10.0.0.1:3000", Source: report.SourceMCP, Severity: "high", Title: "MCP tool description leaks a build-admin token", Evidence: "Requires the build admin token sk-mcp-FAKE-build-admin-9f3a2b1c (already configured server-side)."}}
	creds := ExtractFromFindings(findings).ForTarget("10.0.0.1:3000")
	found := false
	for _, c := range creds {
		if strings.Contains(c.Value, "sk-mcp-FAKE-build-admin-9f3a2b1c") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected hyphenated sk-mcp service token captured, got %+v", creds)
	}
}

func TestServicePairRejectsNonCredentials(t *testing.T) {
	// Shapes the "Label: a / b" pattern also matches but which are NOT credentials:
	// a DSN port+db name, an HTTP request line, and a bare-word "password".
	ev := strings.Join([]string{
		"DATABASE_URL=postgresql://ml_pipeline:MlP1p3l1n3!Pr0d@db-prod-01.acme.internal:5432/acme_hr",
		"request: GET /playground HTTP/1.1",
		"route: GET / model",
	}, "\n")
	findings := []report.Finding{{ID: "f-neg", Target: "http://10.0.0.1:8265", Source: report.SourceMCP, Severity: "high", Title: "ray runtime-env", Evidence: ev}}
	creds := ExtractFromFindings(findings).ForTarget("10.0.0.1:8265")
	for _, c := range creds {
		for _, bogus := range []string{"5432 / acme_hr", "GET / playground", "GET / model"} {
			if c.Value == bogus {
				t.Errorf("falsely captured non-credential %q: %+v", bogus, c)
			}
		}
	}
}

func TestAWSKeyNotTruncated(t *testing.T) {
	// A 21-char AKIA token (AKIA + 17) must be captured WHOLE, not truncated to a 20-char
	// partial that reads as a second, bogus credential.
	findings := []report.Finding{{ID: "f-awslong", Target: "http://10.0.0.2:8265", Source: report.SourceMCP, Severity: "high", Title: "ray leaks aws", Evidence: "AWS_ACCESS_KEY_ID=AKIAFAKERAYML12345678"}}
	creds := ExtractFromFindings(findings).ForTarget("10.0.0.2:8265")
	var full, partial bool
	for _, c := range creds {
		if strings.Contains(c.Value, "AKIAFAKERAYML12345678") {
			full = true
		}
		if c.Value == "AKIAFAKERAYML1234567" { // the truncated 20-char prefix
			partial = true
		}
	}
	if !full {
		t.Errorf("expected the full 21-char AWS key captured, got %+v", creds)
	}
	if partial {
		t.Errorf("expected NO truncated 20-char AWS partial, got %+v", creds)
	}
}

func TestExtractHFToken(t *testing.T) {
	// A bare hf-token found in a file is captured (the operator can see it), but with no
	// discovered HF/TGI endpoint it has nowhere to be replayed — so it drives NO chain action.
	fileOnly := []report.Finding{{
		ID:       "f-4",
		Target:   "http://10.0.0.2:8080",
		Source:   report.SourceFileDiscovery,
		Evidence: "Found HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz",
		Title:    "HF token",
		Severity: "high",
	}}
	store := ExtractFromFindings(fileOnly)
	if creds := store.ForTarget("10.0.0.2:8080"); len(creds) == 0 || creds[0].Type != "hf-token" {
		t.Fatalf("expected the hf-token to be captured, got %+v", store.All())
	}
	if got := GenerateChainActions(store); len(got) != 0 {
		t.Fatalf("bare hf-token with no discovered HF endpoint should drive no chain action, got %+v", got)
	}

	// With a discovered TGI endpoint in the findings, the looted token is ROUTED there so
	// autochain emits a runnable replay — even though the token was found elsewhere.
	withEndpoint := append(fileOnly, report.Finding{
		ID:       "f-4b",
		Target:   "http://10.0.0.9:8180",
		Source:   report.SourceFileDiscovery,
		Title:    "TGI Unauthenticated - Model acme-tgi-lab",
		Severity: "high",
	})
	actions := GenerateChainActions(ExtractFromFindings(withEndpoint))
	found := false
	for _, a := range actions {
		if strings.Contains(a.Command, "generate") &&
			strings.Contains(a.Command, "10.0.0.9:8180") &&
			strings.Contains(a.Command, "hf_abcdefghijklmnopqrstuvwxyz") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a generate replay routed to the discovered TGI endpoint, got %+v", actions)
	}
}

func TestExtractAnthropicKey(t *testing.T) {
	findings := []report.Finding{{
		ID:       "f-5",
		Target:   "http://10.0.0.3:9090",
		Source:   report.SourceFileDiscovery,
		Evidence: "ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz123",
		Title:    "Anthropic key",
		Severity: "high",
	}}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.3:9090")
	if len(creds) == 0 {
		t.Fatal("expected Anthropic key")
	}
	if creds[0].Type != "anthropic-api-key" {
		t.Fatalf("expected anthropic-api-key, got %s", creds[0].Type)
	}
}

func TestExtractGenericAPIKey(t *testing.T) {
	findings := []report.Finding{{
		ID:       "f-6",
		Target:   "http://10.0.0.4:3000",
		Source:   report.SourceVulnCheck,
		Evidence: `config shows api_key="mysecretapikey12345678"`,
		Title:    "Config leak",
		Severity: "medium",
	}}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.4:3000")
	if len(creds) == 0 {
		t.Fatal("expected generic API key")
	}
	if creds[0].Type != "api-key" {
		t.Fatalf("expected api-key, got %s", creds[0].Type)
	}
}

func TestNoDuplicateCredentials(t *testing.T) {
	findings := []report.Finding{
		{
			ID:       "f-7",
			Target:   "http://10.0.0.5:8888?token=sametoken1234567890abc",
			Source:   report.SourceVulnCheck,
			Evidence: "Also token=sametoken1234567890abc in body",
			Title:    "Jupyter",
			Severity: "high",
		},
	}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.5:8888")
	jupyterTokenCount := 0
	for _, c := range creds {
		if c.Type == "jupyter-token" && c.Value == "sametoken1234567890abc" {
			jupyterTokenCount++
		}
	}
	if jupyterTokenCount > 1 {
		t.Fatalf("expected no duplicate jupyter-token, got %d", jupyterTokenCount)
	}
}

func TestNoCredentialsFromEmptyFindings(t *testing.T) {
	store := ExtractFromFindings(nil)
	if store.TotalCredentials() != 0 {
		t.Fatalf("expected 0 credentials, got %d", store.TotalCredentials())
	}
}

func TestSummary(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.5:8888", Credential{Type: "jupyter-token", Value: "tok123", Source: "f-1"})
	summary := store.Summary()
	if summary == "" {
		t.Fatal("expected non-empty summary")
	}
}

func TestForTargetNormalization(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.5:8888", Credential{Type: "token", Value: "v", Source: "f-1"})
	creds := store.ForTarget("  10.0.0.5:8888  ")
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential after normalization, got %d", len(creds))
	}
}

func TestMultipleTargets(t *testing.T) {
	findings := []report.Finding{
		{ID: "f-1", Target: "http://10.0.0.5:8888?token=jupytertoken12345678", Source: report.SourceVulnCheck, Title: "a", Severity: "high"},
		{ID: "f-2", Target: "http://10.0.0.6:4000", Source: report.SourceFileDiscovery, Evidence: "sk-abcdefghijklmnopqrstuv12345", Title: "b", Severity: "high"},
	}
	store := ExtractFromFindings(findings)
	if store.TotalTargets() != 2 {
		t.Fatalf("expected 2 targets, got %d", store.TotalTargets())
	}
}

func TestGenerateChainActions_JupyterToken(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.5:8888", Credential{Type: "jupyter-token", Value: "mytoken123", Source: "f-1"})
	actions := GenerateChainActions(store)
	if len(actions) < 2 {
		t.Fatalf("expected at least 2 actions for jupyter-token, got %d", len(actions))
	}
	foundEnum := false
	for _, a := range actions {
		if a.CredentialType == "jupyter-token" && strings.Contains(a.Command, "enum") {
			foundEnum = true
		}
	}
	if !foundEnum {
		t.Error("expected jupyter enum action")
	}
}

func TestGenerateChainActions_OpenAIKey(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.6:4000", Credential{Type: "openai-api-key", Value: "sk-test123", Source: "f-2"})
	actions := GenerateChainActions(store)
	if len(actions) < 2 {
		t.Fatalf("expected at least 2 actions for openai-api-key, got %d", len(actions))
	}
	foundAuthSweep := false
	for _, a := range actions {
		if strings.Contains(a.Command, "auth-sweep") {
			foundAuthSweep = true
		}
	}
	if !foundAuthSweep {
		t.Error("expected auth-sweep action for OpenAI key")
	}
}

func TestGenerateChainActions_MLflowAuthSuppressesUnauth(t *testing.T) {
	store := NewStore()
	// Same gated gateway has both the URL disclosure and the looted Basic-auth cred.
	store.Add("10.0.0.7:5000", Credential{Type: "mlflow-url", Value: "http://10.0.0.7:5000", Source: "f-ray"})
	store.Add("10.0.0.7:5000", Credential{Type: "mlflow-basic-auth", Value: "cmF5OnB3", Source: "f-ray"})
	actions := GenerateChainActions(store)

	var sawAuthed, sawUnauth bool
	for _, a := range actions {
		switch a.CredentialType {
		case "mlflow-basic-auth":
			sawAuthed = true
		case "mlflow-url":
			sawUnauth = true
		}
	}
	if !sawAuthed {
		t.Fatalf("expected authenticated mlflow action, got %#v", actions)
	}
	if sawUnauth {
		t.Fatalf("unauth mlflow-url actions must be suppressed when Basic-auth exists for the same target; got %#v", actions)
	}
}

func TestGenerateChainActions_MLflowUrlOnlyKeepsUnauth(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.7:5000", Credential{Type: "mlflow-url", Value: "http://10.0.0.7:5000", Source: "f-ray"})
	actions := GenerateChainActions(store)
	sawUnauth := false
	for _, a := range actions {
		if a.CredentialType == "mlflow-url" {
			sawUnauth = true
		}
	}
	if !sawUnauth {
		t.Fatalf("open MLflow with no auth cred should still emit unauth enum actions, got %#v", actions)
	}
}

func TestGenerateChainActions_Empty(t *testing.T) {
	store := NewStore()
	actions := GenerateChainActions(store)
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions for empty store, got %d", len(actions))
	}
}

func TestGenerateChainActions_Nil(t *testing.T) {
	actions := GenerateChainActions(nil)
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions for nil store, got %d", len(actions))
	}
}

func TestExtractMLflowRunID(t *testing.T) {
	findings := []report.Finding{{
		ID:       "mlf-1",
		Target:   "http://10.0.0.7:5000",
		Source:   report.SourceMLflow,
		Title:    "MLflow run discovered: abc",
		Severity: "info",
		Metadata: map[string]interface{}{
			"run_id": "run-secret-1",
		},
	}}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.7:5000")
	var found bool
	for _, c := range creds {
		if c.Type == "mlflow-run-id" && c.Value == "run-secret-1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected mlflow-run-id credential, got %+v", creds)
	}
}

func TestGenerateChainActions_AnthropicKey(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.8:3000", Credential{Type: "anthropic-api-key", Value: "sk-ant-xyz", Source: "f-3"})
	actions := GenerateChainActions(store)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action for anthropic-api-key, got %d: %+v", len(actions), actions)
	}
	if !strings.Contains(actions[0].Command, "auth-sweep") {
		t.Fatalf("expected auth-sweep in command, got %q", actions[0].Command)
	}
}

func TestGenerateChainActions_HFToken(t *testing.T) {
	// A bare hf-token has no target of its own — with no discovered HF endpoint it yields
	// no action (viewer-only), not a guess.
	store := NewStore()
	store.Add("10.0.0.9:5000", Credential{Type: "hf-token", Value: "hf_abc123", Source: "f-4"})
	if got := GenerateChainActions(store); len(got) != 0 {
		t.Fatalf("hf-token with no discovered HF endpoint should yield no action, got %+v", got)
	}
	// Once an HF/TGI endpoint is discovered, the token is routed there for enum + real replay
	// (the credential-chain climax) — targeting the ENDPOINT, not where the token was found.
	store.AddHFInferenceTarget("10.0.0.40:8180")
	actions := GenerateChainActions(store)
	if len(actions) != 2 {
		t.Fatalf("expected 2 hf-token actions once an HF endpoint is discovered, got %d: %+v", len(actions), actions)
	}
	gen := 0
	for _, a := range actions {
		if !strings.Contains(a.Command, "Bearer hf_abc123") {
			t.Fatalf("expected the looted token in the command, got %q", a.Command)
		}
		if !strings.Contains(a.Command, "10.0.0.40:8180") {
			t.Fatalf("expected the command to target the discovered HF endpoint, got %q", a.Command)
		}
		if strings.Contains(a.Command, "generate") {
			gen++
		}
	}
	if gen != 1 {
		t.Fatalf("expected exactly one generate replay among the actions, got %d", gen)
	}
}

func TestGenerateChainActions_HFTokenKindAware(t *testing.T) {
	tok := Credential{Type: "hf-token", Value: "hf_kind", Source: "f-1"}

	// A TGI (generation) endpoint yields a `generate` replay.
	tgi := NewStore()
	tgi.Add("10.0.0.9:5000", tok)
	tgi.AddHFInferenceTargetKind("10.0.0.40:8180", "tgi")
	assertHFReplayVerb(t, GenerateChainActions(tgi), "10.0.0.40:8180", "generate", "embed")

	// A TEI (embeddings-only) endpoint yields an `embed` replay — NOT `generate`, which 404s there.
	tei := NewStore()
	tei.Add("10.0.0.9:5000", tok)
	tei.AddHFInferenceTargetKind("10.0.0.20:8181", "tei")
	assertHFReplayVerb(t, GenerateChainActions(tei), "10.0.0.20:8181", "embed", "generate")

	// An endpoint that fingerprints as BOTH tgi and tei (real TGI gateways do) is treated as
	// TGI: it can generate, in either arrival order.
	amb := NewStore()
	amb.Add("10.0.0.9:5000", tok)
	amb.AddHFInferenceTargetKind("10.0.0.40:8180", "tei")
	amb.AddHFInferenceTargetKind("10.0.0.40:8180", "tgi")
	assertHFReplayVerb(t, GenerateChainActions(amb), "10.0.0.40:8180", "generate", "embed")
}

func assertHFReplayVerb(t *testing.T, actions []ChainAction, target, wantVerb, notVerb string) {
	t.Helper()
	var replay string
	for _, a := range actions {
		if strings.Contains(a.Command, target) && !strings.Contains(a.Command, " enum") {
			replay = a.Command
			break
		}
	}
	if replay == "" {
		t.Fatalf("no non-enum replay action targeting %s; got %+v", target, actions)
	}
	if !strings.Contains(replay, " "+wantVerb+" ") {
		t.Fatalf("expected %s replay to use %q, got %q", target, wantVerb, replay)
	}
	if strings.Contains(replay, " "+notVerb+" ") {
		t.Fatalf("expected %s replay NOT to use %q, got %q", target, notVerb, replay)
	}
}

func TestGenerateChainActions_BearerToken(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.10:5000", Credential{Type: "bearer-token", Value: "tok123", Source: "f-5"})
	actions := GenerateChainActions(store)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action for bearer-token, got %d: %+v", len(actions), actions)
	}
	if !strings.Contains(actions[0].Command, "auth-sweep") {
		t.Fatalf("expected auth-sweep in command, got %q", actions[0].Command)
	}
	if actions[0].CredentialType != "bearer-token" {
		t.Fatalf("expected credential type bearer-token, got %q", actions[0].CredentialType)
	}
}

func TestGenerateChainActions_GenericAPIKey(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.11:4000", Credential{Type: "api-key", Value: "generic-key", Source: "f-6"})
	actions := GenerateChainActions(store)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action for api-key, got %d: %+v", len(actions), actions)
	}
	if !strings.Contains(actions[0].Command, "auth-sweep") {
		t.Fatalf("expected auth-sweep in command, got %q", actions[0].Command)
	}
}

func TestGenerateChainActions_UnknownType(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.12:9090", Credential{Type: "unknown-cred", Value: "val", Source: "f-7"})
	actions := GenerateChainActions(store)
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions for unknown credential type, got %d: %+v", len(actions), actions)
	}
}

func TestExtractBearerToken(t *testing.T) {
	findings := []report.Finding{{
		ID:       "f-bearer",
		Target:   "http://10.0.0.1:8080",
		Source:   report.SourceVulnCheck,
		Evidence: "Authorization: Bearer mysecrettokenvalue1234567890",
		Title:    "Auth header found",
		Severity: "high",
	}}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.1:8080")
	var found bool
	for _, c := range creds {
		if c.Type == "bearer-token" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected bearer-token credential, got %+v", creds)
	}
}

func TestExtractBearerTokenSkipsKnownFormats(t *testing.T) {
	findings := []report.Finding{{
		ID:       "f-bearer-skip",
		Target:   "http://10.0.0.1:8080",
		Source:   report.SourceVulnCheck,
		Evidence: "Authorization: Bearer sk-abcdefghijklmnopqrstuvwx",
		Title:    "OpenAI key as bearer",
		Severity: "high",
	}}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.1:8080")
	for _, c := range creds {
		if c.Type == "bearer-token" {
			t.Fatalf("bearer-token should be skipped for OpenAI key format, got %+v", c)
		}
	}
}

func TestAddDuplicateCredential(t *testing.T) {
	store := NewStore()
	store.Add("host:8080", Credential{Type: "token", Value: "v1", Source: "f-1"})
	store.Add("host:8080", Credential{Type: "token", Value: "v1", Source: "f-2"})
	creds := store.ForTarget("host:8080")
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential (deduped), got %d", len(creds))
	}
}

func TestAddDifferentValuesSameType(t *testing.T) {
	store := NewStore()
	store.Add("host:8080", Credential{Type: "token", Value: "v1", Source: "f-1"})
	store.Add("host:8080", Credential{Type: "token", Value: "v2", Source: "f-2"})
	creds := store.ForTarget("host:8080")
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials (different values), got %d", len(creds))
	}
}

func TestTargetToHostPort(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"empty", "", ""},
		{"valid url", "http://10.0.0.1:8080/path", "10.0.0.1:8080"},
		{"no port", "http://example.com/path", "example.com"},
		{"bare host", "not-a-url", "not-a-url"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := targetToHostPort(tc.target)
			if got != tc.want {
				t.Errorf("targetToHostPort(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}
}

func TestExtractFromFindingWithMetadataStrings(t *testing.T) {
	findings := []report.Finding{{
		ID:       "f-meta",
		Target:   "http://10.0.0.1:3000",
		Source:   report.SourceVulnCheck,
		Title:    "Config leak",
		Severity: "medium",
		Evidence: "some text",
		Metadata: map[string]interface{}{
			"env_value": "sk-abcdefghijklmnopqrstuvwx",
		},
	}}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.1:3000")
	var found bool
	for _, c := range creds {
		if c.Type == "openai-api-key" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected openai-api-key from metadata string, got %+v", creds)
	}
}

func TestAllReturnsDefensiveCopy(t *testing.T) {
	store := NewStore()
	store.Add("host:1", Credential{Type: "t", Value: "v", Source: "f"})
	all := store.All()
	all["host:1"] = nil
	if store.TotalCredentials() != 1 {
		t.Fatal("modifying All() result should not affect store")
	}
}

func TestSummaryEmpty(t *testing.T) {
	store := NewStore()
	if store.Summary() != "" {
		t.Fatal("expected empty summary for empty store")
	}
}

func TestEnsureScheme(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"10.0.0.1:8080", "http://10.0.0.1:8080"},
		{"http://10.0.0.1:8080", "http://10.0.0.1:8080"},
		{"https://example.com", "https://example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ensureScheme(tc.input)
			if got != tc.want {
				t.Errorf("ensureScheme(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestGenerateChainActions_MLflowRunID(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.7:5000", Credential{Type: "mlflow-run-id", Value: "run-xyz", Source: "mlf-1"})
	actions := GenerateChainActions(store)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d: %+v", len(actions), actions)
	}
	if !strings.Contains(actions[0].Command, "artifacts --run-id run-xyz") {
		t.Fatalf("expected artifacts command with run id, got %q", actions[0].Command)
	}
}

func TestExtractWandbKey(t *testing.T) {
	findings := []report.Finding{
		{
			ID:       "wb-1",
			Target:   "http://10.0.0.8:8080",
			Evidence: `wandb_api_key="abcdefghijklmnopqrstuvwxyz123456"`,
		},
	}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.8:8080")
	found := false
	for _, c := range creds {
		if c.Type == "wandb-api-key" && c.Value == "abcdefghijklmnopqrstuvwxyz123456" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected wandb-api-key credential, got %+v", creds)
	}
}

func TestExtractLiteLLMMasterKey(t *testing.T) {
	findings := []report.Finding{
		{
			ID:       "ll-1",
			Target:   "http://10.0.0.9:4000",
			Evidence: `litellm_master_key="sk-litellm-1234567890abcdef"`,
		},
	}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.9:4000")
	found := false
	for _, c := range creds {
		if c.Type == "litellm-master-key" && c.Value == "sk-litellm-1234567890abcdef" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected litellm-master-key credential, got %+v", creds)
	}
}

func TestExtractRayToken(t *testing.T) {
	findings := []report.Finding{
		{
			ID:       "ray-1",
			Target:   "http://10.0.0.10:8265",
			Evidence: `ray_dashboard_token="raytok_abcdefghij1234567890"`,
		},
	}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.10:8265")
	found := false
	for _, c := range creds {
		if c.Type == "ray-dashboard-token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ray-dashboard-token credential, got %+v", creds)
	}
}

func TestGenerateChainActions_MLflowBasicAuth(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.7:5000", Credential{Type: "mlflow-basic-auth", Value: "dTpw", Source: "ray-1"})
	actions := GenerateChainActions(store)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions for mlflow-basic-auth, got %d: %+v", len(actions), actions)
	}
	if !strings.Contains(actions[0].Command, `--header "Authorization: Basic dTpw"`) {
		t.Fatalf("expected Basic header in command, got %+v", actions)
	}
}

func TestGenerateChainActions_WandbAPIKey(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.8:8080", Credential{Type: "wandb-api-key", Value: "testkey123", Source: "wb-1"})
	actions := GenerateChainActions(store)
	if len(actions) < 2 {
		t.Fatalf("expected at least 2 wandb actions, got %d: %+v", len(actions), actions)
	}
	var hasEnum, hasSecrets bool
	for _, a := range actions {
		if strings.Contains(a.Command, "wandb") && strings.Contains(a.Command, "enum") {
			hasEnum = true
		}
		if strings.Contains(a.Command, "wandb") && strings.Contains(a.Command, "secrets") {
			hasSecrets = true
			if !strings.Contains(a.Command, "--entity <entity>") || !strings.Contains(a.Command, "--project <project>") {
				t.Fatalf("expected W&B secrets action placeholders, got %q", a.Command)
			}
		}
	}
	if !hasEnum || !hasSecrets {
		t.Fatalf("expected wandb enum and secrets actions, got %+v", actions)
	}
}

func TestGenerateChainActions_LiteLLMMasterKey(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.9:4000", Credential{Type: "litellm-master-key", Value: "sk-master-abc123", Source: "ll-1"})
	actions := GenerateChainActions(store)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d: %+v", len(actions), actions)
	}
	var hasRelay, hasEnum bool
	for _, a := range actions {
		if strings.Contains(a.Command, "proxy-chain --relay-test") {
			hasRelay = true
		}
		if strings.Contains(a.Command, " enum") {
			hasEnum = true
		}
	}
	if !hasRelay {
		t.Fatalf("expected the real relay-test payoff action, got %+v", actions)
	}
	if !hasEnum {
		t.Fatalf("expected the enum action, got %+v", actions)
	}
}

func TestGenerateChainActions_RayDashboardToken(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.10:8265", Credential{Type: "ray-dashboard-token", Value: "raytok123", Source: "ray-1"})
	actions := GenerateChainActions(store)
	if len(actions) < 2 {
		t.Fatalf("expected at least 2 ray actions, got %d: %+v", len(actions), actions)
	}
	var hasEnum, hasJobs bool
	for _, a := range actions {
		if strings.Contains(a.Command, "ray") && strings.Contains(a.Command, "enum") {
			hasEnum = true
		}
		if strings.Contains(a.Command, "ray") && strings.Contains(a.Command, "jobs") {
			hasJobs = true
		}
	}
	if !hasEnum || !hasJobs {
		t.Fatalf("expected ray enum and jobs actions, got %+v", actions)
	}
}

func TestRAGVerifyChainSuggestion(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.1:8000", Credential{Type: "api-key", Value: "chromadb-key", Source: "vdb-1"})
	store.Add("10.0.0.2:4000", Credential{Type: "openai-api-key", Value: "sk-testkey12345678901234567890", Source: "llm-1"})
	actions := GenerateChainActions(store)
	var ragAction *ChainAction
	for i, a := range actions {
		if a.CredentialType == "rag-verify-chain" {
			ragAction = &actions[i]
			break
		}
	}
	if ragAction == nil {
		t.Fatalf("expected rag-verify-chain action, got %+v", actions)
	}
	if !strings.Contains(ragAction.Command, "rag-verify") {
		t.Fatalf("expected rag-verify in command, got %q", ragAction.Command)
	}
	if !strings.Contains(ragAction.Command, "--llm-target") {
		t.Fatalf("expected --llm-target in command, got %q", ragAction.Command)
	}
	if !strings.Contains(ragAction.Command, "--collection <collection>") {
		t.Fatalf("expected collection placeholder in command, got %q", ragAction.Command)
	}
}

func TestExtractWandbSourceHintNumericSecretCount(t *testing.T) {
	findings := []report.Finding{
		{
			ID:     "wb-secrets",
			Source: report.SourceWandB,
			Target: "http://10.0.0.8:8080",
			Metadata: map[string]interface{}{
				"secret_count": 2,
			},
		},
	}
	store := ExtractFromFindings(findings)
	creds := store.ForTarget("10.0.0.8:8080")
	for _, c := range creds {
		if c.Type == "wandb-secrets-found" && c.Value == "2" {
			return
		}
	}
	t.Fatalf("expected numeric wandb-secrets-found credential, got %+v", creds)
}

func TestRAGVerifyChainNotSuggestedWithoutLLMKey(t *testing.T) {
	store := NewStore()
	store.Add("10.0.0.1:8000", Credential{Type: "api-key", Value: "chromadb-key", Source: "vdb-1"})
	actions := GenerateChainActions(store)
	for _, a := range actions {
		if a.CredentialType == "rag-verify-chain" {
			t.Fatalf("should not suggest rag-verify without LLM credentials, got %+v", a)
		}
	}
}
