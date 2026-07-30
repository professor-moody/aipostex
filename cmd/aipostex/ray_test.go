package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/internal/credchain"
	"github.com/professor-moody/aipostex/internal/exitcode"
	exploitray "github.com/professor-moody/aipostex/pkg/exploit/ray"
	"github.com/professor-moody/aipostex/pkg/report"
)

func TestRaySubmitRequiresForceExploitAndValidPreset(t *testing.T) {
	prevTarget := rayTarget
	prevEntrypoint := rayEntrypoint
	prevRuntimeEnv := rayRuntimeEnvJSON
	prevProofPreset := rayPayloadPreset
	defer func() {
		rayTarget = prevTarget
		rayEntrypoint = prevEntrypoint
		rayRuntimeEnvJSON = prevRuntimeEnv
		rayPayloadPreset = prevProofPreset
	}()

	withTestConfig(t, func() {
		rayTarget = "http://127.0.0.1:8265"
		rayEntrypoint = ""
		rayPayloadPreset = "env-marked"
		cfg.ForceExploit = false

		err := runRaySubmit(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected --force-exploit validation error, got %v", err)
		}

		rayPayloadPreset = "invalid"
		cfg.ForceExploit = true
		err = runRaySubmit(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "invalid --payload-preset") {
			t.Fatalf("expected proof preset validation error, got %v", err)
		}
	})
}

func TestRayRuntimeEnvFindingsPreserveStructuredCredentials(t *testing.T) {
	findings := extractRayEnvVarFindings("http://172.16.50.20:8265", "training-job", map[string]interface{}{
		"env_vars": map[string]interface{}{
			"MLFLOW_TRACKING_URI":      "http://localhost:5000",
			"MLFLOW_TRACKING_USERNAME": "ray-pipeline",
			"MLFLOW_TRACKING_PASSWORD": "secret",
			"STRIPE_BILLING_KEY":       "sk_live_fake_billing_key_123456",
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected one env finding, got %d", len(findings))
	}
	finding := findings[0]
	envVars, ok := finding.Metadata["env_vars"].(map[string]string)
	if !ok {
		t.Fatalf("expected structured env_vars metadata, got %#v", finding.Metadata["env_vars"])
	}
	if envVars["MLFLOW_TRACKING_URI"] != "http://localhost:5000" {
		t.Fatalf("expected raw env var preserved, got %#v", envVars)
	}
	records := credchain.ExtractCredentialRecords(findings)
	if len(records) < 2 {
		t.Fatalf("expected structured credential records, got %#v", records)
	}
	var foundMLflow, foundMLflowBasic, foundStripe bool
	for _, rec := range records {
		switch rec.Name {
		case "MLFLOW_TRACKING_URI":
			foundMLflow = rec.Type == "mlflow-url" && rec.Chainable && rec.TargetURL == "http://172.16.50.20:5000"
		case "MLFLOW_BASIC_AUTH":
			foundMLflowBasic = rec.Type == "mlflow-basic-auth" && rec.Chainable && rec.TargetURL == "http://172.16.50.20:5000" && rec.Value == "cmF5LXBpcGVsaW5lOnNlY3JldA=="
		case "STRIPE_BILLING_KEY":
			foundStripe = rec.Type == "secret" && !rec.Chainable
		}
	}
	if !foundMLflow {
		t.Fatalf("expected chainable inferred MLflow target, got %#v", records)
	}
	if !foundMLflowBasic {
		t.Fatalf("expected chainable MLflow Basic credential, got %#v", records)
	}
	if !foundStripe {
		t.Fatalf("expected unsupported Stripe secret to remain viewer-only, got %#v", records)
	}
	actions := credchain.GenerateChainActions(credchain.ExtractFromFindings(findings))
	var mlflowUnauthCommand, mlflowAuthCommand, stripeCommand bool
	for _, action := range actions {
		if strings.Contains(action.Command, "mlflow --target http://172.16.50.20:5000 enum") {
			mlflowUnauthCommand = true
		}
		if strings.Contains(action.Command, `--header "Authorization: Basic cmF5LXBpcGVsaW5lOnNlY3JldA=="`) {
			mlflowAuthCommand = true
		}
		if strings.Contains(strings.ToLower(action.Command), "stripe") {
			stripeCommand = true
		}
	}
	if mlflowUnauthCommand {
		t.Fatalf("unauth MLflow command must be suppressed when Basic Auth is available, got %#v", actions)
	}
	if !mlflowAuthCommand {
		t.Fatalf("expected MLflow Basic Auth follow-on command, got %#v", actions)
	}
	if stripeCommand {
		t.Fatalf("did not expect unsupported Stripe command, got %#v", actions)
	}
}

func TestRayRuntimeEnvModelRegistryURLIsMLflowPivot(t *testing.T) {
	records := rayRuntimeEnvCredentialMetadata("http://172.16.50.20:8265", map[string]string{
		"MODEL_REGISTRY_URL": "http://mlflow.acme.internal:5000",
	})
	if len(records) != 1 {
		t.Fatalf("expected one credential record, got %#v", records)
	}
	rec := records[0].(map[string]interface{})
	if rec["type"] != "mlflow-url" || rec["chainable"] != true {
		t.Fatalf("expected chainable mlflow-url, got %#v", rec)
	}
	if rec["target_url"] != "http://mlflow.acme.internal:5000" {
		t.Fatalf("expected registry URL target, got %#v", rec)
	}
}

// Regression: a real LiteLLM master key starts with "sk-", which must NOT be
// misclassified as an OpenAI key. The name-based match has to win so the looted
// key chains to the LiteLLM gateway (the headline-climax credential chain).
func TestRayRuntimeEnvLiteLLMMasterKeyIsChainableNotOpenAI(t *testing.T) {
	records := rayRuntimeEnvCredentialMetadata("http://172.16.50.20:8265", map[string]string{
		"LITELLM_API_URL":    "http://172.16.50.20:4001",
		"LITELLM_MASTER_KEY": "sk-litellm-lab-auth-key-FAKE123",
	})
	var litellm map[string]interface{}
	for _, r := range records {
		rec := r.(map[string]interface{})
		if rec["type"] == "openai-api-key" {
			t.Fatalf("sk-prefixed LiteLLM master key misclassified as openai-api-key: %#v", rec)
		}
		if rec["type"] == "litellm-master-key" {
			litellm = rec
		}
	}
	if litellm == nil {
		t.Fatalf("expected a litellm-master-key record, got %#v", records)
	}
	if litellm["chainable"] != true {
		t.Fatalf("expected chainable litellm-master-key, got %#v", litellm)
	}
	if litellm["target_url"] != "http://172.16.50.20:4001" {
		t.Fatalf("expected litellm gateway target, got %#v", litellm)
	}
}

func TestRaySubmitUnconfirmedUsesSubmissionAcceptedProof(t *testing.T) {
	// Shared mock 404s job-detail/logs, so execution cannot be confirmed.
	prevWait := raySubmitWait
	raySubmitWait = 100 * time.Millisecond
	defer func() { raySubmitWait = prevWait }()

	findings, stderr := runRayCommandAndCollectFindings(t, func() error {
		rayPayloadPreset = "env-marked"
		return runRaySubmit(nil, nil)
	})

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	// Findings are reordered by dedupeAndSortFindings, so assert on the set of
	// landed values: surface=influenced, job=influenced, no overclaim.
	strengths := map[string]bool{}
	for _, finding := range findings {
		if finding.Severity != report.SeverityHigh {
			t.Fatalf("expected high severity, got %s", finding.Severity)
		}
		if s, ok := finding.Metadata["landed"].(string); ok {
			strengths[s] = true
		}
	}
	if !strengths["influenced"] {
		t.Fatalf("expected an influenced surface finding, got %#v", strengths)
	}
	if !strengths["influenced"] {
		t.Fatalf("expected a influenced job finding, got %#v", strengths)
	}
	if strengths["execution-confirmed"] {
		t.Fatalf("expected no execution-confirmed overclaim, got %#v", strengths)
	}
	if strings.Contains(stderr, "execution-confirmed") || strings.Contains(stderr, "takeover-capable") {
		t.Fatalf("expected no execution/takeover overclaim in stderr, got %q", stderr)
	}
}

func TestRaySubmitConfirmedExecutionUpgradesToCritical(t *testing.T) {
	prevWait := raySubmitWait
	raySubmitWait = 2 * time.Second
	defer func() { raySubmitWait = prevWait }()

	prevTarget := rayTarget
	prevErr := stderrWriter
	prevFactory := rayClientFactory
	prevPreset := rayPayloadPreset
	defer func() {
		rayTarget = prevTarget
		stderrWriter = prevErr
		rayClientFactory = prevFactory
		rayPayloadPreset = prevPreset
	}()

	var findings []report.Finding
	withTestConfig(t, func() {
		rayTarget = "http://127.0.0.1:8265"
		rayPayloadPreset = "env-marked"
		cfg.ForceExploit = true
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "findings.jsonl")
		var stderr strings.Builder
		stderrWriter = &stderr
		rayClientFactory = func() (*exploitray.Client, http.Header, error) {
			client, err := exploitray.NewClient(context.Background(), rayTarget, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.ForceExploit = cfg.ForceExploit
			client.HTTPClient = &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					switch {
					case req.Method == http.MethodPost && req.URL.Path == "/api/jobs/":
						return jsonResponse(http.StatusOK, `{"job_id":"job-rce","status":"PENDING"}`), nil
					case strings.HasSuffix(req.URL.Path, "/logs"):
						return jsonResponse(http.StatusOK, `{"logs":"AIPOSTEX_PROOF=env-marked\n"}`), nil
					default:
						return jsonResponse(http.StatusOK, `{"job_id":"job-rce","status":"SUCCEEDED"}`), nil
					}
				}),
			}
			return client, nil, nil
		}
		err := runRaySubmit(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		data, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatalf("reading findings: %v", readErr)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var f report.Finding
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				t.Fatalf("decoding finding: %v", err)
			}
			findings = append(findings, f)
		}
	})

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	// Locate the executed-job finding regardless of sort order.
	var job *report.Finding
	for i := range findings {
		if findings[i].Metadata["landed"] == "execution-confirmed" {
			job = &findings[i]
		}
	}
	if job == nil {
		t.Fatalf("expected an execution-confirmed job finding, got %#v", findings)
	}
	if job.Severity != report.SeverityCritical {
		t.Fatalf("expected critical severity for executed job, got %s", job.Severity)
	}
	if !strings.Contains(job.Evidence, "AIPOSTEX_PROOF=env-marked") {
		t.Fatalf("expected job stdout in evidence, got %q", job.Evidence)
	}
}

func TestRayRuntimeEnvRequiresForceExploit(t *testing.T) {
	prevTarget := rayTarget
	defer func() { rayTarget = prevTarget }()
	rayTarget = "http://127.0.0.1:8265"

	withTestConfig(t, func() {
		cfg.ForceExploit = false
		err := runRayRuntimeEnv(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected --force-exploit error, got %v", err)
		}
	})
}

func TestRayPipInjectRequiresForceExploit(t *testing.T) {
	prevTarget := rayTarget
	defer func() { rayTarget = prevTarget }()
	rayTarget = "http://127.0.0.1:8265"

	withTestConfig(t, func() {
		cfg.ForceExploit = false
		err := runRayPipInject(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected --force-exploit error, got %v", err)
		}
	})
}

func TestRayClusterInfoRequiresForceExploit(t *testing.T) {
	prevTarget := rayTarget
	defer func() { rayTarget = prevTarget }()
	rayTarget = "http://127.0.0.1:8265"

	withTestConfig(t, func() {
		cfg.ForceExploit = false
		err := runRayClusterInfo(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--force-exploit") {
			t.Fatalf("expected --force-exploit error, got %v", err)
		}
	})
}

func TestRunRayJobsMissingTarget(t *testing.T) {
	prevTarget := rayTarget
	defer func() { rayTarget = prevTarget }()
	rayTarget = ""

	withTestConfig(t, func() {
		err := runRayJobs(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunRayJobLogsMissingJobID(t *testing.T) {
	prevJobID := rayJobID
	defer func() { rayJobID = prevJobID }()
	rayJobID = ""

	err := runRayJobLogs(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--job-id") {
		t.Fatalf("expected --job-id error, got %v", err)
	}
}

func TestRunRayJobArtifactsMissingJobID(t *testing.T) {
	prevJobID := rayJobID
	defer func() { rayJobID = prevJobID }()
	rayJobID = ""

	err := runRayJobArtifacts(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--job-id") {
		t.Fatalf("expected --job-id error, got %v", err)
	}
}

func TestRunRayJobLogsMissingTarget(t *testing.T) {
	prevTarget := rayTarget
	prevJobID := rayJobID
	defer func() {
		rayTarget = prevTarget
		rayJobID = prevJobID
	}()
	rayTarget = ""
	rayJobID = "job-1"

	withTestConfig(t, func() {
		err := runRayJobLogs(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunRayJobArtifactsMissingTarget(t *testing.T) {
	prevTarget := rayTarget
	prevJobID := rayJobID
	defer func() {
		rayTarget = prevTarget
		rayJobID = prevJobID
	}()
	rayTarget = ""
	rayJobID = "job-1"

	withTestConfig(t, func() {
		err := runRayJobArtifacts(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRunRaySubmitMissingTarget(t *testing.T) {
	prevTarget := rayTarget
	defer func() { rayTarget = prevTarget }()
	rayTarget = ""

	withTestConfig(t, func() {
		cfg.ForceExploit = true
		rayPayloadPreset = "env-marked"
		err := runRaySubmit(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestRayEnumMissingTarget(t *testing.T) {
	prevTarget := rayTarget
	defer func() { rayTarget = prevTarget }()
	rayTarget = ""

	withTestConfig(t, func() {
		err := runRayEnum(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("expected missing target error, got %v", err)
		}
	})
}

func TestResolveRayEntrypointPresets(t *testing.T) {
	prevEntrypoint := rayEntrypoint
	prevPreset := rayPayloadPreset
	defer func() {
		rayEntrypoint = prevEntrypoint
		rayPayloadPreset = prevPreset
	}()

	presets := []string{"env-disclosure", "env-marked", "fs-survey", "runtime-survey", "beacon", "python-print"}
	for _, preset := range presets {
		t.Run(preset, func(t *testing.T) {
			rayEntrypoint = ""
			rayPayloadPreset = preset
			ep, err := resolveRayEntrypoint()
			if err != nil {
				t.Fatalf("unexpected error for preset %q: %v", preset, err)
			}
			if ep == "" {
				t.Fatalf("empty entrypoint for preset %q", preset)
			}
			if !strings.Contains(ep, "python3") {
				t.Fatalf("expected preset %q to use python3 for lab portability, got %q", preset, ep)
			}
		})
	}

	t.Run("invalid-preset", func(t *testing.T) {
		rayEntrypoint = ""
		rayPayloadPreset = "invalid"
		_, err := resolveRayEntrypoint()
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("expected invalid preset error, got %v", err)
		}
	})

	t.Run("custom-entrypoint", func(t *testing.T) {
		rayEntrypoint = "echo hello"
		rayPayloadPreset = "env-disclosure"
		ep, err := resolveRayEntrypoint()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ep != "echo hello" {
			t.Fatalf("expected custom entrypoint, got %q", ep)
		}
	})
}

func TestRayPythonEntrypointEncodesMultilinePayload(t *testing.T) {
	entrypoint := rayPythonEntrypoint("print('one')\nprint('two')")
	if !strings.Contains(entrypoint, "base64.b64decode") {
		t.Fatalf("expected base64 decode wrapper, got %q", entrypoint)
	}
	if strings.Contains(entrypoint, `\nprint`) {
		t.Fatalf("entrypoint must not pass escaped newlines directly to python -c: %q", entrypoint)
	}
}

func TestRayRuntimeEnvAcceptedFindingUsesInfluencedProof(t *testing.T) {
	findings, _ := runRayCommandAndCollectFindings(t, func() error {
		return runRayRuntimeEnv(nil, nil)
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != report.SeverityHigh {
		t.Fatalf("expected high severity, got %s", findings[0].Severity)
	}
	if findings[0].Metadata["landed"] != "influenced" {
		t.Fatalf("expected landed influenced, got %#v", findings[0].Metadata["landed"])
	}
}

func TestRayPipInjectAcceptedFindingUsesInfluencedProof(t *testing.T) {
	findings, _ := runRayCommandAndCollectFindings(t, func() error {
		return runRayPipInject(nil, nil)
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != report.SeverityHigh {
		t.Fatalf("expected high severity, got %s", findings[0].Severity)
	}
	if findings[0].Metadata["landed"] != "influenced" {
		t.Fatalf("expected landed influenced, got %#v", findings[0].Metadata["landed"])
	}
}

func TestRayClusterInfoUnconfirmedUsesSubmissionAcceptedProof(t *testing.T) {
	// Shared mock 404s job-detail/logs, so execution cannot be confirmed.
	prevWait := rayClusterInfoWait
	rayClusterInfoWait = 100 * time.Millisecond
	defer func() { rayClusterInfoWait = prevWait }()

	findings, _ := runRayCommandAndCollectFindings(t, func() error {
		return runRayClusterInfo(nil, nil)
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != report.SeverityHigh {
		t.Fatalf("expected high severity, got %s", findings[0].Severity)
	}
	if findings[0].Metadata["landed"] != "influenced" {
		t.Fatalf("expected landed influenced, got %#v", findings[0].Metadata["landed"])
	}
	if findings[0].Metadata["executed"] != false {
		t.Fatalf("expected executed=false, got %#v", findings[0].Metadata["executed"])
	}
}

func TestRayClusterInfoConfirmedExecutionUpgradesToCritical(t *testing.T) {
	prevWait := rayClusterInfoWait
	rayClusterInfoWait = 2 * time.Second
	defer func() { rayClusterInfoWait = prevWait }()

	prevTarget := rayTarget
	prevErr := stderrWriter
	prevFactory := rayClientFactory
	defer func() {
		rayTarget = prevTarget
		stderrWriter = prevErr
		rayClientFactory = prevFactory
	}()

	var findings []report.Finding
	withTestConfig(t, func() {
		rayTarget = "http://127.0.0.1:8265"
		cfg.ForceExploit = true
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "findings.jsonl")
		var stderr strings.Builder
		stderrWriter = &stderr
		rayClientFactory = func() (*exploitray.Client, http.Header, error) {
			client, err := exploitray.NewClient(context.Background(), rayTarget, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.ForceExploit = cfg.ForceExploit
			client.HTTPClient = &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					switch {
					case req.Method == http.MethodPost && req.URL.Path == "/api/jobs/":
						return jsonResponse(http.StatusOK, `{"job_id":"job-rce","status":"PENDING"}`), nil
					case strings.HasSuffix(req.URL.Path, "/logs"):
						return jsonResponse(http.StatusOK, "AIPOSTEX_CLUSTER_INFO\n{\"hostname\":\"ailab-ml\",\"user\":\"mluser\",\"platform\":\"Linux-6.1.0\",\"node_count\":2,\"cpu_total\":8.0,\"gpu_total\":1.0}\n"), nil
					default:
						return jsonResponse(http.StatusOK, `{"job_id":"job-rce","status":"SUCCEEDED"}`), nil
					}
				}),
			}
			return client, nil, nil
		}
		err := runRayClusterInfo(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		data, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatalf("reading findings: %v", readErr)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var f report.Finding
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				t.Fatalf("decoding finding: %v", err)
			}
			findings = append(findings, f)
		}
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != report.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", findings[0].Severity)
	}
	if findings[0].Metadata["landed"] != "execution-confirmed" {
		t.Fatalf("expected landed execution-confirmed, got %#v", findings[0].Metadata["landed"])
	}
	if findings[0].Metadata["executed"] != true {
		t.Fatalf("expected executed=true, got %#v", findings[0].Metadata["executed"])
	}
}

func TestRayBeaconAcceptedOnlyStaysInfluenced(t *testing.T) {
	prevObserve := rayBeaconObserveWait
	prevOOB := oobConfirmWait
	rayBeaconObserveWait = 20 * time.Millisecond
	oobConfirmWait = time.Millisecond
	defer func() {
		rayBeaconObserveWait = prevObserve
		oobConfirmWait = prevOOB
	}()

	findings, stderr := runRayCommandAndCollectFindings(t, func() error {
		cfg.CallbackURL = fmt.Sprintf("http://127.0.0.1:%d/ray-beacon", oobFreePort(t))
		return runRayBeacon(nil, nil)
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != report.SeverityHigh {
		t.Fatalf("expected high severity for accepted-only beacon, got %s", f.Severity)
	}
	if f.Metadata["stage"] != "impact" || f.Metadata["landed"] != "influenced" {
		t.Fatalf("expected impact/influenced for accepted-only beacon, got stage=%#v landed=%#v", f.Metadata["stage"], f.Metadata["landed"])
	}
	if f.Metadata["callback_confirmed"] != false || f.Metadata["confirmed"] != false {
		t.Fatalf("expected no callback/confirmed flags, got %#v", f.Metadata)
	}
	if strings.Contains(stderr, "takeover-capable") {
		t.Fatalf("accepted-only beacon should not overclaim takeover, got stderr %q", stderr)
	}
}

func TestRayBeaconRunningJobConfirmsExecution(t *testing.T) {
	prevObserve := rayBeaconObserveWait
	prevOOB := oobConfirmWait
	prevTarget := rayTarget
	prevErr := stderrWriter
	prevFactory := rayClientFactory
	defer func() {
		rayBeaconObserveWait = prevObserve
		oobConfirmWait = prevOOB
		rayTarget = prevTarget
		stderrWriter = prevErr
		rayClientFactory = prevFactory
	}()
	rayBeaconObserveWait = 20 * time.Millisecond
	oobConfirmWait = time.Millisecond

	var findings []report.Finding
	withTestConfig(t, func() {
		rayTarget = "http://127.0.0.1:8265"
		cfg.ForceExploit = true
		cfg.CallbackURL = fmt.Sprintf("http://127.0.0.1:%d/ray-beacon", oobFreePort(t))
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "findings.jsonl")
		var stderr strings.Builder
		stderrWriter = &stderr
		rayClientFactory = func() (*exploitray.Client, http.Header, error) {
			client, err := exploitray.NewClient(context.Background(), rayTarget, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.ForceExploit = cfg.ForceExploit
			client.HTTPClient = &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					switch {
					case req.Method == http.MethodPost && req.URL.Path == "/api/jobs/":
						return jsonResponse(http.StatusOK, `{"job_id":"beacon-job","status":"PENDING"}`), nil
					case req.URL.Path == "/api/jobs/beacon-job":
						return jsonResponse(http.StatusOK, `{"job_id":"beacon-job","status":"RUNNING"}`), nil
					case req.URL.Path == "/api/jobs/beacon-job/logs":
						return jsonResponse(http.StatusOK, `{"logs":""}`), nil
					default:
						return jsonResponse(http.StatusNotFound, `{}`), nil
					}
				}),
			}
			return client, nil, nil
		}
		err := runRayBeacon(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		findings = readFindingsJSONL(t, cfg.OutputFile)
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != report.SeverityCritical {
		t.Fatalf("expected critical severity for running beacon, got %s", f.Severity)
	}
	if f.Metadata["stage"] != "own" || f.Metadata["landed"] != "execution-confirmed" {
		t.Fatalf("expected own/execution-confirmed for running beacon, got stage=%#v landed=%#v", f.Metadata["stage"], f.Metadata["landed"])
	}
	if f.Metadata["beacon_signal"] != "job-running" || f.Metadata["confirmed"] != true {
		t.Fatalf("expected job-running confirmation, got %#v", f.Metadata)
	}
}

func TestRayBeaconCallbackConfirmsExecution(t *testing.T) {
	prevObserve := rayBeaconObserveWait
	prevOOB := oobConfirmWait
	prevTarget := rayTarget
	prevErr := stderrWriter
	prevFactory := rayClientFactory
	defer func() {
		rayBeaconObserveWait = prevObserve
		oobConfirmWait = prevOOB
		rayTarget = prevTarget
		stderrWriter = prevErr
		rayClientFactory = prevFactory
	}()
	rayBeaconObserveWait = 20 * time.Millisecond
	oobConfirmWait = 2 * time.Second

	var findings []report.Finding
	withTestConfig(t, func() {
		rayTarget = "http://127.0.0.1:8265"
		cfg.ForceExploit = true
		cfg.CallbackURL = fmt.Sprintf("http://127.0.0.1:%d/ray-beacon", oobFreePort(t))
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "findings.jsonl")
		var stderr strings.Builder
		stderrWriter = &stderr
		rayClientFactory = func() (*exploitray.Client, http.Header, error) {
			client, err := exploitray.NewClient(context.Background(), rayTarget, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.ForceExploit = cfg.ForceExploit
			client.HTTPClient = &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method == http.MethodPost && req.URL.Path == "/api/jobs/" {
						var body map[string]interface{}
						_ = json.NewDecoder(req.Body).Decode(&body)
						if runtimeEnv, ok := body["runtime_env"].(map[string]interface{}); ok {
							if env, ok := runtimeEnv["env_vars"].(map[string]interface{}); ok {
								if callbackURL, ok := env["CALLBACK_URL"].(string); ok {
									go func() {
										resp, _ := http.Post(callbackURL, "application/json", strings.NewReader(`{"proof":"beacon"}`)) //nolint:noctx
										if resp != nil {
											_ = resp.Body.Close()
										}
									}()
								}
							}
						}
						return jsonResponse(http.StatusOK, `{"job_id":"beacon-job","status":"PENDING"}`), nil
					}
					return jsonResponse(http.StatusOK, `{"job_id":"beacon-job","status":"RUNNING"}`), nil
				}),
			}
			return client, nil, nil
		}
		err := runRayBeacon(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		findings = readFindingsJSONL(t, cfg.OutputFile)
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Metadata["stage"] != "own" || f.Metadata["landed"] != "execution-confirmed" {
		t.Fatalf("expected own/execution-confirmed for callback-confirmed beacon, got stage=%#v landed=%#v", f.Metadata["stage"], f.Metadata["landed"])
	}
	if f.Metadata["beacon_signal"] != "callback-confirmed" || f.Metadata["callback_confirmed"] != true {
		t.Fatalf("expected callback-confirmed metadata, got %#v", f.Metadata)
	}
	if !strings.Contains(f.Evidence, "callback_remote_addr") {
		t.Fatalf("expected callback evidence, got %q", f.Evidence)
	}
}

func TestRunRayEnumAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ray_version": "2.10.0", "python_version": "3.11.5",
			"session_name": "test-session", "cluster_id": "cluster-abc",
		})
	})
	mux.HandleFunc("/api/jobs/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/jobs/" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"job_id": "job-1", "status": "SUCCEEDED", "entrypoint": "python train.py"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := rayTarget
	prevFactory := rayClientFactory
	defer func() {
		rayTarget = prevTarget
		rayClientFactory = prevFactory
	}()

	withTestConfig(t, func() {
		rayTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ray-enum.json")

		rayClientFactory = func() (*exploitray.Client, http.Header, error) {
			client, err := exploitray.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runRayEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "2.10.0") {
			t.Fatalf("expected ray version in output, got %s", out)
		}
		if !strings.Contains(out, "jobs") || !strings.Contains(out, "reachable") {
			t.Fatalf("expected jobs API reachable finding in output, got %s", out)
		}
	})
}

func TestRunRayJobsAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/jobs/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/jobs/" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"job_id": "job-alpha", "status": "RUNNING", "entrypoint": "python serve.py", "runtime_env": map[string]any{
				"env_vars": map[string]any{"API_KEY": "sk-secret-key-42"},
			}},
			{"job_id": "job-beta", "status": "SUCCEEDED", "entrypoint": "python train.py"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := rayTarget
	prevFactory := rayClientFactory
	defer func() {
		rayTarget = prevTarget
		rayClientFactory = prevFactory
	}()

	withTestConfig(t, func() {
		rayTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ray-jobs.json")

		rayClientFactory = func() (*exploitray.Client, http.Header, error) {
			client, err := exploitray.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runRayJobs(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "job-alpha") || !strings.Contains(out, "job-beta") {
			t.Fatalf("expected both job IDs in output, got %s", out)
		}
		if !strings.Contains(out, "runtime_env") || !strings.Contains(out, "secrets") {
			t.Fatalf("expected env var finding in output, got %s", out)
		}
	})
}

func TestExtractRayEnvVarFindingsSkipsNonSensitiveProofMarkers(t *testing.T) {
	findings := extractRayEnvVarFindings("http://ray.local:8265", "proof-job", map[string]interface{}{
		"env_vars": map[string]interface{}{
			"AIPOSTEX_PROOF": "ray-submit-surface",
		},
	})
	if len(findings) != 0 {
		t.Fatalf("expected proof marker env vars to be skipped, got %#v", findings)
	}
}

func TestExtractRayEnvVarFindingsKeepsSensitiveRuntimeEnv(t *testing.T) {
	findings := extractRayEnvVarFindings("http://ray.local:8265", "training-job", map[string]interface{}{
		"env_vars": map[string]interface{}{
			"AIPOSTEX_PROOF": "ray-submit-surface",
			"DATABASE_URL":   "postgresql://svc:secret@db.internal:5432/app",
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected one sensitive env finding, got %#v", findings)
	}
	if findings[0].Severity != report.SeverityCritical {
		t.Fatalf("expected critical finding for sensitive env vars, got %s", findings[0].Severity)
	}
	if _, ok := findings[0].Metadata["extracted_credentials"]; !ok {
		t.Fatalf("expected structured credential metadata, got %#v", findings[0].Metadata)
	}
}

func TestRunRayJobLogsAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/jobs/job-42", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"job_id": "job-42", "status": "SUCCEEDED", "entrypoint": "python proof.py",
			"logs": "AIPOSTEX_PROOF=confirmed\nHOSTNAME=ray-worker-1",
		})
	})
	mux.HandleFunc("/api/jobs/job-42/logs", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("AIPOSTEX_PROOF=confirmed\nHOSTNAME=ray-worker-1"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := rayTarget
	prevFactory := rayClientFactory
	prevJobID := rayJobID
	defer func() {
		rayTarget = prevTarget
		rayClientFactory = prevFactory
		rayJobID = prevJobID
	}()

	withTestConfig(t, func() {
		rayTarget = srv.URL
		rayJobID = "job-42"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ray-job-logs.json")

		rayClientFactory = func() (*exploitray.Client, http.Header, error) {
			client, err := exploitray.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runRayJobLogs(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "job-42") {
			t.Fatalf("expected job ID in output, got %s", out)
		}
		if !strings.Contains(out, "job-logs") {
			t.Fatalf("expected job-logs action in output, got %s", out)
		}
	})
}

func TestRunRayJobArtifactsAgainstMockServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/jobs/job-99", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"job_id": "job-99", "status": "SUCCEEDED", "entrypoint": "python train.py",
			"logs": "/tmp/ray/model.pt\n/var/data/dataset.csv",
		})
	})
	mux.HandleFunc("/api/jobs/job-99/logs", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("/tmp/ray/model.pt\n/var/data/dataset.csv"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prevTarget := rayTarget
	prevFactory := rayClientFactory
	prevJobID := rayJobID
	defer func() {
		rayTarget = prevTarget
		rayClientFactory = prevFactory
		rayJobID = prevJobID
	}()

	withTestConfig(t, func() {
		rayTarget = srv.URL
		rayJobID = "job-99"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ray-job-artifacts.json")

		rayClientFactory = func() (*exploitray.Client, http.Header, error) {
			client, err := exploitray.NewClient(context.Background(), srv.URL, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.HTTPClient = srv.Client()
			return client, nil, nil
		}

		err := runRayJobArtifacts(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatal(err)
		}
		out := string(raw)
		if !strings.Contains(out, "job-99") {
			t.Fatalf("expected job ID in output, got %s", out)
		}
		if !strings.Contains(out, "job-artifacts") {
			t.Fatalf("expected job-artifacts action in output, got %s", out)
		}
	})
}

func runRayCommandAndCollectFindings(t *testing.T, run func() error) ([]report.Finding, string) {
	t.Helper()

	prevTarget := rayTarget
	prevEntrypoint := rayEntrypoint
	prevRuntimeEnv := rayRuntimeEnvJSON
	prevProofPreset := rayPayloadPreset
	prevJobID := rayJobID
	prevErr := stderrWriter
	prevFactory := rayClientFactory
	defer func() {
		rayTarget = prevTarget
		rayEntrypoint = prevEntrypoint
		rayRuntimeEnvJSON = prevRuntimeEnv
		rayPayloadPreset = prevProofPreset
		rayJobID = prevJobID
		stderrWriter = prevErr
		rayClientFactory = prevFactory
	}()

	var findings []report.Finding
	var stderrText string
	withTestConfig(t, func() {
		rayTarget = "http://127.0.0.1:8265"
		rayEntrypoint = ""
		rayRuntimeEnvJSON = ""
		rayPayloadPreset = "env-disclosure"
		rayJobID = "job-anchor"
		cfg.ForceExploit = true
		cfg.Format = "jsonl"
		cfg.OutputFile = filepath.Join(t.TempDir(), "findings.jsonl")
		cfg.Verbose = false

		var stderr strings.Builder
		stderrWriter = &stderr
		rayClientFactory = func() (*exploitray.Client, http.Header, error) {
			client, err := exploitray.NewClient(context.Background(), rayTarget, cfg.Timeout, nil)
			if err != nil {
				return nil, nil, err
			}
			client.ForceExploit = cfg.ForceExploit
			client.HTTPClient = &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method == http.MethodPost && req.URL.Path == "/api/jobs/" {
						return jsonResponse(http.StatusOK, `{"job_id":"job-123","status":"PENDING"}`), nil
					}
					return jsonResponse(http.StatusNotFound, `{"error":"not found"}`), nil
				}),
			}
			return client, nil, nil
		}

		err := run()
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}

		data, err := os.ReadFile(cfg.OutputFile)
		if err != nil {
			t.Fatalf("reading findings: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		findings = make([]report.Finding, 0, len(lines))
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var finding report.Finding
			if err := json.Unmarshal([]byte(line), &finding); err != nil {
				t.Fatalf("unmarshal finding: %v", err)
			}
			findings = append(findings, finding)
		}
		stderrText = stderr.String()
	})

	return findings, stderrText
}

func readFindingsJSONL(t *testing.T, path string) []report.Finding {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading findings: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	findings := make([]report.Finding, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var finding report.Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			t.Fatalf("unmarshal finding: %v", err)
		}
		findings = append(findings, finding)
	}
	return findings
}
