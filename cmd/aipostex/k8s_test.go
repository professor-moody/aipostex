package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/pkg/exploit/k8s"
)

// newK8SVulnServer returns a TLS server emulating an anonymous-open (vuln) cluster.
func newK8SVulnServer() *httptest.Server {
	hf := base64.StdEncoding.EncodeToString([]byte("hf_FAKEsbXqProd0000"))
	aws := base64.StdEncoding.EncodeToString([]byte("AKIAFAKE7PROD"))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/pods"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"llama-inference-1","namespace":"ml-prod","labels":{"component":"model-server"}},"spec":{"containers":[{"name":"model-server","image":"busybox:1.36"}]}}]}`))
		case strings.HasSuffix(p, "/deployments"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"llama-inference","namespace":"ml-prod","labels":{"framework":"vllm"}},"spec":{"template":{"spec":{"containers":[{"name":"model-server","image":"busybox:1.36"}]}}}}]}`))
		case strings.HasSuffix(p, "/services"):
			_, _ = w.Write([]byte(`{"items":[]}`))
		case strings.HasSuffix(p, "/configmaps"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"inference-config"},"data":{"MODEL_NAME":"meta-llama/Llama-3.1-8B"}}]}`))
		case strings.HasSuffix(p, "/customresourcedefinitions"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"inferenceservices.serving.kserve.io"},"spec":{"group":"serving.kserve.io","names":{"kind":"InferenceService"},"versions":[{"name":"v1beta1"}]}}]}`))
		case strings.HasSuffix(p, "/inferenceservices"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"llama-8b"},"spec":{"predictor":{"model":{"storageUri":"s3://acme-ml-model-registry-prod/llama/"}}}}]}`))
		case strings.HasSuffix(p, "/secrets"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"model-registry-creds","namespace":"ml-prod"},"type":"Opaque","data":{"HF_TOKEN":"` + hf + `","AWS_ACCESS_KEY_ID":"` + aws + `"}}]}`))
		case strings.HasSuffix(p, "/namespaces"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"ml-prod"}}]}`))
		default:
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	})
	return httptest.NewTLSServer(mux)
}

// newK8SSecureServer returns a TLS server that 401s every request (anon-auth off).
func newK8SSecureServer() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","code":401,"reason":"Unauthorized","message":"Unauthorized"}`))
	}))
}

func resetK8SFlags() func() {
	prevTarget, prevNS, prevPod, prevContainer := k8sTarget, k8sNamespace, k8sPod, k8sContainer
	prevCommand := k8sCommand
	prevAll := k8sAllNamespaces
	prevForce, prevInsecure := cfg.ForceExploit, cfg.Insecure
	return func() {
		k8sTarget, k8sNamespace, k8sPod, k8sContainer = prevTarget, prevNS, prevPod, prevContainer
		k8sCommand = prevCommand
		k8sAllNamespaces = prevAll
		cfg.ForceExploit, cfg.Insecure = prevForce, prevInsecure
	}
}

// newK8SLateralServer is a TLS mock for access-review / sa-loot / --all-namespaces:
// SSRR returns ssrrBody at ssrrStatus, namespaces returns ml-prod + ml-system, and
// each namespace exposes one secret. A pod is listed for auto-selection. The
// configmaps dry-run write-probe (CanCreate) returns 201 when allowed: a request
// WITH an Authorization header (the re-authenticated stolen identity) is gated on
// stolenWrite, an anonymous request (the foothold) on footholdWrite — modeling the
// privilege delta sa-loot measures.
func newK8SLateralServer(ssrrStatus int, ssrrBody string, footholdWrite, stolenWrite bool) *httptest.Server {
	secret := func(ns string) string {
		v := base64.StdEncoding.EncodeToString([]byte("val-" + ns))
		return `{"items":[{"metadata":{"name":"creds-` + ns + `","namespace":"` + ns + `"},"type":"Opaque","data":{"K":"` + v + `"}}]}`
	}
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/selfsubjectrulesreviews"):
			w.WriteHeader(ssrrStatus)
			_, _ = w.Write([]byte(ssrrBody))
		case strings.Contains(p, "/configmaps") && r.Method == http.MethodPost:
			allowed := footholdWrite
			if r.Header.Get("Authorization") != "" {
				allowed = stolenWrite
			}
			if allowed {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"kind":"ConfigMap","metadata":{"name":"x"}}`))
			} else {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"kind":"Status","code":403}`))
			}
		case strings.HasSuffix(p, "/api/v1/namespaces"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"ml-prod"}},{"metadata":{"name":"ml-system"}}]}`))
		case strings.Contains(p, "/namespaces/ml-system/secrets"):
			_, _ = w.Write([]byte(secret("ml-system")))
		case strings.Contains(p, "/secrets"):
			_, _ = w.Write([]byte(secret("ml-prod")))
		case strings.HasSuffix(p, "/pods"):
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"llama-1","namespace":"ml-prod","labels":{"component":"model-server"}},"spec":{"containers":[{"name":"model-server","image":"busybox"}]}}]}`))
		default:
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	}))
}

const ssrrWritable = `{"status":{"resourceRules":[{"verbs":["get","list","create","update","delete"],"apiGroups":[""],"resources":["secrets","pods"]},{"verbs":["create","delete"],"apiGroups":["apps"],"resources":["deployments"]}]}}`
const ssrrReadOnly = `{"status":{"resourceRules":[{"verbs":["get","list","watch"],"apiGroups":[""],"resources":["secrets","pods"]}]}}`

func TestRunK8SEnumAgainstVulnServer(t *testing.T) {
	srv := newK8SVulnServer()
	defer srv.Close()
	defer resetK8SFlags()()

	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		cfg.Insecure = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "k8s-enum.json")

		err := runK8SEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		for _, want := range []string{"llama-inference", "InferenceService", `"action":"enum"`, `"stage"`, "workloads enumerated"} {
			if !strings.Contains(content, want) {
				t.Errorf("enum output missing %q: %s", want, content)
			}
		}
	})
}

func TestRunK8SRBACProbeVulnReportsOpen(t *testing.T) {
	srv := newK8SVulnServer()
	defer srv.Close()
	defer resetK8SFlags()()

	withTestConfig(t, func() {
		k8sTarget = srv.URL
		cfg.Insecure = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "k8s-rbac.json")

		err := runK8SRBACProbe(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, "unauthenticated read access") {
			t.Errorf("expected anonymous-open finding: %s", content)
		}
		if !strings.Contains(content, `"anon_accessible":true`) {
			t.Errorf("expected anon_accessible=true: %s", content)
		}
		// Lock the elevated claim: a regression downgrading severity/proof must fail.
		if !strings.Contains(content, `"severity":"high"`) {
			t.Errorf("expected high severity on anonymous-open: %s", content)
		}
		if !strings.Contains(content, `"landed":"influenced"`) {
			t.Errorf("expected landed influenced on anonymous-open: %s", content)
		}
	})
}

// Honesty: against a 401-enforcing cluster, rbac-probe must report not-weak,
// never claim anonymous access.
func TestRunK8SRBACProbeSecureReportsEnforced(t *testing.T) {
	srv := newK8SSecureServer()
	defer srv.Close()
	defer resetK8SFlags()()

	withTestConfig(t, func() {
		k8sTarget = srv.URL
		cfg.Insecure = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "k8s-rbac-secure.json")

		err := runK8SRBACProbe(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, "access enforced") {
			t.Errorf("expected auth-enforced finding: %s", content)
		}
		if strings.Contains(content, `"anon_accessible":true`) {
			t.Errorf("must not report anon access on a 401 cluster: %s", content)
		}
		if !strings.Contains(content, `"posture":"auth-enforced"`) {
			t.Errorf("expected posture auth-enforced: %s", content)
		}
	})
}

func TestRunK8SSecretReadRequiresForceExploit(t *testing.T) {
	defer resetK8SFlags()()
	withTestConfig(t, func() {
		k8sTarget = "https://127.0.0.1:1"
		cfg.ForceExploit = false
		err := runK8SSecretRead(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "force") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

func TestRunK8SSecretReadExfiltrates(t *testing.T) {
	srv := newK8SVulnServer()
	defer srv.Close()
	defer resetK8SFlags()()

	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "k8s-secret.json")

		err := runK8SSecretRead(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, "model-registry-creds") {
			t.Errorf("expected secret name in output: %s", content)
		}
		if !strings.Contains(content, "hf_FAKEsbXqProd0000") {
			t.Errorf("expected decoded HF token in evidence: %s", content)
		}
		if !strings.Contains(content, `"landed":"read-confirmed"`) {
			t.Errorf("expected read-confirmed landed: %s", content)
		}
		if !strings.Contains(content, `"severity":"critical"`) {
			t.Errorf("expected critical severity: %s", content)
		}
	})
}

func TestRunK8SArtifactReadHarvestsStorageURI(t *testing.T) {
	srv := newK8SVulnServer()
	defer srv.Close()
	defer resetK8SFlags()()

	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "k8s-artifact.json")

		err := runK8SArtifactRead(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, "s3://acme-ml-model-registry-prod") {
			t.Errorf("expected storageUri in output: %s", content)
		}
		if !strings.Contains(content, `"action":"artifact-read"`) {
			t.Errorf("expected artifact-read action: %s", content)
		}
	})
}

func TestRunK8SPodExecRequiresForceExploit(t *testing.T) {
	defer resetK8SFlags()()
	withTestConfig(t, func() {
		k8sTarget = "https://127.0.0.1:1"
		cfg.ForceExploit = false
		err := runK8SPodExec(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "force") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

// pod-exec uses the injectable client factory to supply a fake exec conn,
// proving the RCE finding path without a live cluster.
func TestRunK8SPodExecReportsRCE(t *testing.T) {
	srv := newK8SVulnServer()
	defer srv.Close()
	defer resetK8SFlags()()
	prevFactory := k8sClientFactory
	defer func() { k8sClientFactory = prevFactory }()

	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		k8sPod = "llama-inference-1"
		k8sCommand = []string{"id"}
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "k8s-exec.json")

		k8sClientFactory = func() (*k8s.Client, error) {
			c, err := newK8SClient()
			if err != nil {
				return nil, err
			}
			c.Dial = func(string, http.Header) (k8s.ExecConn, error) {
				return &scriptedExecConn{frames: [][]byte{
					append([]byte{1}, []byte("uid=0(root) gid=0(root)\n")...),
					append([]byte{3}, []byte(`{"metadata":{},"status":"Success"}`)...),
				}}, nil
			}
			return c, nil
		}

		err := runK8SPodExec(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, "uid=0(root)") {
			t.Errorf("expected root exec output in evidence: %s", content)
		}
		if !strings.Contains(content, `"landed":"execution-confirmed"`) {
			t.Errorf("expected exploited landed: %s", content)
		}
		if !strings.Contains(content, "arbitrary pod execution") {
			t.Errorf("expected RCE title: %s", content)
		}
	})
}

// k8sExecFactory returns a client factory whose exec stream replays the given frames.
func k8sExecFactory(t *testing.T, frames ...[]byte) func() (*k8s.Client, error) {
	t.Helper()
	return func() (*k8s.Client, error) {
		c, err := newK8SClient()
		if err != nil {
			return nil, err
		}
		c.Dial = func(string, http.Header) (k8s.ExecConn, error) {
			return &scriptedExecConn{frames: frames}, nil
		}
		return c, nil
	}
}

// Honesty: a stderr-only exec stream (no stdout, no error status) must NOT be
// reported as exploited RCE — only as a reachable, unconfirmed-execution finding.
func TestRunK8SPodExecStderrOnlyNotExploited(t *testing.T) {
	srv := newK8SVulnServer()
	defer srv.Close()
	defer resetK8SFlags()()
	prevFactory := k8sClientFactory
	defer func() { k8sClientFactory = prevFactory }()

	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		k8sPod = "llama-inference-1"
		k8sCommand = []string{"id"}
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "k8s-exec-stderr.json")

		// stderr output + a Success status (exit 0) but NO stdout.
		k8sClientFactory = k8sExecFactory(t,
			append([]byte{2}, []byte("warning: TLS proxy in path\n")...),
			append([]byte{3}, []byte(`{"metadata":{},"status":"Success"}`)...),
		)

		err := runK8SPodExec(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if strings.Contains(content, `"landed":"execution-confirmed"`) {
			t.Errorf("stderr-only stream must NOT be exploited: %s", content)
		}
		if strings.Contains(content, "arbitrary pod execution") {
			t.Errorf("stderr-only stream must NOT claim RCE: %s", content)
		}
		if !strings.Contains(content, `"landed":"reachable"`) {
			t.Errorf("expected reachable landed: %s", content)
		}
		if !strings.Contains(content, "no stdout") {
			t.Errorf("expected 'no stdout' title: %s", content)
		}
	})
}

// A Failure status (non-zero exit) is execution-confirmed, not exploited.
func TestRunK8SPodExecFailureExecutionConfirmed(t *testing.T) {
	srv := newK8SVulnServer()
	defer srv.Close()
	defer resetK8SFlags()()
	prevFactory := k8sClientFactory
	defer func() { k8sClientFactory = prevFactory }()

	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		k8sPod = "llama-inference-1"
		k8sCommand = []string{"false"}
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "k8s-exec-fail.json")

		k8sClientFactory = k8sExecFactory(t,
			append([]byte{3}, []byte(`{"metadata":{},"status":"Failure","reason":"NonZeroExitCode"}`)...),
		)

		err := runK8SPodExec(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, `"landed":"execution-confirmed"`) {
			t.Errorf("expected execution-confirmed on non-zero exit: %s", content)
		}
		if strings.Contains(content, `"landed":"takeover-capable"`) {
			t.Errorf("a failed command must not over-claim takeover: %s", content)
		}
	})
}

func TestRunK8SAccessReviewWritable(t *testing.T) {
	srv := newK8SLateralServer(200, ssrrWritable, false, false)
	defer srv.Close()
	defer resetK8SFlags()()
	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		cfg.Insecure = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ar.json")
		err := runK8SAccessReview(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, `"can_write":true`) {
			t.Errorf("expected can_write=true: %s", content)
		}
		if !strings.Contains(content, `"severity":"high"`) {
			t.Errorf("expected high severity for writable identity: %s", content)
		}
		if !strings.Contains(content, "incl. WRITE") {
			t.Errorf("expected WRITE in title: %s", content)
		}
	})
}

// Honesty: an identity that cannot self-review (403) is reported as such, not as a weakness.
func TestRunK8SAccessReviewForbidden(t *testing.T) {
	srv := newK8SLateralServer(403, `{"kind":"Status","code":403}`, false, false)
	defer srv.Close()
	defer resetK8SFlags()()
	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		cfg.Insecure = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ar403.json")
		err := runK8SAccessReview(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, "could not self-review") {
			t.Errorf("expected denied self-review finding: %s", content)
		}
		if strings.Contains(content, `"severity":"high"`) || strings.Contains(content, `"severity":"critical"`) {
			t.Errorf("denied self-review must not be elevated: %s", content)
		}
	})
}

func TestRunK8SSALootRequiresForceExploit(t *testing.T) {
	defer resetK8SFlags()()
	withTestConfig(t, func() {
		k8sTarget = "https://127.0.0.1:1"
		cfg.ForceExploit = false
		err := runK8SSALoot(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "force") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

// The headline path: steal a token, re-auth, and the stolen identity can WRITE -> escalation.
func TestRunK8SSALootEscalation(t *testing.T) {
	srv := newK8SLateralServer(200, ssrrWritable, false, true)
	defer srv.Close()
	defer resetK8SFlags()()
	prevFactory := k8sClientFactory
	defer func() { k8sClientFactory = prevFactory }()
	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		k8sPod = "llama-1"
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "saloot.json")
		k8sClientFactory = k8sExecFactory(t,
			append([]byte{1}, []byte("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYSJ9.sig\n")...),
			append([]byte{3}, []byte(`{"status":"Success"}`)...),
		)
		err := runK8SSALoot(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, `"escalation":true`) {
			t.Errorf("expected escalation=true: %s", content)
		}
		// Stolen-token-with-write proves takeover capability, not code execution.
		if !strings.Contains(content, `"landed":"takeover-capable"`) {
			t.Errorf("expected takeover-capable: %s", content)
		}
		if !strings.Contains(content, "privilege escalation") {
			t.Errorf("expected escalation title: %s", content)
		}
		if !strings.Contains(content, "eyJhbGci") {
			t.Errorf("raw SA token must be present in evidence (no redaction): %s", content)
		}
	})
}

// Read-only stolen identity -> token stolen, but NO escalation claim.
func TestRunK8SSALootNoEscalation(t *testing.T) {
	srv := newK8SLateralServer(200, ssrrReadOnly, false, false)
	defer srv.Close()
	defer resetK8SFlags()()
	prevFactory := k8sClientFactory
	defer func() { k8sClientFactory = prevFactory }()
	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		k8sPod = "llama-1"
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "saloot-ro.json")
		k8sClientFactory = k8sExecFactory(t,
			append([]byte{1}, []byte("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYSJ9.sig\n")...),
			append([]byte{3}, []byte(`{"status":"Success"}`)...),
		)
		err := runK8SSALoot(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if strings.Contains(content, `"escalation":true`) {
			t.Errorf("read-only SA must not claim escalation: %s", content)
		}
		if strings.Contains(content, `"landed":"execution-confirmed"`) || strings.Contains(content, "privilege escalation") {
			t.Errorf("read-only SA must not be execution-confirmed/escalation: %s", content)
		}
		if !strings.Contains(content, `"token_stolen":true`) {
			t.Errorf("expected token_stolen=true: %s", content)
		}
	})
}

// The false-positive guard: if the FOOTHOLD can also write (anon-open cluster with a
// broad write binding), stealing a write-capable SA grants no NEW capability — must
// NOT claim privilege escalation.
func TestRunK8SSALootFootholdAlsoWritesNoEscalation(t *testing.T) {
	srv := newK8SLateralServer(200, ssrrWritable, true, true) // foothold AND stolen can write
	defer srv.Close()
	defer resetK8SFlags()()
	prevFactory := k8sClientFactory
	defer func() { k8sClientFactory = prevFactory }()
	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		k8sPod = "llama-1"
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "saloot-nogain.json")
		k8sClientFactory = k8sExecFactory(t,
			append([]byte{1}, []byte("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYSJ9.sig\n")...),
			append([]byte{3}, []byte(`{"status":"Success"}`)...),
		)
		err := runK8SSALoot(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if strings.Contains(content, `"escalation":true`) || strings.Contains(content, "privilege escalation") {
			t.Errorf("must NOT claim escalation when the foothold can already write: %s", content)
		}
		if !strings.Contains(content, "no privilege gain") {
			t.Errorf("expected 'no privilege gain' framing: %s", content)
		}
		if strings.Contains(content, `"landed":"execution-confirmed"`) {
			t.Errorf("no-gain must not be execution-confirmed: %s", content)
		}
	})
}

// Token theft fails (exec yields no JWT) -> reachable, no escalation, no token claim.
func TestRunK8SSALootTokenTheftFails(t *testing.T) {
	srv := newK8SLateralServer(200, ssrrWritable, false, true)
	defer srv.Close()
	defer resetK8SFlags()()
	prevFactory := k8sClientFactory
	defer func() { k8sClientFactory = prevFactory }()
	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		k8sPod = "llama-1"
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "saloot-fail.json")
		k8sClientFactory = k8sExecFactory(t,
			append([]byte{1}, []byte("cat: token: No such file\n")...),
			append([]byte{3}, []byte(`{"status":"Success"}`)...),
		)
		err := runK8SSALoot(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, `"token_stolen":false`) || !strings.Contains(content, `"escalation":false`) {
			t.Errorf("theft-failed must set token_stolen=false escalation=false: %s", content)
		}
		if !strings.Contains(content, `"landed":"reachable"`) {
			t.Errorf("theft-failed must be reachable: %s", content)
		}
		if strings.Contains(content, "privilege escalation") {
			t.Errorf("theft-failed must not claim escalation: %s", content)
		}
	})
}

// enum --all-namespaces fans out across namespaces.
func TestRunK8SEnumAllNamespaces(t *testing.T) {
	srv := newK8SLateralServer(200, ssrrReadOnly, false, false)
	defer srv.Close()
	defer resetK8SFlags()()
	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sAllNamespaces = true
		cfg.Insecure = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "enum-all.json")
		err := runK8SEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, `"namespace_count":2`) {
			t.Errorf("expected namespace_count=2 across ml-prod+ml-system: %s", content)
		}
		if !strings.Contains(content, "all namespaces") {
			t.Errorf("expected 'all namespaces' scope label: %s", content)
		}
	})
}

// An incomplete SSRR must not be reported as a hard read-only.
func TestRunK8SAccessReviewIncomplete(t *testing.T) {
	srv := newK8SLateralServer(200, `{"status":{"resourceRules":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"]}],"incomplete":true}}`, false, false)
	defer srv.Close()
	defer resetK8SFlags()()
	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sNamespace = "ml-prod"
		cfg.Insecure = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "ar-incomplete.json")
		err := runK8SAccessReview(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, `"review_incomplete":true`) {
			t.Errorf("expected review_incomplete=true: %s", content)
		}
		if !strings.Contains(content, "INCOMPLETE") {
			t.Errorf("expected the description to flag the incomplete review: %s", content)
		}
	})
}

// Cross-namespace reach: secret-read --all-namespaces spans ml-prod + ml-system.
func TestRunK8SSecretReadAllNamespaces(t *testing.T) {
	srv := newK8SLateralServer(200, ssrrReadOnly, false, false)
	defer srv.Close()
	defer resetK8SFlags()()
	withTestConfig(t, func() {
		k8sTarget = srv.URL
		k8sAllNamespaces = true
		cfg.Insecure = true
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "all-ns.json")
		err := runK8SSecretRead(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, "creds-ml-prod") || !strings.Contains(content, "creds-ml-system") {
			t.Errorf("expected secrets from both namespaces: %s", content)
		}
	})
}

// scriptedExecConn implements k8s.ExecConn, emitting a fixed set of channel frames.
type scriptedExecConn struct {
	frames [][]byte
	idx    int
}

func (s *scriptedExecConn) ReadMessage() (int, []byte, error) {
	if s.idx >= len(s.frames) {
		return 0, nil, http.ErrServerClosed
	}
	frame := s.frames[s.idx]
	s.idx++
	return 2, frame, nil // 2 = websocket.BinaryMessage
}
func (s *scriptedExecConn) WriteMessage(int, []byte) error  { return nil }
func (s *scriptedExecConn) SetReadDeadline(time.Time) error { return nil }
func (s *scriptedExecConn) Close() error                    { return nil }

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
