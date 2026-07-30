package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func manualTestCreds() []dossierCredential {
	return []dossierCredential{
		{Type: "k8s-sa-token", Name: "ml-prod/llama-inference-abc service-account token", Value: "eyJhbGc.k8s.tok", TargetURL: "https://172.16.50.50:6443", Chainable: true},
		{Type: "hf-token", Name: "HF_TOKEN", Value: "hf_FAKE123", TargetURL: "http://172.16.50.40:8180", Chainable: true},
		{Type: "litellm-master-key", Value: "sk-litellm-lab-auth-key-FAKE123", TargetURL: "http://172.16.50.20:4000", Chainable: true},
		{Type: "db-connection-string", Value: "postgres://u:p@h:5432/db", Chainable: false},
	}
}

func TestWriteDossierManualNativeHandoff(t *testing.T) {
	dir := t.TempDir()
	kubeconfigs, pivots, err := writeDossierManual(dir, manualTestCreds())
	if err != nil {
		t.Fatalf("writeDossierManual: %v", err)
	}
	if kubeconfigs != 1 {
		t.Fatalf("kubeconfigs = %d, want 1", kubeconfigs)
	}
	// k8s + hf + litellm get native pivots; db-connection-string (viewer-only) does not.
	if pivots != 3 {
		t.Fatalf("pivots = %d, want 3", pivots)
	}

	mdir := filepath.Join(dir, "manual")

	// kubeconfig — 0600, correct server/token/ns/insecure.
	kcPath := filepath.Join(mdir, "kubeconfig-ml-prod")
	info, err := os.Stat(kcPath)
	if err != nil {
		t.Fatalf("stat kubeconfig: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("kubeconfig mode = %v, want 0600 (embeds the token)", info.Mode().Perm())
	}
	kc := readDossierFile(t, mdir, "kubeconfig-ml-prod")
	for _, want := range []string{"server: https://172.16.50.50:6443", "insecure-skip-tls-verify: true", "token: eyJhbGc.k8s.tok", "namespace: ml-prod"} {
		if !strings.Contains(kc, want) {
			t.Fatalf("kubeconfig missing %q:\n%s", want, kc)
		}
	}

	// env.sh — 0600, quoted exports for every cred (name-based + type-based).
	envInfo, err := os.Stat(filepath.Join(mdir, "env.sh"))
	if err != nil {
		t.Fatalf("stat env.sh: %v", err)
	}
	if envInfo.Mode().Perm() != 0o600 {
		t.Fatalf("env.sh mode = %v, want 0600", envInfo.Mode().Perm())
	}
	env := readDossierFile(t, mdir, "env.sh")
	for _, want := range []string{
		"export SA_TOKEN='eyJhbGc.k8s.tok'",
		"export HF_TOKEN='hf_FAKE123'",
		"export LITELLM_MASTER_KEY='sk-litellm-lab-auth-key-FAKE123'",
		"export DB_URL='postgres://u:p@h:5432/db'",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("env.sh missing %q:\n%s", want, env)
		}
	}

	// pivots.sh — 0700, bash-clean, native kubectl/curl, DESTRUCTIVE commented, no viewer-only pivot.
	pivPath := filepath.Join(mdir, "pivots.sh")
	pivInfo, err := os.Stat(pivPath)
	if err != nil {
		t.Fatalf("stat pivots.sh: %v", err)
	}
	if pivInfo.Mode().Perm() != 0o700 {
		t.Fatalf("pivots.sh mode = %v, want 0700 (embeds credentials)", pivInfo.Mode().Perm())
	}
	piv := readDossierFile(t, mdir, "pivots.sh")
	for _, want := range []string{
		"#!/usr/bin/env bash",
		`kubectl --kubeconfig "$(dirname "$0")/kubeconfig-ml-prod" auth can-i --list`,
		`kubectl --kubeconfig "$(dirname "$0")/kubeconfig-ml-prod" get secrets --all-namespaces`,
		"# DESTRUCTIVE",
		"http://172.16.50.20:4000/v1/models", // litellm read-only
		"http://172.16.50.40:8180/generate",  // hf read-only
	} {
		if !strings.Contains(piv, want) {
			t.Fatalf("pivots.sh missing %q:\n%s", want, piv)
		}
	}
	// db-connection-string is viewer-only: exported to env.sh but never given a raw pivot.
	if strings.Contains(piv, "postgres://u:p@h:5432/db") {
		t.Fatalf("pivots.sh leaked a viewer-only db-connection-string pivot:\n%s", piv)
	}
	// The DESTRUCTIVE kubectl/curl variants must be commented (start with '# ').
	for _, line := range strings.Split(piv, "\n") {
		if strings.Contains(line, "create deployment pwn") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Fatalf("DESTRUCTIVE line is not commented out: %q", line)
		}
		if strings.Contains(line, "/key/generate") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Fatalf("DESTRUCTIVE key-generate line is not commented out: %q", line)
		}
	}
	if _, err := exec.LookPath("bash"); err == nil {
		if out, err := exec.Command("bash", "-n", pivPath).CombinedOutput(); err != nil {
			t.Fatalf("bash -n pivots.sh failed: %v\n%s", err, out)
		}
	}
}

func TestWriteDossierManualNoCreds(t *testing.T) {
	dir := t.TempDir()
	kubeconfigs, pivots, err := writeDossierManual(dir, nil)
	if err != nil {
		t.Fatalf("writeDossierManual(nil): %v", err)
	}
	if kubeconfigs != 0 || pivots != 0 {
		t.Fatalf("expected 0/0 for no creds, got %d/%d", kubeconfigs, pivots)
	}
	if _, err := os.Stat(filepath.Join(dir, "manual")); !os.IsNotExist(err) {
		t.Fatalf("manual/ should not be created with no credentials")
	}
}

// Integration: a real k8s sa-loot finding flows through writeDossier into manual/.
func TestWriteDossierEmitsManualFromK8sFinding(t *testing.T) {
	findings := []report.Finding{{
		ID:       "k8s-sa-loot-1",
		Source:   "k8s",
		Target:   "https://172.16.50.50:6443",
		Title:    "Kubernetes privilege escalation: stolen SA token",
		Severity: report.SeverityCritical,
		Evidence: "Captured service-account token: eyJhbGc.k8s.tok",
		Metadata: map[string]interface{}{
			"service": "k8s",
			"stage":   "own",
			"landed":  "execution-confirmed",
			"extracted_credentials": []interface{}{
				map[string]interface{}{
					"type":       "k8s-sa-token",
					"name":       "ml-prod/llama-inference-abc service-account token",
					"value":      "eyJhbGc.k8s.tok",
					"target_url": "https://172.16.50.50:6443",
					"chainable":  true,
				},
			},
		},
	}}
	dir := filepath.Join(t.TempDir(), "dossier")
	if err := writeDossier(dir, findings, report.FindingCollection{Findings: findings}); err != nil {
		t.Fatalf("writeDossier: %v", err)
	}
	kc := readDossierFile(t, filepath.Join(dir, "manual"), "kubeconfig-ml-prod")
	if !strings.Contains(kc, "token: eyJhbGc.k8s.tok") {
		t.Fatalf("manual/kubeconfig-ml-prod not built from the finding:\n%s", kc)
	}
	readme := readDossierFile(t, dir, "README.md")
	if !strings.Contains(readme, "manual/kubeconfig") || !strings.Contains(readme, "pivots.sh") {
		t.Fatalf("README.md does not document the manual/ handoff:\n%s", readme)
	}
}

func TestK8sNamespaceFromCredName(t *testing.T) {
	cases := map[string]string{
		"ml-prod/llama-inference-abc service-account token": "ml-prod",
		"ml-system/pipeline service-account token":          "ml-system",
		"":              "default",
		"no-slash-here": "no-slash-here",
	}
	for in, want := range cases {
		if got := k8sNamespaceFromCredName(in); got != want {
			t.Fatalf("k8sNamespaceFromCredName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnvNameForCredential(t *testing.T) {
	if got := envNameForCredential(dossierCredential{Name: "AWS_ACCESS_KEY_ID"}); got != "AWS_ACCESS_KEY_ID" {
		t.Fatalf("valid identifier name should pass through, got %q", got)
	}
	if got := envNameForCredential(dossierCredential{Type: "k8s-sa-token", Name: "ml-prod/x token"}); got != "SA_TOKEN" {
		t.Fatalf("non-identifier name should fall back to type, got %q", got)
	}
	if got := envNameForCredential(dossierCredential{Type: "unknown-type"}); got != "" {
		t.Fatalf("unknown type with no name should yield empty, got %q", got)
	}
}

func TestShellSingleQuote(t *testing.T) {
	if got := shellSingleQuote(`ab'cd`); got != `'ab'\''cd'` {
		t.Fatalf("shellSingleQuote embedded-quote = %q", got)
	}
}
