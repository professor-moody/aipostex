# Kubernetes

Enumerate and exploit Kubernetes API servers hosting ML/AI workloads.

## Overview

The `k8s` module probes a [Kubernetes](https://kubernetes.io/) API server directly (no `kubectl`/`client-go` dependency). It assesses **anonymous / unauthenticated RBAC posture**, maps **the current identity's authorization**, enumerates **workloads and custom resources**, exfiltrates **Secrets**, harvests **model-artifact locations**, executes commands **inside pods**, and performs **in-cluster lateral movement** by stealing a pod's service-account token and re-authenticating as it.

The headline weakness it finds is the classic catastrophic misconfiguration: anonymous authentication enabled (`--anonymous-auth=true`) plus a read (or broader) `ClusterRole` bound to `system:anonymous`. On ML clusters that turns an unauthenticated request into model-registry token theft and, when the binding includes `pods/exec`, in-pod remote code execution — and from there, theft of a pod's service-account token to escalate to a more-privileged identity.

**Scope (single API server; in-cluster traversal).** Every verb operates against exactly one `--target` API server, but it traverses **identities** and **namespaces** within that cluster: `enum`/`secret-read` take `--all-namespaces`, `access-review` maps any identity's permissions, and `sa-loot` steals a pod's SA token and re-authenticates as it. It **stops at the cluster boundary** — no cross-cluster / cluster-mesh movement. (Kubelet `:10250` pivots, cloud-metadata SSRF, and host escape are out of scope here — they cannot be honestly proven on a single-node target.)

**TLS.** k3s and most clusters serve a self-signed API server certificate on `:6443`; pass `--insecure` to skip verification.

## Subcommands

### Read-only (no `--force-exploit` required)

| Subcommand | Description |
|---|---|
| `rbac-probe` | Assess anonymous / unauthenticated API access and classify the posture |
| `access-review` | Map what the current identity is authorized to do (`SelfSubjectRulesReview`) |
| `enum` | Enumerate workloads (pods, deployments, services, configmaps) and custom resources (`--all-namespaces` for cluster-wide) |

### Gated (requires `--force-exploit`)

| Subcommand | Description |
|---|---|
| `secret-read` | List and base64-decode every Secret in a namespace (`--all-namespaces` for cluster-wide) to plaintext |
| `artifact-read` | Harvest model-artifact locations from ConfigMaps and InferenceService specs |
| `pod-exec` | Execute a command inside a pod over the API server exec stream (in-pod RCE) |
| `sa-loot` | Steal a pod's service-account token, re-authenticate as it, and detect privilege escalation |
| `persist` | Deploy a bounded, self-healing persistence workload (a labelled busybox canary — no reverse shell/host access) with the current/stolen identity and confirm the cluster runs it |

## Flags

### Common (persistent)

| Flag | Required | Description |
|---|---|---|
| `--target`, `-t` | Yes | Kubernetes API server URL (e.g. `https://127.0.0.1:6443`) |
| `--namespace` | No | Namespace to target (default `default`) |
| `--header` | No | Additional HTTP header(s) in `Key: Value` format — e.g. a bearer token. Repeatable. |
| `--insecure` | No | Skip TLS verification (needed for self-signed API server certs) |

### Per-subcommand

| Subcommand | Flags |
|---|---|
| `enum`, `secret-read` | `--all-namespaces`, `-A` (operate over every readable namespace instead of just `--namespace`) |
| `pod-exec` | `--pod` (default: first pod in the namespace), `--container` (default: the pod's first container), `--command` (comma-separated argv, default `id`) |
| `sa-loot` | `--pod` (default: first pod in the namespace), `--container` (default: the pod's first container) |

## Honest classification

Findings carry stage/landed metadata (`stage` / `landed`) and are **honest in both directions**. `rbac-probe` classifies the response, never assuming a weakness:

| Posture | Meaning | Severity |
|---|---|---|
| `anonymous-open` | A sensitive resource (namespaces/secrets/pods) is readable without credentials | High, `influenced` |
| `authenticated-restricted` | An anonymous identity exists but RBAC denies the resource (HTTP 403) | Info, `reachable` |
| `auth-enforced` | Anonymous reads are rejected with HTTP 401 — **not weak** | Info, `reachable` |

The gated verbs only claim success when it is real: `secret-read` reports `read-confirmed` only on a decoded Secret, and `pod-exec` reports `execution-confirmed` only when the exec stream returns command output — a 401/403 that prevents the exec stream is reported honestly as `reachable` (denied), not as RCE. `sa-loot` claims **privilege escalation** (`execution-confirmed`) only when the stolen identity can genuinely *write* (create/update/delete) where the anonymous foothold is read-only; a stolen token that is itself read-only is `read-confirmed` ("token stolen, no escalation"), and a token that can't be read is `reachable`. The escalation is confirmed via a non-persisting dry-run create (the write is **not** persisted), and the captured token is surfaced in evidence so the operator can re-authenticate and pivot.

## What each `landed` level means here

The `landed` axis records what actually landed on the API server. k8s reaches `takeover-capable` with `persist` — a bounded self-healing workload the cluster keeps running under a stolen identity; short of that, in-pod RCE (`pod-exec`) and privilege-escalating token theft (`sa-loot`) are its `own`/`execution-confirmed` peaks. Cross-cluster / cluster-mesh movement stays out of scope (it cannot be honestly proven on a single-node target).

| `landed` | What produces it in k8s |
|---|---|
| `reachable` | `rbac-probe` when anonymous reads are enforced (`auth-enforced`) or restricted (`authenticated-restricted`); `access-review` when the identity cannot self-review; `pod-exec` / `sa-loot` when the exec stream can't be opened or no token is mounted; `persist` when the identity cannot create the Deployment (denied — no persistence claimed) |
| `influenced` | `rbac-probe` when sensitive resources (namespaces/secrets/pods) are readable without credentials (`anonymous-open`) — an over-broad read surface is exposed; `persist` when the Deployment is accepted but no Running pod is observed in the poll window (deployed, not yet executing) |
| `read-confirmed` | `secret-read` on a base64-decoded Secret; `access-review` when the identity's rule map is returned; `sa-loot` when a token is stolen but grants no write beyond the foothold |
| `execution-confirmed` | `pod-exec` when the exec stream returns command output (in-pod RCE — even a non-zero exit counts, as execution is proven); `sa-loot` when the stolen SA token can WRITE where the foothold identity is denied (privilege escalation, confirmed by dry-run create) |
| `takeover-capable` | `persist` when the deployed self-healing Deployment has a Running pod — the cluster is executing our (bounded, benign) workload and will restart it if killed: a persistent foothold |

## Verbs

### `rbac-probe` (read-only)

Sends credential-free reads to sensitive endpoints (`/api/v1/namespaces`, `/api/v1/secrets`, `/api/v1/pods`, `/apis/apps/v1/deployments`) plus the discovery documents, and classifies the posture from the status codes (200 = anonymous access, 401 = enforced, 403 = anonymous identity but restricted).

```bash
aipostex k8s --target https://127.0.0.1:6443 --insecure rbac-probe
```

### `access-review` (read-only)

Asks the API server, **as the current identity** (anonymous, or a token via `--header "Authorization: Bearer <jwt>"`), exactly what it can do in `--namespace` via `SelfSubjectRulesReview` — a precise authorization map, not a probe-by-request heuristic. An unauthenticated caller that cannot self-review (401/403, e.g. `system:anonymous`) is reported honestly as such (Info, `reachable`); an identity that can write is High (`incl. WRITE`).

```bash
# anonymous (typically can't self-review)
aipostex k8s --target https://127.0.0.1:6443 --insecure access-review --namespace ml-prod
# as a captured/supplied identity
aipostex k8s --target https://127.0.0.1:6443 --insecure access-review --namespace ml-prod --header "Authorization: Bearer <jwt>"
```

### `enum` (read-only)

Lists pods, deployments, services, and configmaps in `--namespace` and the cluster's CustomResourceDefinitions, highlighting ML-platform CRDs (KServe `inferenceservices`, Kubeflow, Seldon, Ray). Endpoints denied by RBAC are skipped, so a partial grant still yields what it exposes. Pass `--all-namespaces`/`-A` to enumerate every namespace the identity can read.

```bash
aipostex k8s --target https://127.0.0.1:6443 --insecure enum --all-namespaces
```

### `secret-read` (gated)

Lists every Secret in `--namespace` and base64-decodes its data to plaintext — model-registry tokens, cloud object-store credentials, database passwords.

```bash
aipostex k8s --target https://127.0.0.1:6443 --insecure secret-read --namespace ml-prod --force-exploit
```

### `artifact-read` (gated)

Reads ConfigMaps and InferenceService specs to recover model names, registry endpoints, and object-store `storageUri`s — the coordinates an attacker needs to pull proprietary models.

```bash
aipostex k8s --target https://127.0.0.1:6443 --insecure artifact-read --namespace ml-prod --force-exploit
```

### `pod-exec` (gated)

Opens an exec stream (WebSocket `v5.channel.k8s.io`) into a pod and runs `--command`. If `--pod` is omitted, the first pod in `--namespace` (preferring a `component=model-server` pod) is targeted. Arbitrary in-pod command execution is the takeover step.

```bash
aipostex k8s --target https://127.0.0.1:6443 --insecure pod-exec --namespace ml-prod --command id --force-exploit
```

### `sa-loot` (gated)

In-cluster lateral movement. Execs into a pod (`--pod`, or the first pod in `--namespace`), reads its mounted service-account token (`/var/run/secrets/kubernetes.io/serviceaccount/token`), re-authenticates to the API server **as that ServiceAccount**, and maps what it can do via `SelfSubjectRulesReview`. If the stolen identity can write where the anonymous foothold is read-only, that is a **privilege escalation** (Critical, `execution-confirmed`). The token is redacted from output; the write capability is reported, not exercised.

```bash
aipostex k8s --target https://127.0.0.1:6443 --insecure sa-loot --namespace ml-prod --force-exploit
```

## Detection & templates

The discovery fingerprint identifies a Kubernetes API server on `:6443` from `/version` (`gitVersion`, e.g. `v1.31.5+k3s1`) when anonymous reads are allowed, and from the `401 Unauthorized` `Status` object when they are not. Three `k8s-*` vulncheck templates run in `assess --mode full`:

- `k8s-enum-001-anonymous-api` — anonymous `/version` + `/api` discovery (detection).
- `k8s-rbac-001-anonymous-namespace-list` — anonymous namespace enumeration (detection).
- `k8s-exploit-001-anonymous-secret-exfil` — anonymous cluster-wide Secret data exfiltration (exploit).

## Examples

```bash
# Posture first (read-only), then enumerate cluster-wide and map your own access
aipostex k8s --target https://127.0.0.1:6443 --insecure rbac-probe
aipostex k8s --target https://127.0.0.1:6443 --insecure enum --all-namespaces
aipostex k8s --target https://127.0.0.1:6443 --insecure access-review --namespace ml-prod

# Active exfiltration and execution (gated)
aipostex k8s --target https://127.0.0.1:6443 --insecure secret-read --all-namespaces --force-exploit
aipostex k8s --target https://127.0.0.1:6443 --insecure pod-exec --namespace ml-prod --command id --force-exploit

# In-cluster lateral movement: steal a pod's SA token and escalate
aipostex k8s --target https://127.0.0.1:6443 --insecure sa-loot --namespace ml-prod --force-exploit

# Network discovery + templated assessment of an API server
aipostex assess network --target 10.0.0.0/24 --ports 6443 --insecure --mode full
```
