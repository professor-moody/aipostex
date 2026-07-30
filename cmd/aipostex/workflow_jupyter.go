package main

import (
	"net"
	"net/url"
	"strings"
)

func buildJupyterEnumWorkflowPlan(target string, notebookPaths, kernelIDs []string) workflowPlan {
	target = canonicalServiceURL(target)
	recommendations := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" notebooks"), "List notebook paths for follow-on reads.", false, 10),
		newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" kernels"), "List active kernels before considering execution.", false, 20),
	}
	if notebook := shellSafeArg(firstNonPlaceholder(notebookPaths)); notebook != "" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" read-notebook --path "+notebook), "Read a discovered notebook directly.", false, 30),
		)
	}
	if kernel := shellSafeArg(firstNonPlaceholder(kernelIDs)); kernel != "" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" exec --kernel "+kernel+" --code \"print('hi')\" --force-exploit"), "Only after confirming execution is in scope for this kernel.", true, 40),
		)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "enum",
		Rationale:       "Move through notebook and kernel inventory before any code execution.",
		Recommendations: recommendations,
	}
}

func buildJupyterNotebooksSummaryWorkflowPlan(target string, allPaths []string, kernelIDs []string) workflowPlan {
	target = canonicalServiceURL(target)
	recommendations := make([]workflowRecommendation, 0, len(allPaths)+2)
	priority := 10
	for _, path := range allPaths {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" read-notebook --path "+shellSafeArg(path)), "Browse or read this discovered path.", false, priority),
		)
		priority += 10
	}
	if len(allPaths) == 0 {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" read-notebook --path <path>"), "Read a notebook or browse a directory by path.", false, priority),
		)
		priority += 10
	}
	recommendations = append(recommendations,
		newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" kernels"), "List active kernels for potential execution paths.", false, priority),
	)
	priority += 10
	if kernel := shellSafeArg(firstNonPlaceholder(kernelIDs)); kernel != "" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" exec --kernel "+kernel+" --code \"print('hi')\" --force-exploit"), "Only after confirming execution is in scope for this kernel.", true, priority),
		)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "notebooks",
		Rationale:       "Notebook listing complete; read discovered paths and list kernels.",
		Recommendations: recommendations,
	}
}

// buildJupyterExecWorkflowPlan chains a confirmed kernel code-execution into the
// deepening steps that share the same live kernel: persistence, an interactive
// shell, and dependency-loading abuse. The kernel id is threaded through so each
// command targets the kernel that just executed.
func buildJupyterExecWorkflowPlan(target, kernel string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "jupyter --target " + target + " "
	kArg := ""
	if kernel != "" {
		kArg = " --kernel " + shellSafeArg(kernel)
	}
	return workflowPlan{
		Target:      target,
		Stage:       "own",
		Landed:      "execution-confirmed",
		ChainSource: "jupyter-exec",
		Rationale:   "Code execution on the kernel is confirmed; deepen the foothold on the same kernel — persist, prove an interactive shell, and probe dependency-loading abuse.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"persist"+kArg+" --force-exploit"), "Install a persistence hook so execution survives kernel/session restarts.", true, 10),
			newWorkflowRecommendation(formatCommandExample(base+"reverse-shell-proof"+kArg+" --force-exploit"), "Prove outbound socket capability (reverse-shell reachability) from the kernel host.", true, 20),
			newWorkflowRecommendation(formatCommandExample(base+"pip-proof"+kArg+" --force-exploit"), "Prove pip/dependency-install capability from the execution context.", true, 30),
		},
	}
}

func buildJupyterKernelWorkflowPlan(target, kernel string) workflowPlan {
	target = canonicalServiceURL(target)
	kernel = shellSafeArg(firstOrPlaceholder([]string{kernel}, "<kernel-id>"))
	return workflowPlan{
		Target:    target,
		Stage:     "kernel",
		Rationale: "A confirmed kernel ID enables a concrete execution path if the engagement allows it.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" exec --kernel "+kernel+" --code \"print('hi')\" --force-exploit"), "This is the next step only when execution is explicitly allowed.", true, 10),
		},
	}
}

func buildJupyterNotebookWorkflowPlan(target, path string) workflowPlan {
	target = canonicalServiceURL(target)
	path = shellSafeArg(firstOrPlaceholder([]string{path}, "<notebook-path>"))
	return workflowPlan{
		Target:    target,
		Stage:     "notebook",
		Rationale: "A discovered notebook path can be read directly without extra discovery.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("jupyter --target "+target+" read-notebook --path "+path), "Read this specific notebook via the contents API.", false, 10),
		},
	}
}

func buildJupyterCredentialWorkflowPlan(notebookTarget, path, secretType, secretValue string) workflowPlan {
	secretType = strings.TrimSpace(secretType)
	secretValue = strings.TrimSpace(secretValue)

	switch secretType {
	case "OpenAI API Key":
		target := jupyterCredentialTarget(notebookTarget, "openai")
		return workflowPlan{
			Target:      target,
			Stage:       "credential-chain",
			Landed:      "read-confirmed",
			ChainSource: "jupyter-read-notebook",
			Rationale:   "Notebook read exposed an OpenAI-style bearer key; validate it against the discovered OpenAI-compatible or proxy endpoint.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" --api-key "+shellSafeArg(secretValue)+" auth-sweep"), "Test the discovered key before falling back to weak-auth patterns.", false, 10),
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" --api-key "+shellSafeArg(secretValue)+" enum"), "List models reachable with the discovered key.", false, 20),
			},
		}
	case "Anthropic API Key":
		target := jupyterCredentialTarget(notebookTarget, "openai")
		return workflowPlan{
			Target:      target,
			Stage:       "credential-chain",
			Landed:      "read-confirmed",
			ChainSource: "jupyter-read-notebook",
			Rationale:   "Notebook read exposed an Anthropic key; validate it through the discovered OpenAI-compatible proxy only if that proxy fronts Anthropic-compatible upstream models.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" --api-key "+shellSafeArg(secretValue)+" auth-sweep"), "Validate the bearer credential with the OpenAI-compatible module against the proxy, such as LiteLLM.", false, 10),
			},
		}
	case "HuggingFace Token":
		target := "<huggingface-target>"
		return workflowPlan{
			Target:      target,
			Stage:       "credential-chain",
			Landed:      "read-confirmed",
			ChainSource: "jupyter-read-notebook",
			Rationale:   "Notebook read exposed a HuggingFace token; validate it against the served TGI or TEI endpoint.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("huggingface --target "+target+" --header "+shellSafeArg("Authorization: Bearer "+secretValue)+" enum"), "Enumerate the HuggingFace inference service with the discovered token.", false, 10),
			},
		}
	case "Bearer Token", "Generic API Key Assignment":
		target := "<api-target>"
		return workflowPlan{
			Target:      target,
			Stage:       "credential-chain",
			Landed:      "read-confirmed",
			ChainSource: "jupyter-read-notebook",
			Rationale:   "Notebook read exposed a reusable bearer credential; validate it against the matching API surface discovered in the lab.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("openai-compat --target "+target+" --api-key "+shellSafeArg(secretValue)+" auth-sweep"), "Use the credential as a bearer token against an OpenAI-compatible service if the target matches.", false, 10),
			},
		}
	default:
		target := canonicalServiceURL(notebookTarget)
		return workflowPlan{
			Target:      target,
			Stage:       "credential-chain",
			Landed:      "read-confirmed",
			ChainSource: "jupyter-read-notebook",
			Rationale:   "Notebook read exposed a credential-like value. Correlate it with adjacent services before use.",
		}
	}
}

func jupyterCredentialTarget(notebookTarget, targetKind string) string {
	if targetKind != "openai" {
		return "<" + targetKind + "-target>"
	}
	if labTarget := inferLabOpenAICompatTarget(notebookTarget); labTarget != "" {
		return labTarget
	}
	return "<openai-compatible-target>"
}

func inferLabOpenAICompatTarget(notebookTarget string) string {
	u, err := url.Parse(canonicalServiceURL(notebookTarget))
	if err != nil {
		return ""
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	// Lab topology: notebook/demo host 172.16.50.10 pivots to LiteLLM on
	// 172.16.50.20:4000. Unknown environments keep the explicit placeholder.
	if v4[0] == 172 && v4[1] == 16 && v4[2] == 50 && v4[3] == 10 {
		return "http://172.16.50.20:4000"
	}
	return ""
}
