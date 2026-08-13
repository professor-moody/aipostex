package report

// The source registry is the single declaration of what a finding source *is*.
//
// A source's identity was previously implied by agreement between several
// independent places — the Source constants, the console display-key map, the
// published JSON schema, the module documentation, and the CLI command tree —
// with nothing enforcing that they agreed. They drifted: `agent` and `rag` shipped
// missing from the schema enum, and the coverage matrix went stale by an entire
// module's worth of verbs.
//
// Registry fixes the identity in one place, and registry_test.go enforces every
// other site against it. Adding a source without registering it, or registering a
// module without its documentation, schema entry, or display keys, fails the build.
//
// Display keys deliberately stay in moduleDisplayKeys: they are rendering
// configuration rather than identity, and the tests bind them to this registry.

// SourceKind classifies what produces a source, which decides what the rest of the
// repository must provide for it.
type SourceKind string

const (
	// KindModule is a target-facing module: it has a CLI command of the same name
	// and a page under docs/modules/.
	KindModule SourceKind = "module"
	// KindOperator is a top-level operator verb that emits its own findings but is
	// not a target module and has no module documentation page.
	KindOperator SourceKind = "operator"
	// KindInfrastructure is emitted by shared machinery (discovery, fingerprinting,
	// template checks, credential extraction) rather than by a single command.
	KindInfrastructure SourceKind = "infrastructure"
)

// SourceInfo is the registered identity of one finding source.
type SourceInfo struct {
	// Source is the value written to a finding's `source` field.
	Source string
	// Kind decides which consistency rules apply.
	Kind SourceKind
	// Command is the top-level CLI command that emits this source, empty when the
	// source comes from shared machinery. For modules it must equal Source.
	Command string
	// DocPage is the basename under docs/modules/ (without .md). Modules must have
	// one; other kinds leave it empty.
	DocPage string
	// MatrixLabel is how the module is named in the capability matrix
	// (docs/development/coverage.md). It is a human label, so it does not always
	// match Source ("tfserving" is written "TensorFlow Serving"). Modules that the
	// matrix covers under a broader heading — the vector-database backends are
	// listed individually — point at that heading instead.
	MatrixLabel string
}

// Registry declares every finding source exactly once.
var Registry = []SourceInfo{
	// ── target-facing modules ──
	{Source: SourceOllama, Kind: KindModule, Command: "ollama", DocPage: "ollama", MatrixLabel: "Ollama"},
	{Source: SourceVectorDB, Kind: KindModule, Command: "vectordb", DocPage: "vectordb", MatrixLabel: "ChromaDB"},
	{Source: SourceMCP, Kind: KindModule, Command: "mcp", DocPage: "mcp", MatrixLabel: "MCP"},
	{Source: SourceJupyter, Kind: KindModule, Command: "jupyter", DocPage: "jupyter", MatrixLabel: "Jupyter"},
	{Source: SourceOpenAICompat, Kind: KindModule, Command: "openai-compat", DocPage: "openai-compat", MatrixLabel: "OpenAI-Compatible"},
	{Source: SourceLiteLLM, Kind: KindModule, Command: "litellm", DocPage: "litellm", MatrixLabel: "LiteLLM"},
	{Source: SourceRay, Kind: KindModule, Command: "ray", DocPage: "ray", MatrixLabel: "Ray"},
	{Source: SourceMLflow, Kind: KindModule, Command: "mlflow", DocPage: "mlflow", MatrixLabel: "MLflow"},
	{Source: SourceGradio, Kind: KindModule, Command: "gradio", DocPage: "gradio", MatrixLabel: "Gradio"},
	{Source: SourceBentoML, Kind: KindModule, Command: "bentoml", DocPage: "bentoml", MatrixLabel: "BentoML"},
	{Source: SourceTriton, Kind: KindModule, Command: "triton", DocPage: "triton", MatrixLabel: "NVIDIA Triton"},
	{Source: SourceTorchServe, Kind: KindModule, Command: "torchserve", DocPage: "torchserve", MatrixLabel: "TorchServe"},
	{Source: SourceTFServing, Kind: KindModule, Command: "tfserving", DocPage: "tfserving", MatrixLabel: "TensorFlow Serving"},
	{Source: SourceA2A, Kind: KindModule, Command: "a2a", DocPage: "a2a", MatrixLabel: "A2A"},
	{Source: SourceWandB, Kind: KindModule, Command: "wandb", DocPage: "wandb", MatrixLabel: "Weights & Biases"},
	{Source: SourceHuggingFace, Kind: KindModule, Command: "huggingface", DocPage: "huggingface", MatrixLabel: "HuggingFace"},
	{Source: SourceKubeflow, Kind: KindModule, Command: "kubeflow", DocPage: "kubeflow", MatrixLabel: "Kubeflow"},
	{Source: SourceK8s, Kind: KindModule, Command: "k8s", DocPage: "k8s", MatrixLabel: "Kubernetes"},
	{Source: SourceAgent, Kind: KindModule, Command: "agent", DocPage: "agent", MatrixLabel: "Agent (bespoke)"},
	{Source: SourceRAG, Kind: KindModule, Command: "rag", DocPage: "rag", MatrixLabel: "RAG (black-box)"},

	// ── operator verbs ──
	{Source: SourceRequest, Kind: KindOperator, Command: "request"},
	{Source: SourceListener, Kind: KindOperator, Command: "listen"},

	// ── shared machinery ──
	{Source: SourceFileDiscovery, Kind: KindInfrastructure},
	{Source: SourceFingerprint, Kind: KindInfrastructure},
	{Source: SourceVulnCheck, Kind: KindInfrastructure},
	{Source: SourceCredential, Kind: KindInfrastructure},
}

// registryBySource indexes Registry for lookup.
var registryBySource = func() map[string]SourceInfo {
	m := make(map[string]SourceInfo, len(Registry))
	for _, info := range Registry {
		m[info.Source] = info
	}
	return m
}()

// LookupSource returns the registered identity for a source value.
func LookupSource(source string) (SourceInfo, bool) {
	info, ok := registryBySource[source]
	return info, ok
}

// ModuleSources returns the source values of every target-facing module, in
// registration order.
func ModuleSources() []string {
	out := make([]string, 0, len(Registry))
	for _, info := range Registry {
		if info.Kind == KindModule {
			out = append(out, info.Source)
		}
	}
	return out
}

// AllSources returns every registered source value, in registration order.
func AllSources() []string {
	out := make([]string, 0, len(Registry))
	for _, info := range Registry {
		out = append(out, info.Source)
	}
	return out
}
