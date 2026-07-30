package report

// FingerprintMetadata holds metadata from fingerprint scan findings.
type FingerprintMetadata struct {
	Service         string   `json:"service,omitempty"`
	Host            string   `json:"host,omitempty"`
	Port            int      `json:"port,omitempty"`
	Specificity     int      `json:"specificity,omitempty"`
	Confidence      string   `json:"confidence,omitempty"`
	MatchKind       string   `json:"match_kind,omitempty"`
	ProxyLikely     bool     `json:"proxy_likely,omitempty"`
	MatchedProbes   []string `json:"matched_probes,omitempty"`
	AmbiguityReason string   `json:"ambiguity_reason,omitempty"`
	Version         string   `json:"version,omitempty"`
}

func (m FingerprintMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "service", m.Service)
	setNonZero(out, "host", m.Host)
	if m.Port != 0 {
		out["port"] = m.Port
	}
	if m.Specificity != 0 {
		out["specificity"] = m.Specificity
	}
	setNonZero(out, "confidence", m.Confidence)
	setNonZero(out, "match_kind", m.MatchKind)
	if m.ProxyLikely {
		out["proxy_likely"] = true
	}
	if len(m.MatchedProbes) > 0 {
		out["matched_probes"] = append([]string(nil), m.MatchedProbes...)
	}
	setNonZero(out, "ambiguity_reason", m.AmbiguityReason)
	setNonZero(out, "version", m.Version)
	return out
}

// OllamaMetadata holds metadata from Ollama exploit findings.
type OllamaMetadata struct {
	Module        string `json:"module,omitempty"`
	Action        string `json:"action,omitempty"`
	Provider      string `json:"provider,omitempty"`
	Model         string `json:"model,omitempty"`
	Version       string `json:"version,omitempty"`
	Mutating      bool   `json:"mutating,omitempty"`
	PayloadPreset string `json:"payload_preset,omitempty"`
	Stage         string `json:"stage,omitempty"`
	Landed        string `json:"landed,omitempty"`
	ChainSource   string `json:"chain_source,omitempty"`
}

func (m OllamaMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "module", m.Module)
	setNonZero(out, "action", m.Action)
	setNonZero(out, "provider", m.Provider)
	setNonZero(out, "model", m.Model)
	setNonZero(out, "version", m.Version)
	if m.Mutating {
		out["mutating"] = true
	}
	setNonZero(out, "payload_preset", m.PayloadPreset)
	setNonZero(out, "stage", m.Stage)
	setNonZero(out, "landed", m.Landed)
	setNonZero(out, "chain_source", m.ChainSource)
	return out
}

// VectorDBMetadata holds metadata from vector database exploit findings.
type VectorDBMetadata struct {
	Module           string `json:"module,omitempty"`
	Action           string `json:"action,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Version          string `json:"version,omitempty"`
	Collection       string `json:"collection,omitempty"`
	Class            string `json:"class,omitempty"`
	SensitivityHints string `json:"sensitivity_hints,omitempty"`
	ArtifactKind     string `json:"artifact_kind,omitempty"`
}

func (m VectorDBMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "module", m.Module)
	setNonZero(out, "action", m.Action)
	setNonZero(out, "provider", m.Provider)
	setNonZero(out, "version", m.Version)
	setNonZero(out, "collection", m.Collection)
	setNonZero(out, "class", m.Class)
	setNonZero(out, "sensitivity_hints", m.SensitivityHints)
	setNonZero(out, "artifact_kind", m.ArtifactKind)
	return out
}

// JupyterMetadata holds metadata from Jupyter exploit findings.
type JupyterMetadata struct {
	Module   string `json:"module,omitempty"`
	Action   string `json:"action,omitempty"`
	Provider string `json:"provider,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	Path     string `json:"path,omitempty"`
	Version  string `json:"version,omitempty"`
}

func (m JupyterMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "module", m.Module)
	setNonZero(out, "action", m.Action)
	setNonZero(out, "provider", m.Provider)
	setNonZero(out, "kernel", m.Kernel)
	setNonZero(out, "path", m.Path)
	setNonZero(out, "version", m.Version)
	return out
}

// MCPMetadata holds metadata from MCP exploit findings.
type MCPMetadata struct {
	Module           string `json:"module,omitempty"`
	Action           string `json:"action,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Transport        string `json:"transport,omitempty"`
	Server           string `json:"server,omitempty"`
	ConfigSource     string `json:"config_source,omitempty"`
	EnvKey           string `json:"env_key,omitempty"`
	Capability       string `json:"capability,omitempty"`
	CapabilityLabels string `json:"capability_labels,omitempty"`
	Confidence       string `json:"confidence,omitempty"`
	Tool             string `json:"tool,omitempty"`
	Endpoint         string `json:"endpoint,omitempty"`
	Mode             string `json:"mode,omitempty"`
	TargetAlias      string `json:"target_alias,omitempty"`
}

func (m MCPMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "module", m.Module)
	setNonZero(out, "action", m.Action)
	setNonZero(out, "provider", m.Provider)
	setNonZero(out, "transport", m.Transport)
	setNonZero(out, "server", m.Server)
	setNonZero(out, "config_source", m.ConfigSource)
	setNonZero(out, "env_key", m.EnvKey)
	setNonZero(out, "capability", m.Capability)
	setNonZero(out, "capability_labels", m.CapabilityLabels)
	setNonZero(out, "confidence", m.Confidence)
	setNonZero(out, "tool", m.Tool)
	setNonZero(out, "endpoint", m.Endpoint)
	setNonZero(out, "mode", m.Mode)
	setNonZero(out, "target_alias", m.TargetAlias)
	return out
}

// OpenAICompatMetadata holds metadata from OpenAI-compatible API exploit findings.
type OpenAICompatMetadata struct {
	Module          string `json:"module,omitempty"`
	Action          string `json:"action,omitempty"`
	Provider        string `json:"provider,omitempty"`
	Model           string `json:"model,omitempty"`
	Version         string `json:"version,omitempty"`
	AcceptanceClass string `json:"acceptance_class,omitempty"`
	AuthPattern     string `json:"auth_pattern,omitempty"`
	CoherenceScore  string `json:"coherence_score,omitempty"`
	RateLimitSignal string `json:"rate_limit_signal,omitempty"`
	ThroughputScore string `json:"throughput_score,omitempty"`
	ValueScore      string `json:"value_score,omitempty"`
}

func (m OpenAICompatMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "module", m.Module)
	setNonZero(out, "action", m.Action)
	setNonZero(out, "provider", m.Provider)
	setNonZero(out, "model", m.Model)
	setNonZero(out, "version", m.Version)
	setNonZero(out, "acceptance_class", m.AcceptanceClass)
	setNonZero(out, "auth_pattern", m.AuthPattern)
	setNonZero(out, "coherence_score", m.CoherenceScore)
	setNonZero(out, "rate_limit_signal", m.RateLimitSignal)
	setNonZero(out, "throughput_score", m.ThroughputScore)
	setNonZero(out, "value_score", m.ValueScore)
	return out
}

// RayMetadata holds metadata from Ray exploit findings.
type RayMetadata struct {
	Module        string `json:"module,omitempty"`
	Action        string `json:"action,omitempty"`
	Provider      string `json:"provider,omitempty"`
	Version       string `json:"version,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	JobID         string `json:"job_id,omitempty"`
	Mutating      bool   `json:"mutating,omitempty"`
	RiskLabel     string `json:"risk_label,omitempty"`
	PayloadPreset string `json:"payload_preset,omitempty"`
	Stage         string `json:"stage,omitempty"`
	Landed        string `json:"landed,omitempty"`
}

func (m RayMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "module", m.Module)
	setNonZero(out, "action", m.Action)
	setNonZero(out, "provider", m.Provider)
	setNonZero(out, "version", m.Version)
	setNonZero(out, "endpoint", m.Endpoint)
	setNonZero(out, "job_id", m.JobID)
	if m.Mutating {
		out["mutating"] = true
	}
	setNonZero(out, "risk_label", m.RiskLabel)
	setNonZero(out, "payload_preset", m.PayloadPreset)
	setNonZero(out, "stage", m.Stage)
	setNonZero(out, "landed", m.Landed)
	return out
}

// MLflowMetadata holds metadata from MLflow exploit findings.
type MLflowMetadata struct {
	Module       string `json:"module,omitempty"`
	Action       string `json:"action,omitempty"`
	Provider     string `json:"provider,omitempty"`
	Version      string `json:"version,omitempty"`
	Experiment   string `json:"experiment,omitempty"`
	RunID        string `json:"run_id,omitempty"`
	ArtifactPath string `json:"artifact_path,omitempty"`
	ArtifactKind string `json:"artifact_kind,omitempty"`
}

func (m MLflowMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "module", m.Module)
	setNonZero(out, "action", m.Action)
	setNonZero(out, "provider", m.Provider)
	setNonZero(out, "version", m.Version)
	setNonZero(out, "experiment", m.Experiment)
	setNonZero(out, "run_id", m.RunID)
	setNonZero(out, "artifact_path", m.ArtifactPath)
	setNonZero(out, "artifact_kind", m.ArtifactKind)
	return out
}

// GradioMetadata holds metadata from Gradio exploit findings.
type GradioMetadata struct {
	Module       string `json:"module,omitempty"`
	Action       string `json:"action,omitempty"`
	Provider     string `json:"provider,omitempty"`
	Version      string `json:"version,omitempty"`
	FnIndex      int    `json:"fn_index,omitempty"`
	QueueEnabled bool   `json:"queue_enabled,omitempty"`
	FileInput    string `json:"file_input,omitempty"`
	FileOutput   string `json:"file_output,omitempty"`
}

func (m GradioMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "module", m.Module)
	setNonZero(out, "action", m.Action)
	setNonZero(out, "provider", m.Provider)
	setNonZero(out, "version", m.Version)
	if m.FnIndex != 0 {
		out["fn_index"] = m.FnIndex
	}
	if m.QueueEnabled {
		out["queue_enabled"] = true
	}
	setNonZero(out, "file_input", m.FileInput)
	setNonZero(out, "file_output", m.FileOutput)
	return out
}

// VulnCheckMetadata holds metadata from vulncheck template findings.
type VulnCheckMetadata struct {
	Template string `json:"template,omitempty"`
	Tags     string `json:"tags,omitempty"`
}

func (m VulnCheckMetadata) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	setNonZero(out, "template", m.Template)
	setNonZero(out, "tags", m.Tags)
	return out
}

func setNonZero(m map[string]interface{}, key, value string) {
	if value != "" {
		m[key] = value
	}
}
