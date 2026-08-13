package report

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding source modules
const (
	SourceFileDiscovery = "file-discovery"
	SourceFingerprint   = "fingerprint"
	SourceVulnCheck     = "vulncheck"
	SourceOllama        = "ollama"
	SourceVectorDB      = "vectordb"
	SourceMCP           = "mcp"
	SourceJupyter       = "jupyter"
	SourceOpenAICompat  = "openai-compat"
	SourceLiteLLM       = "litellm"
	SourceRay           = "ray"
	SourceMLflow        = "mlflow"
	SourceGradio        = "gradio"
	SourceBentoML       = "bentoml"
	SourceTriton        = "triton"
	SourceTorchServe    = "torchserve"
	SourceTFServing     = "tfserving"
	SourceA2A           = "a2a"
	SourceWandB         = "wandb"
	SourceHuggingFace   = "huggingface"
	SourceKubeflow      = "kubeflow"
	SourceK8s           = "k8s"
	SourceAgent         = "agent"
	SourceRAG           = "rag"
	SourceListener      = "listener"
	SourceCredential    = "credential"
	// SourceRequest tags a finding produced by the operator console `request`
	// primitive — a manual, operator-issued HTTP call through the tool.
	SourceRequest = "request"
)

// Finding represents a single security finding from any module
type Finding struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`                // Which module generated this
	TemplateID  string    `json:"template_id,omitempty"` // For vulncheck findings
	Target      string    `json:"target"`                // Host, URL, or file path
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss,omitempty"`
	Description string    `json:"description"`
	Remediation string    `json:"remediation,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	References  []string  `json:"references,omitempty"`

	// Metadata varies by source module
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// FindingCollection holds all findings from an engagement
type FindingCollection struct {
	EngagementID string    `json:"engagement_id"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time,omitempty"`
	Findings     []Finding `json:"findings"`
}

func NewCollection() *FindingCollection {
	return &FindingCollection{
		EngagementID: newEngagementID(),
		StartTime:    time.Now().UTC(),
		Findings:     make([]Finding, 0),
	}
}

func newEngagementID() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("eng-%d", time.Now().UTC().UnixNano())
	}
	return "eng-" + hex.EncodeToString(buf)
}

func (fc *FindingCollection) Add(f Finding) {
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now().UTC()
	}
	fc.Findings = append(fc.Findings, f)
}

func (fc *FindingCollection) ToJSON() ([]byte, error) {
	fc.EndTime = time.Now().UTC()
	return json.MarshalIndent(fc, "", "  ")
}

func NewFindingID(source string) string {
	uuid := randomUUIDv4()
	prefix := strings.TrimSpace(source)
	if prefix == "" {
		return uuid
	}
	return prefix + "-" + uuid
}

func randomUUIDv4() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%x", time.Now().UTC().UnixNano())
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return strings.Join([]string{
		hex.EncodeToString(buf[0:4]),
		hex.EncodeToString(buf[4:6]),
		hex.EncodeToString(buf[6:8]),
		hex.EncodeToString(buf[8:10]),
		hex.EncodeToString(buf[10:16]),
	}, "-")
}

// IsValidSeverity reports whether the given severity string is one of the
// recognized levels (critical, high, medium, low, info). The check is
// case-insensitive and trims whitespace.
func IsValidSeverity(sev string) bool {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

// moduleDisplayKeys maps each source to the metadata keys to show (in order)
// when rendering findings. Modules declare their own priority keys here so
// the console writer doesn't need hardcoded lists.
var moduleDisplayKeys = map[string][]string{
	SourceFingerprint: {"service", "host", "port", "match_kind", "confidence", "specificity", "ambiguity_reason", "proxy_likely"},
	SourceOllama:      {"module", "action", "provider", "model", "version", "model_count", "layer_count", "total_bytes", "bytes_read", "downloadable", "output_dir", "mutating", "payload_preset", "stage", "landed", "chain_source"},
	SourceVectorDB:    {"module", "action", "provider", "version", "collection", "collection_count", "count", "class", "sensitivity_hints", "artifact_kind", "mutating", "stage", "landed"},
	SourceJupyter:     {"module", "action", "provider", "kernel", "kernel_count", "path", "session_count", "version", "mutating", "stage", "landed"},
	SourceMCP: {"module", "action", "provider", "transport", "tool_count", "prompt_count", "resource_count", "tools_probed", "server_requests_observed", "auth_enforced", "issuer", "registration_endpoint", "client_id",
		"completion_ref", "argument", "completions_probed", "completions_disclosed", "log_level",
		"subscriptions_attempted", "subscriptions_accepted", "server", "config_source", "env_key", "capability", "capability_labels", "confidence", "tool", "prompt", "resource", "endpoint", "mode", "target_alias", "escaped", "escape_technique", "ssti_confirmed", "ssti_signal", "stage", "landed"},
	SourceOpenAICompat: {"module", "action", "provider", "model", "model_family", "model_vendor", "fingerprint_confidence", "cutoff_hint", "context_window_recalled", "version", "model_count", "accepted_pattern_count", "acceptance_class", "auth_pattern", "backend_failure_class", "coherence_score", "inference_verified", "rate_limit_signal", "throughput_score", "value_score", "status", "success", "max_tokens", "mutating", "stage", "landed"},
	SourceLiteLLM:      {"module", "action", "provider", "model", "version", "model_count", "coherence_score", "status", "success", "mutating", "stage", "landed"},
	SourceRay:          {"module", "action", "provider", "version", "endpoint", "job_id", "job_count", "env_var_count", "mutating", "risk_label", "payload_preset", "stage", "landed"},
	SourceMLflow:       {"module", "action", "provider", "version", "experiment", "experiment_count", "run_id", "run_count", "registry_count", "artifact_path", "artifact_count", "artifact_kind", "files_found", "bytes_read", "total_bytes", "failures", "bulk", "version_count", "stage", "landed"},
	SourceGradio:       {"module", "action", "provider", "version", "endpoint_count", "fn_index", "queue_enabled", "file_input", "file_output", "stage", "landed"},
	SourceBentoML:      {"module", "action", "provider", "version", "route_count", "endpoint", "model", "runner", "mutating", "stage", "landed"},
	SourceTriton:       {"module", "action", "provider", "version", "model", "model_count", "endpoint", "platform", "region_count", "mutating", "stage", "landed"},
	SourceTorchServe:   {"module", "action", "provider", "version", "model", "model_count", "endpoint", "handler", "mutating", "stage", "landed"},
	SourceTFServing:    {"module", "action", "provider", "version", "model", "model_count", "version_count", "signature_count", "endpoint", "signature", "mutating", "stage", "landed"},
	SourceA2A:          {"module", "action", "provider", "agent_name", "agent_version", "skill_count", "event_count", "task_id", "webhook_url", "preset", "mutating", "stage", "landed", "advertised_schemes", "no_auth_accepted", "bad_auth_accepted", "auth_enforcement", "integrity_mode", "integrity_signal", "bad_sig_accepted", "unsigned_accepted", "status_code", "spoof_id", "behavior_delta", "sender_validated", "peer_url", "delegation_depth", "outbound_attempted", "delegation_signal", "spoof_mode", "attacker_card_url", "card_fetched", "card_trust_signal", "callback_confirmed", "register_endpoint", "rogue_name", "rogue_url", "registration_accepted", "listed_in_registry"},
	SourceWandB:        {"module", "action", "entity", "project", "project_count", "version", "username", "admin", "run_count", "secret_count", "artifact_count", "mutating", "stage", "landed"},
	SourceHuggingFace:  {"module", "action", "provider", "service_type", "model_id", "revision", "version", "hub_base", "artifact_path", "artifact_kind", "files_found", "bytes_read", "total_bytes", "failures", "output_dir", "metric_lines", "input_count", "dimensions", "mutating", "stage", "landed"},
	SourceKubeflow:     {"module", "action", "provider", "api_version", "namespace", "pipeline_id", "pipeline_name", "pipeline_count", "run_id", "run_name", "run_count", "run_status", "experiment_id", "experiment_name", "experiment_count", "notebook", "mutating", "stage", "landed"},
	SourceK8s:          {"module", "action", "provider", "namespace", "namespace_count", "posture", "anon_accessible", "unauth_accessible", "authenticated", "can_write", "can_exec", "rule_count", "review_incomplete", "version", "workload", "kind", "image", "workload_count", "crd", "crd_kind", "crd_count", "secret_name", "key_count", "artifact", "artifact_source", "pod", "container", "command", "token_stolen", "escalation", "sa_can_write", "foothold_can_write", "mutating", "stage", "landed"},
	SourceVulnCheck:    {"stage", "landed", "scan_mode", "advisory_confidence", "affected_version", "server_name", "server_url", "transport_type"},
	SourceAgent:        {"module", "action", "endpoint", "method", "model_family", "model_vendor", "fingerprint_confidence", "cutoff_hint", "tool_count", "filter_detected", "filter_bypassed", "bypass_encoders", "leaked", "marker", "injected", "inject_framings", "control_refused", "broke", "break_step", "direct_refused", "turns", "session_scheme", "session_predictable", "session_present", "session_samples", "fragments", "reassembled", "secret_refused", "secret_leaked", "override_susceptible", "jailbreak_susceptible", "over_refusal", "mutating", "stage", "landed"},
	SourceRAG:          {"module", "action", "endpoint", "query", "source_count", "document_count", "documents", "sensitive_docs", "sensitive_hints", "poisoned", "poison_surfaced", "injection_obeyed", "obey_marker", "trigger_query", "mutating", "stage", "landed"},
}

// fallbackDisplayKeys are used when the source is not in moduleDisplayKeys.
var fallbackDisplayKeys = []string{
	"service", "match_kind", "confidence", "specificity", "provider", "module", "action", "transport",
	"capability", "capability_labels", "confidence", "model", "version",
	"collection", "class", "kernel", "tool", "endpoint", "path",
	"job_id", "experiment", "run_id", "artifact_path", "fn_index",
	"acceptance_class", "coherence_score", "throughput_score", "value_score",
	"artifact_kind", "queue_enabled", "file_input", "file_output",
	"stage", "landed", "chain_source",
}

// DisplayKeysForSource returns the ordered metadata keys to display for a given source.
func DisplayKeysForSource(source string) []string {
	if keys, ok := moduleDisplayKeys[source]; ok {
		return keys
	}
	return fallbackDisplayKeys
}

// NormalizeSeverity returns the canonical lowercase severity string.
// Unrecognized values are mapped to SeverityInfo.
func NormalizeSeverity(sev string) string {
	s := strings.ToLower(strings.TrimSpace(sev))
	if IsValidSeverity(s) {
		return s
	}
	return SeverityInfo
}

// Stats returns finding counts by severity. Severities are normalized
// so that unexpected or mixed-case values are folded into the canonical
// buckets rather than creating spurious map keys.
func (fc *FindingCollection) Stats() map[string]int {
	stats := map[string]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}
	for _, f := range fc.Findings {
		stats[NormalizeSeverity(f.Severity)]++
	}
	return stats
}
