package report

import (
	"testing"
)

func TestSetNonZero(t *testing.T) {
	m := make(map[string]interface{})
	setNonZero(m, "a", "val")
	setNonZero(m, "b", "")
	if m["a"] != "val" {
		t.Fatal("expected key a")
	}
	if _, ok := m["b"]; ok {
		t.Fatal("empty string should be omitted")
	}
}

func TestFingerprintMetadataToMap(t *testing.T) {
	m := FingerprintMetadata{
		Service: "ollama", Host: "10.0.0.1", Port: 11434,
		Specificity: 90, Confidence: "high", MatchKind: "header",
		ProxyLikely: true, MatchedProbes: []string{"p1", "p2"},
		AmbiguityReason: "none", Version: "0.3.0",
	}
	out := m.ToMap()
	for _, key := range []string{"service", "host", "confidence", "match_kind", "ambiguity_reason", "version"} {
		if _, ok := out[key]; !ok {
			t.Errorf("expected key %q", key)
		}
	}
	if out["port"] != 11434 {
		t.Error("expected port=11434")
	}
	if out["proxy_likely"] != true {
		t.Error("expected proxy_likely=true")
	}
	probes := out["matched_probes"].([]string)
	if len(probes) != 2 {
		t.Error("expected 2 probes")
	}

	empty := FingerprintMetadata{}.ToMap()
	if len(empty) != 0 {
		t.Errorf("empty struct should produce empty map, got %v", empty)
	}
}

func TestOllamaMetadataToMap(t *testing.T) {
	m := OllamaMetadata{Module: "ollama", Action: "enum", Model: "llama3", Mutating: true}
	out := m.ToMap()
	if out["module"] != "ollama" || out["mutating"] != true {
		t.Error("unexpected map")
	}
	empty := OllamaMetadata{}.ToMap()
	if _, ok := empty["mutating"]; ok {
		t.Error("false mutating should be omitted")
	}
}

func TestVectorDBMetadataToMap(t *testing.T) {
	m := VectorDBMetadata{Provider: "chromadb", Collection: "docs"}.ToMap()
	if m["provider"] != "chromadb" || m["collection"] != "docs" {
		t.Error("unexpected map")
	}
}

func TestJupyterMetadataToMap(t *testing.T) {
	m := JupyterMetadata{Module: "jupyter", Kernel: "python3"}.ToMap()
	if m["module"] != "jupyter" || m["kernel"] != "python3" {
		t.Error("unexpected map")
	}
}

func TestMCPMetadataToMap(t *testing.T) {
	m := MCPMetadata{
		Module: "mcp", Action: "enum", Transport: "http",
		Server: "acme", Tool: "exec", Endpoint: "/msg",
	}.ToMap()
	for _, k := range []string{"module", "action", "transport", "server", "tool", "endpoint"} {
		if _, ok := m[k]; !ok {
			t.Errorf("expected key %q", k)
		}
	}
}

func TestOpenAICompatMetadataToMap(t *testing.T) {
	m := OpenAICompatMetadata{Module: "openai-compat", AcceptanceClass: "inference-capable"}.ToMap()
	if m["acceptance_class"] != "inference-capable" {
		t.Error("unexpected acceptance_class")
	}
}

func TestRayMetadataToMap(t *testing.T) {
	m := RayMetadata{Module: "ray", JobID: "j-1", Mutating: true, Landed: "execution-confirmed"}.ToMap()
	if m["job_id"] != "j-1" || m["mutating"] != true || m["landed"] != "execution-confirmed" {
		t.Error("unexpected map")
	}
}

func TestMLflowMetadataToMap(t *testing.T) {
	m := MLflowMetadata{Module: "mlflow", RunID: "r-1", ArtifactPath: "model/"}.ToMap()
	if m["run_id"] != "r-1" || m["artifact_path"] != "model/" {
		t.Error("unexpected map")
	}
}

func TestGradioMetadataToMap(t *testing.T) {
	m := GradioMetadata{Module: "gradio", FnIndex: 3, QueueEnabled: true, FileInput: "upload"}.ToMap()
	if m["fn_index"] != 3 || m["queue_enabled"] != true || m["file_input"] != "upload" {
		t.Error("unexpected map")
	}
	empty := GradioMetadata{}.ToMap()
	if _, ok := empty["fn_index"]; ok {
		t.Error("zero fn_index should be omitted")
	}
}

func TestVulnCheckMetadataToMap(t *testing.T) {
	m := VulnCheckMetadata{Template: "ollama-detect-001", Tags: "ollama,detection"}.ToMap()
	if m["template"] != "ollama-detect-001" || m["tags"] != "ollama,detection" {
		t.Error("unexpected map")
	}
}
