package vulncheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMatchesSeverityConsidersEachCheckEffectiveSeverity(t *testing.T) {
	tmpl := &Template{
		ID: "mixed",
		Info: TemplateInfo{
			Name:     "Mixed",
			Severity: "critical",
			Author:   "t",
		},
		Checks: []Check{
			{Name: "a", Method: "GET", Path: "/", Severity: "medium"},
		},
	}
	if !tmpl.MatchesSeverity([]string{"medium"}) {
		t.Fatal("expected --severity medium to include template with a medium-severity check")
	}
	inherited := &Template{
		ID: "inherit",
		Info: TemplateInfo{
			Name:     "Inherit",
			Severity: "info",
			Author:   "t",
		},
		Checks: []Check{
			{Name: "a", Method: "GET", Path: "/"},
		},
	}
	if !inherited.MatchesSeverity([]string{"info"}) {
		t.Fatal("expected check with empty severity to inherit template severity for filtering")
	}
	tmpl2 := &Template{
		ID: "low-check-only",
		Info: TemplateInfo{
			Name:     "X",
			Severity: "critical",
			Author:   "t",
		},
		Checks: []Check{
			{Name: "a", Method: "GET", Path: "/", Severity: "low"},
		},
	}
	if !tmpl2.MatchesSeverity([]string{"low"}) {
		t.Fatal("expected --severity low to match lower per-check severity under higher template severity")
	}
}

func TestTemplateValidateRejectsMalformedMatchersAndExtractors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Template)
		wantErr string
	}{
		{
			name: "invalid matcher type",
			mutate: func(tmpl *Template) {
				tmpl.Checks[0].Matchers[0] = Matcher{Type: "wat", Value: "200"}
			},
			wantErr: `unsupported matcher type "wat"`,
		},
		{
			name: "header matcher missing key",
			mutate: func(tmpl *Template) {
				tmpl.Checks[0].Matchers[0] = Matcher{Type: MatchHeaderContains, Value: "json"}
			},
			wantErr: "missing header key",
		},
		{
			name: "json path matcher missing key",
			mutate: func(tmpl *Template) {
				tmpl.Checks[0].Matchers[0] = Matcher{Type: MatchJSONPath}
			},
			wantErr: "missing json path key",
		},
		{
			name: "invalid extractor type",
			mutate: func(tmpl *Template) {
				tmpl.Checks[0].Extractors = []Extractor{{Type: "wat", Name: "x"}}
			},
			wantErr: `unsupported extractor type "wat"`,
		},
		{
			name: "regex extractor missing pattern",
			mutate: func(tmpl *Template) {
				tmpl.Checks[0].Extractors = []Extractor{{Type: "regex", Name: "x"}}
			},
			wantErr: "missing regex",
		},
		{
			name: "invalid check severity",
			mutate: func(tmpl *Template) {
				tmpl.Checks[0].Severity = "urgent"
			},
			wantErr: "invalid severity 'urgent'",
		},
		{
			name: "missing finding title",
			mutate: func(tmpl *Template) {
				tmpl.Checks[0].Finding.Title = ""
			},
			wantErr: "missing finding.title",
		},
		{
			name: "empty matcher list",
			mutate: func(tmpl *Template) {
				tmpl.Checks[0].Matchers = nil
			},
			wantErr: "has no matchers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := validTemplate()
			tt.mutate(tmpl)

			err := tmpl.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestLoadTemplatesWarnsAndOverridesDuplicateIDs(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	file1 := filepath.Join(dir1, "one.yaml")
	file2 := filepath.Join(dir2, "two.yaml")
	if err := os.WriteFile(file1, []byte(validTemplateYAML("Duplicate One")), 0o600); err != nil {
		t.Fatalf("writing template one: %v", err)
	}
	if err := os.WriteFile(file2, []byte(validTemplateYAML("Duplicate Two")), 0o600); err != nil {
		t.Fatalf("writing template two: %v", err)
	}

	engine := NewEngine(time.Second, 1)
	if err := engine.LoadTemplates(dir1, dir2); err != nil {
		t.Fatalf("LoadTemplates returned error: %v", err)
	}
	if len(engine.Templates) != 1 {
		t.Fatalf("expected 1 template after dedupe, got %d", len(engine.Templates))
	}

	tmpl := engine.Templates[0]
	if tmpl.Info.Name != "Duplicate Two" {
		t.Fatalf("expected later template to win, got %q", tmpl.Info.Name)
	}
	if tmpl.SourcePath != file2 {
		t.Fatalf("expected source path %q, got %q", file2, tmpl.SourcePath)
	}
}

func validTemplate() *Template {
	return &Template{
		ID: "test-template",
		Info: TemplateInfo{
			Name:        "Test Template",
			Severity:    "high",
			Author:      "test",
			Description: "test",
		},
		Checks: []Check{
			{
				Name:   "check",
				Method: "GET",
				Path:   "/",
				Matchers: []Matcher{
					{Type: MatchStatus, Value: "200"},
				},
				Finding: FindingTemplate{
					Title:       "title",
					Description: "description",
				},
			},
		},
	}
}

func validTemplateYAML(name string) string {
	return `id: duplicate-template
info:
  name: "` + name + `"
  severity: high
  author: test
  description: "test"
checks:
  - name: "check"
    method: GET
    path: /
    matchers:
      - type: status
        value: "200"
    finding:
      title: "title"
      description: "description"
`
}

func TestBuiltinMCPTemplatesCoverInspectorAndDNSRebinding(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "mcp", "mcp-auth-003-inspector-exposed.yaml"),
		filepath.Join("templates", "mcp", "mcp-auth-005-inspector-api-exposed.yaml"),
		filepath.Join("templates", "mcp", "mcp-auth-004-dns-rebinding-host-header.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if tmpl.SourcePath == "" {
			t.Fatalf("expected source path for %q", relativePath)
		}
	}
}

func TestBuiltinServiceTemplatesCoverRayMLflowAndGradio(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "ray", "ray-auth-001-unauthenticated-dashboard.yaml"),
		filepath.Join("templates", "ray", "ray-auth-002-jobs-api-exposed.yaml"),
		filepath.Join("templates", "ray", "ray-enum-003-cluster-status-exposed.yaml"),
		filepath.Join("templates", "ray", "ray-exploit-002-job-logs-exposed.yaml"),
		filepath.Join("templates", "mlflow", "mlflow-auth-001-unauthenticated-tracking.yaml"),
		filepath.Join("templates", "mlflow", "mlflow-enum-002-artifact-surface.yaml"),
		filepath.Join("templates", "mlflow", "mlflow-enum-003-registry-surface.yaml"),
		filepath.Join("templates", "gradio", "gradio-auth-001-config-exposed.yaml"),
		filepath.Join("templates", "gradio", "gradio-enum-002-callable-api-surface.yaml"),
		filepath.Join("templates", "gradio", "gradio-enum-003-file-capable-surface.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if tmpl.SourcePath == "" {
			t.Fatalf("expected source path for %q", relativePath)
		}
	}
}

func TestBuiltinBalancedAISurfaceTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "ollama", "ollama-enum-003-model-metadata-surface.yaml"),
		filepath.Join("templates", "ollama", "ollama-exploit-004-unauthenticated-generate.yaml"),
		filepath.Join("templates", "openai", "openai-auth-002-model-inventory-exposed.yaml"),
		filepath.Join("templates", "openai", "openai-exploit-003-placeholder-key-chat-completions.yaml"),
		filepath.Join("templates", "jupyter", "jupyter-enum-003-kernelspecs-exposed.yaml"),
		filepath.Join("templates", "jupyter", "jupyter-exploit-002-contents-read.yaml"),
		filepath.Join("templates", "triton", "triton-enum-003-metrics-exposed.yaml"),
		filepath.Join("templates", "huggingface", "hf-tgi-enum-002-metrics-exposed.yaml"),
		filepath.Join("templates", "huggingface", "hf-tei-enum-002-metrics-exposed.yaml"),
		filepath.Join("templates", "langchain", "langserve-enum-002-schema-exposed.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestLoadEmbeddedTemplatesIncludesInspectorTemplate(t *testing.T) {
	templates, err := LoadEmbeddedTemplates()
	if err != nil {
		t.Fatalf("LoadEmbeddedTemplates returned error: %v", err)
	}
	found := false
	apiFound := false
	rayFound := false
	mlflowFound := false
	gradioFound := false
	openAIDetectionFound := false
	openAIExploitFound := false
	openAIToolExploitFound := false
	openAIPromptExploitFound := false
	ollamaDetectionFound := false
	ollamaExploitFound := false
	jupyterDetectionFound := false
	jupyterExploitFound := false
	tritonMetricsFound := false
	hfTGIMetricsFound := false
	hfTEIMetricsFound := false
	langserveSchemaFound := false
	for _, tmpl := range templates {
		if tmpl.ID == "mcp-auth-003-inspector-exposed" {
			found = true
		}
		if tmpl.ID == "mcp-auth-005-inspector-api-exposed" {
			apiFound = true
		}
		if tmpl.ID == "ray-auth-001-unauthenticated-dashboard" {
			rayFound = true
		}
		if tmpl.ID == "mlflow-auth-001-unauthenticated-tracking" {
			mlflowFound = true
		}
		if tmpl.ID == "gradio-auth-001-config-exposed" {
			gradioFound = true
		}
		if tmpl.ID == "openai-auth-002-model-inventory-exposed" {
			openAIDetectionFound = true
		}
		if tmpl.ID == "openai-exploit-003-placeholder-key-chat-completions" {
			openAIExploitFound = true
		}
		if tmpl.ID == "openai-exploit-004-tool-injection" {
			openAIToolExploitFound = true
		}
		if tmpl.ID == "openai-exploit-005-prompt-injection" {
			openAIPromptExploitFound = true
		}
		if tmpl.ID == "ollama-enum-003-model-metadata-surface" {
			ollamaDetectionFound = true
		}
		if tmpl.ID == "ollama-exploit-004-unauthenticated-generate" {
			ollamaExploitFound = true
		}
		if tmpl.ID == "jupyter-enum-003-kernelspecs-exposed" {
			jupyterDetectionFound = true
		}
		if tmpl.ID == "jupyter-exploit-002-contents-read" {
			jupyterExploitFound = true
		}
		if tmpl.ID == "triton-enum-003-metrics-exposed" {
			tritonMetricsFound = true
		}
		if tmpl.ID == "hf-tgi-enum-002-metrics-exposed" {
			hfTGIMetricsFound = true
		}
		if tmpl.ID == "hf-tei-enum-002-metrics-exposed" {
			hfTEIMetricsFound = true
		}
		if tmpl.ID == "langserve-enum-002-schema-exposed" {
			langserveSchemaFound = true
		}
	}
	if !found {
		t.Fatal("expected embedded inspector template to be present")
	}
	if !apiFound {
		t.Fatal("expected embedded inspector API template to be present")
	}
	if !rayFound {
		t.Fatal("expected embedded ray template to be present")
	}
	if !mlflowFound {
		t.Fatal("expected embedded mlflow template to be present")
	}
	if !gradioFound {
		t.Fatal("expected embedded gradio template to be present")
	}
	if !openAIDetectionFound || !openAIExploitFound || !openAIToolExploitFound || !openAIPromptExploitFound {
		t.Fatal("expected embedded openai detection/exploit templates to be present")
	}
	if !ollamaDetectionFound || !ollamaExploitFound {
		t.Fatal("expected embedded ollama detection/exploit templates to be present")
	}
	if !jupyterDetectionFound || !jupyterExploitFound {
		t.Fatal("expected embedded jupyter detection/exploit templates to be present")
	}
	if !tritonMetricsFound || !hfTGIMetricsFound || !hfTEIMetricsFound || !langserveSchemaFound {
		t.Fatal("expected embedded triton/huggingface/langserve expansion templates to be present")
	}
}

func TestBuiltinVulnerableMCPTemplatesCoverGaps(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "mcp", "mcp-session-001-session-id-in-url.yaml"),
		filepath.Join("templates", "mcp", "cve-2025-49596-inspector-rce.yaml"),
		filepath.Join("templates", "mcp", "cve-2025-66414-sdk-dns-rebinding.yaml"),
		filepath.Join("templates", "mcp", "cve-2025-53355-k8s-mcp-command-injection.yaml"),
		filepath.Join("templates", "mcp", "mcp-enum-006-neo4j-mcp-exposed.yaml"),
		filepath.Join("templates", "mcp", "tra-2025-36-ms-learn-mcp-ssrf.yaml"),
		filepath.Join("templates", "mcp", "cve-2025-53967-figma-mcp-rce.yaml"),
		filepath.Join("templates", "mcp", "cve-2025-59163-vet-mcp-dns-rebinding.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
		if tmpl.SourcePath == "" {
			t.Fatalf("expected source path for %q", relativePath)
		}
	}
}

func TestLoadEmbeddedTemplatesIncludesVulnerableMCPTemplates(t *testing.T) {
	templates, err := LoadEmbeddedTemplates()
	if err != nil {
		t.Fatalf("LoadEmbeddedTemplates returned error: %v", err)
	}

	want := map[string]bool{
		"mcp-session-001-session-id-in-url":        false,
		"cve-2025-49596-inspector-rce":             false,
		"cve-2025-66414-sdk-dns-rebinding":         false,
		"cve-2025-53355-k8s-mcp-command-injection": false,
		"mcp-enum-006-neo4j-mcp-exposed":           false,
		"tra-2025-36-ms-learn-mcp-ssrf":            false,
		"cve-2025-53967-figma-mcp-rce":             false,
		"cve-2025-59163-vet-mcp-dns-rebinding":     false,
	}

	for _, tmpl := range templates {
		if _, ok := want[tmpl.ID]; ok {
			want[tmpl.ID] = true
		}
	}

	for id, found := range want {
		if !found {
			t.Fatalf("expected embedded template %q to be present", id)
		}
	}
}

func TestBuiltinMCPToolVulnTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "mcp", "mcp-cmdi-001-execute-command-rce.yaml"),
		filepath.Join("templates", "mcp", "mcp-ssrf-001-fetch-url-ssrf.yaml"),
		filepath.Join("templates", "mcp", "mcp-path-001-read-file-traversal.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
		if tmpl.SourcePath == "" {
			t.Fatalf("expected source path for %q", relativePath)
		}
	}
}

func TestMCPCmdiTemplateHasCanaryCheck(t *testing.T) {
	tmpl, err := LoadTemplate(filepath.Join("templates", "mcp", "mcp-cmdi-001-execute-command-rce.yaml"))
	if err != nil {
		t.Fatalf("LoadTemplate returned error: %v", err)
	}
	if len(tmpl.Detect) == 0 {
		t.Fatal("expected detect steps")
	}
	foundCanary := false
	for _, check := range tmpl.Checks {
		for _, m := range check.Matchers {
			if m.Type == MatchBodyContains && strings.Contains(m.Value, "AIPOSTEX_RCE_CANARY") {
				foundCanary = true
			}
		}
	}
	if !foundCanary {
		t.Fatal("expected at least one check to match canary string")
	}
}

func TestMCPToolVulnTemplatesIncludedInEmbedded(t *testing.T) {
	templates, err := LoadEmbeddedTemplates()
	if err != nil {
		t.Fatalf("LoadEmbeddedTemplates returned error: %v", err)
	}

	want := map[string]bool{
		"mcp-cmdi-001-execute-command-rce": false,
		"mcp-ssrf-001-fetch-url-ssrf":      false,
		"mcp-path-001-read-file-traversal": false,
	}

	for _, tmpl := range templates {
		if _, ok := want[tmpl.ID]; ok {
			want[tmpl.ID] = true
		}
	}

	for id, found := range want {
		if !found {
			t.Fatalf("expected embedded template %q to be present", id)
		}
	}
}

func TestBizarreBazaarTemplateHasModelNameExtractor(t *testing.T) {
	tmpl, err := LoadTemplate(filepath.Join("templates", "campaign", "bizarre-bazaar-001-llmjacking-validation.yaml"))
	if err != nil {
		t.Fatalf("LoadTemplate returned error: %v", err)
	}
	if err := tmpl.Validate(); err != nil {
		t.Fatalf("template failed validation: %v", err)
	}
	foundExtractor := false
	for _, check := range tmpl.Checks {
		for _, e := range check.Extractors {
			if e.Name == "model_names" && e.Path == "models.#.name" {
				foundExtractor = true
			}
		}
	}
	if !foundExtractor {
		t.Fatal("expected Ollama check to have model_names extractor")
	}
}

func TestTemplateIsExploit(t *testing.T) {
	det := &Template{ID: "det", Info: TemplateInfo{Name: "d", Severity: "info", Author: "t", Description: "t"}}
	if det.IsExploit() {
		t.Fatal("default template should not be exploit")
	}

	det.Info.Type = TemplateTypeDetection
	if det.IsExploit() {
		t.Fatal("detection template should not be exploit")
	}

	exp := &Template{ID: "exp", Info: TemplateInfo{Name: "e", Type: TemplateTypeExploit, Severity: "high", Author: "t", Description: "t"}}
	if !exp.IsExploit() {
		t.Fatal("exploit template should return true for IsExploit()")
	}
}

func TestEmptyTypeDefaultsToDetection(t *testing.T) {
	tmpl := validTemplate()
	if tmpl.IsExploit() {
		t.Fatal("template with empty type should default to detection (not exploit)")
	}
}

func TestValidateRejectsUnknownType(t *testing.T) {
	tmpl := validTemplate()
	tmpl.Info.Type = "recon"
	err := tmpl.Validate()
	if err == nil {
		t.Fatal("expected validation error for unknown type")
	}
	if !strings.Contains(err.Error(), "invalid type") {
		t.Fatalf("expected 'invalid type' in error, got: %v", err)
	}
}

func TestValidateAcceptsValidTypes(t *testing.T) {
	for _, typ := range []string{"", "detection", "exploit", "Detection", "EXPLOIT"} {
		tmpl := validTemplate()
		tmpl.Info.Type = typ
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("type %q should be accepted, got: %v", typ, err)
		}
	}
}

func TestExploitTemplatesLoadAndValidate(t *testing.T) {
	templates, err := LoadEmbeddedTemplates()
	if err != nil {
		t.Fatalf("LoadEmbeddedTemplates returned error: %v", err)
	}
	exploitCount := 0
	for _, tmpl := range templates {
		if tmpl.IsExploit() {
			exploitCount++
		}
	}
	// The 2026-06 template-honesty audit downgraded ~20 detection-shaped CVE
	// templates (version/reachability probes for RCE CVEs that don't execute the
	// exploit) from info.type: exploit to detection, leaving the genuinely-active
	// templates classified as exploit.
	if exploitCount != 46 {
		t.Fatalf("expected 46 exploit templates, found %d", exploitCount)
	}
}

func TestBuiltinA2AAndLangServeExpansionTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "a2a", "a2a-enum-002-skills-exposed.yaml"),
		filepath.Join("templates", "a2a", "a2a-exploit-002-task-status-poll.yaml"),
		filepath.Join("templates", "a2a", "a2a-exploit-003-push-notification-hijack.yaml"),
		filepath.Join("templates", "a2a", "a2a-exploit-004-streaming-task-eavesdrop.yaml"),
		filepath.Join("templates", "a2a", "a2a-exploit-005-a2a-to-mcp-pivot.yaml"),
		filepath.Join("templates", "langchain", "langserve-exploit-002-memory-exposure.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestAllEmbeddedTemplatesParseAndValidate(t *testing.T) {
	templates, err := LoadEmbeddedTemplates()
	if err != nil {
		t.Fatalf("LoadEmbeddedTemplates returned error: %v", err)
	}
	if len(templates) != 131 {
		t.Fatalf("expected 131 embedded templates, got %d", len(templates))
	}
	for _, tmpl := range templates {
		if tmpl.ID == "" {
			t.Fatalf("template with empty ID (source: %s)", tmpl.SourcePath)
		}
		if tmpl.Info.Name == "" {
			t.Fatalf("template %q has empty Name", tmpl.ID)
		}
		if len(tmpl.Detect) == 0 && len(tmpl.Checks) == 0 {
			t.Fatalf("template %q has no detect steps and no checks", tmpl.ID)
		}
		hasCheck := len(tmpl.Checks) > 0
		hasDetect := len(tmpl.Detect) > 0
		if !hasCheck && !hasDetect {
			t.Fatalf("template %q must have at least one detect step or check", tmpl.ID)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", tmpl.ID, err)
		}
	}
}

func TestBuiltinBentoMLTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "bentoml", "bentoml-detect-001-unauth-inference.yaml"),
		filepath.Join("templates", "bentoml", "bentoml-detect-002-metrics-exposed.yaml"),
		filepath.Join("templates", "bentoml", "bentoml-detect-003-root-banner.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinWandbTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "wandb", "wandb-auth-001-unauthenticated-api.yaml"),
		filepath.Join("templates", "wandb", "wandb-enum-001-config-exposure.yaml"),
		filepath.Join("templates", "wandb", "wandb-enum-002-api-key-in-config.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinStreamlitTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "streamlit", "streamlit-auth-001-unauthenticated-app.yaml"),
		filepath.Join("templates", "streamlit", "streamlit-enum-001-health-metadata.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinLiteLLMTemplatesParseAndValidate(t *testing.T) {
	tmpl, err := LoadTemplate(filepath.Join("templates", "litellm", "litellm-config-001-endpoint-exposure.yaml"))
	if err != nil {
		t.Fatalf("LoadTemplate returned error: %v", err)
	}
	if err := tmpl.Validate(); err != nil {
		t.Fatalf("template failed validation: %v", err)
	}
}

func TestBuiltinKubeflowTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "kubeflow", "kubeflow-dashboard-unauth.yaml"),
		filepath.Join("templates", "kubeflow", "kubeflow-enum-001-pipeline-access.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinTFServingTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "tfserving", "tfserving-exploit-001-predict-abuse.yaml"),
		filepath.Join("templates", "tfserving", "tfserving-model-status.yaml"),
		filepath.Join("templates", "tfserving", "tfserving-unauth.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinTorchServeTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "torchserve", "torchserve-detect-002-mgmt-exposed.yaml"),
		filepath.Join("templates", "torchserve", "torchserve-exploit-001-model-register.yaml"),
		filepath.Join("templates", "torchserve", "torchserve-exploit-002-register-ssrf.yaml"),
		filepath.Join("templates", "torchserve", "torchserve-management.yaml"),
		filepath.Join("templates", "torchserve", "torchserve-unauth.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinTritonTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "triton", "triton-detect-002-shm-exposed.yaml"),
		filepath.Join("templates", "triton", "triton-detect-003-model-repo-access.yaml"),
		filepath.Join("templates", "triton", "triton-exploit-001-inference-abuse.yaml"),
		filepath.Join("templates", "triton", "triton-exploit-002-model-load.yaml"),
		filepath.Join("templates", "triton", "triton-model-enum.yaml"),
		filepath.Join("templates", "triton", "triton-unauth.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinVLLMTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "vllm", "ghsa-8fr4-5q9j-m8gm-vllm-automap-rce.yaml"),
		filepath.Join("templates", "vllm", "ghsa-mrw7-hf4f-83pf-vllm-deserialization-dos.yaml"),
		filepath.Join("templates", "vllm", "vllm-auth-001-unauthenticated-openai-compat.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinVectorDBTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "vectordb", "chroma-auth-001-unauthenticated-api.yaml"),
		filepath.Join("templates", "vectordb", "chromadb-exploit-001-data-exfil.yaml"),
		filepath.Join("templates", "vectordb", "milvus-detect-001-unauth-access.yaml"),
		filepath.Join("templates", "vectordb", "qdrant-auth-001-unauthenticated-api.yaml"),
		filepath.Join("templates", "vectordb", "qdrant-exploit-001-data-exfil.yaml"),
		filepath.Join("templates", "vectordb", "weaviate-auth-001-unauthenticated-api.yaml"),
		filepath.Join("templates", "vectordb", "weaviate-exploit-001-data-exfil.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinGradioExploitTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "gradio", "cve-2025-48889-gradio-file-copy.yaml"),
		filepath.Join("templates", "gradio", "gradio-exploit-001-file-read.yaml"),
		filepath.Join("templates", "gradio", "gradio-exploit-002-queue-enumerate.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestBuiltinHuggingFaceTemplatesParseAndValidate(t *testing.T) {
	for _, relativePath := range []string{
		filepath.Join("templates", "huggingface", "hf-tei-exploit-001-embedding-abuse.yaml"),
		filepath.Join("templates", "huggingface", "hf-tei-unauth.yaml"),
		filepath.Join("templates", "huggingface", "hf-tgi-exploit-001-inference-abuse.yaml"),
		filepath.Join("templates", "huggingface", "hf-tgi-unauth.yaml"),
	} {
		tmpl, err := LoadTemplate(relativePath)
		if err != nil {
			t.Fatalf("LoadTemplate(%q) returned error: %v", relativePath, err)
		}
		if err := tmpl.Validate(); err != nil {
			t.Fatalf("template %q failed validation: %v", relativePath, err)
		}
	}
}

func TestLoadTemplateInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: valid: yaml: {{{}"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	_, err := LoadTemplate(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Fatalf("expected parsing error, got: %v", err)
	}
}

func TestLoadTemplateMissingFile(t *testing.T) {
	_, err := LoadTemplate("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "reading") {
		t.Fatalf("expected reading error, got: %v", err)
	}
}

func TestLoadTemplateValidationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incomplete.yaml")
	yaml := `id: incomplete
info:
  name: ""
  severity: high
  author: test
  description: test
checks:
  - name: check
    method: GET
    path: /
    matchers:
      - type: status
        value: "200"
    finding:
      title: t
      description: d
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	_, err := LoadTemplate(path)
	if err == nil {
		t.Fatal("expected validation error for missing name")
	}
	if !strings.Contains(err.Error(), "validating") {
		t.Fatalf("expected validating error, got: %v", err)
	}
}

func TestValidateMatcherExhaustive(t *testing.T) {
	tests := []struct {
		name    string
		matcher Matcher
		wantErr string
	}{
		{"status empty value", Matcher{Type: MatchStatus, Value: ""}, "missing status value"},
		{"status non-numeric", Matcher{Type: MatchStatus, Value: "abc"}, "invalid status value"},
		{"body_contains empty", Matcher{Type: MatchBodyContains, Value: ""}, "missing value"},
		{"body_not_contains empty", Matcher{Type: MatchBodyNotContains, Value: ""}, "missing value"},
		{"body_regex empty", Matcher{Type: MatchBodyRegex, Value: ""}, "missing regex"},
		{"body_regex invalid", Matcher{Type: MatchBodyRegex, Value: "[invalid("}, "invalid regex"},
		{"header_contains no key", Matcher{Type: MatchHeaderContains, Key: "", Value: "x"}, "missing header key"},
		{"header_contains no value", Matcher{Type: MatchHeaderContains, Key: "X-Hdr", Value: ""}, "missing header value"},
		{"json_path no key", Matcher{Type: MatchJSONPath, Key: ""}, "missing json path key"},
		{"unknown type", Matcher{Type: "wat", Value: "x"}, "unsupported matcher type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMatcher("test", tc.matcher)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected %q in error, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateMatcherValid(t *testing.T) {
	valid := []Matcher{
		{Type: MatchStatus, Value: "200"},
		{Type: MatchBodyContains, Value: "ok"},
		{Type: MatchBodyNotContains, Value: "error"},
		{Type: MatchBodyRegex, Value: `\d+`},
		{Type: MatchHeaderContains, Key: "Server", Value: "nginx"},
		{Type: MatchJSONPath, Key: "result.id"},
		{Type: MatchJSONPath, Key: "result.id", Value: "abc"},
	}
	for _, m := range valid {
		if err := validateMatcher("test", m); err != nil {
			t.Fatalf("expected valid matcher %v to pass, got: %v", m, err)
		}
	}
}

func TestValidateTemplateRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Template)
		wantErr string
	}{
		{"missing id", func(t *Template) { t.ID = "" }, "missing 'id'"},
		{"missing severity", func(t *Template) { t.Info.Severity = "" }, "missing 'info.severity'"},
		{"invalid severity", func(t *Template) { t.Info.Severity = "banana" }, "invalid severity"},
		{"missing author", func(t *Template) { t.Info.Author = "" }, "missing 'info.author'"},
		{"missing description", func(t *Template) { t.Info.Description = "" }, "missing 'info.description'"},
		{"no checks", func(t *Template) { t.Checks = nil }, "has no checks"},
		{"check missing name", func(t *Template) { t.Checks[0].Name = "" }, "missing name"},
		{"check missing method", func(t *Template) { t.Checks[0].Method = "" }, "missing method"},
		{"check missing path", func(t *Template) { t.Checks[0].Path = "" }, "missing path"},
		{"missing finding description", func(t *Template) { t.Checks[0].Finding.Description = "" }, "missing finding.description"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := validTemplate()
			tc.mutate(tmpl)
			err := tmpl.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateExtractor(t *testing.T) {
	tests := []struct {
		name    string
		ext     Extractor
		wantErr string
	}{
		{"missing name", Extractor{Type: "json", Name: "", Path: "x"}, "missing name"},
		{"regex missing pattern", Extractor{Type: "regex", Name: "x"}, "missing regex"},
		{"regex invalid", Extractor{Type: "regex", Name: "x", Regex: "[bad("}, "invalid regex"},
		{"json missing path", Extractor{Type: "json", Name: "x"}, "missing path"},
		{"header missing path", Extractor{Type: "header", Name: "x"}, "missing path"},
		{"unknown type", Extractor{Type: "wat", Name: "x"}, "unsupported extractor type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExtractor("test", tc.ext)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestSeverityPriority(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"info", 0},
		{"unknown", -1},
		{"", -1},
	}
	for _, tc := range tests {
		t.Run(tc.sev, func(t *testing.T) {
			got := severityPriority(tc.sev)
			if got != tc.want {
				t.Errorf("severityPriority(%q) = %d, want %d", tc.sev, got, tc.want)
			}
		})
	}
}

func TestEngineStopsWhenContextCancelled(t *testing.T) {
	engine := NewEngine(time.Second, 1)
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	engine.Context = cancelledCtx
	if err := engine.AddTemplate(validTemplate()); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}

	findings, metrics, err := engine.ScanDetailed("http://127.0.0.1:1", nil, nil)
	if err != nil {
		t.Fatalf("ScanDetailed returned error: %v", err)
	}
	if len(findings) != 0 || metrics.RequestErrors != 0 {
		t.Fatalf("expected empty result after cancellation, got findings=%d metrics=%+v", len(findings), metrics)
	}
}
