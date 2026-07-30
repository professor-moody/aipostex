package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindTemplateByIDRequiresExactMatch(t *testing.T) {
	engine, err := loadTemplateEngine()
	if err != nil {
		t.Fatalf("loading template engine: %v", err)
	}

	if _, ok := findTemplateByID(engine.Templates, "mcp-auth-001-unauthenticated-sse"); !ok {
		t.Fatal("expected exact template id match")
	}
	if _, ok := findTemplateByID(engine.Templates, "mcp-auth-001"); ok {
		t.Fatal("did not expect partial template id match")
	}
}

func TestLoadTemplateEnginePrefersAdditionalTemplateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "override.yaml")
	content := `id: mcp-auth-001-unauthenticated-sse
info:
  name: "Override Template"
  severity: high
  author: test
  description: "override"
checks:
  - name: "override"
    method: GET
    path: /
    matchers:
      - type: status
        value: "200"
    finding:
      title: "Override"
      description: "Override"
`
	if err := os.WriteFile(templatePath, []byte(content), 0o600); err != nil {
		t.Fatalf("writing override template: %v", err)
	}

	prev := scanTemplDir
	scanTemplDir = tmpDir
	defer func() { scanTemplDir = prev }()

	engine, err := loadTemplateEngine()
	if err != nil {
		t.Fatalf("loading template engine: %v", err)
	}

	tmpl, ok := findTemplateByID(engine.Templates, "mcp-auth-001-unauthenticated-sse")
	if !ok {
		t.Fatal("expected template to be found")
	}
	if tmpl.Info.Name != "Override Template" {
		t.Fatalf("expected override template to win, got %q", tmpl.Info.Name)
	}
	if tmpl.SourcePath != templatePath {
		t.Fatalf("expected source path %q, got %q", templatePath, tmpl.SourcePath)
	}
}

func TestWriteTemplateInfoIncludesSourceAndChecks(t *testing.T) {
	engine, err := loadTemplateEngine()
	if err != nil {
		t.Fatalf("loading template engine: %v", err)
	}

	tmpl, ok := findTemplateByID(engine.Templates, "mcp-auth-001-unauthenticated-sse")
	if !ok {
		t.Fatal("expected template to be found")
	}

	var out strings.Builder
	writeTemplateInfo(&out, tmpl)
	rendered := out.String()

	for _, expected := range []string{
		"ID: mcp-auth-001-unauthenticated-sse",
		"Name: MCP Server - Unauthenticated SSE Access",
		"Source:",
		"Detect Steps: 1",
		"Checks:",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected output to contain %q, got %q", expected, rendered)
		}
	}
}

func TestRunTemplateInfoKnownTemplate(t *testing.T) {
	withTestConfig(t, func() {
		err := runTemplateInfo(nil, []string{"mcp-auth-001-unauthenticated-sse"})
		if err != nil {
			t.Fatalf("runTemplateInfo returned error for known template: %v", err)
		}
	})
}

func TestRunTemplateInfoUnknownTemplate(t *testing.T) {
	withTestConfig(t, func() {
		err := runTemplateInfo(nil, []string{"nonexistent-template-id-xyz"})
		if err == nil {
			t.Fatal("expected error for unknown template id")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Fatalf("expected 'not found' in error, got %v", err)
		}
	})
}

func TestLoadTemplateEngineIncludesNewBuiltinTemplateFamilies(t *testing.T) {
	engine, err := loadTemplateEngine()
	if err != nil {
		t.Fatalf("loading template engine: %v", err)
	}

	for _, id := range []string{
		"weaviate-auth-001-unauthenticated-api",
		"qdrant-auth-001-unauthenticated-api",
		"jupyter-auth-002-terminals-exposed",
		"openai-auth-001-unauthenticated-inference",
		"mcp-auth-002-unauthenticated-http",
	} {
		if _, ok := findTemplateByID(engine.Templates, id); !ok {
			t.Fatalf("expected built-in template %q to be loaded", id)
		}
	}
}
