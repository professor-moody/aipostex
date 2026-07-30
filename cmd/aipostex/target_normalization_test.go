package main

import "testing"

func TestExploitClientFactoriesNormalizeTargetsAtCommandBoundary(t *testing.T) {
	t.Run("openai-compat", func(t *testing.T) {
		prev := openAICompatTarget
		defer func() { openAICompatTarget = prev }()
		openAICompatTarget = "127.0.0.1:8000"
		if _, _, err := newOpenAICompatClient(); err != nil {
			t.Fatalf("newOpenAICompatClient returned error: %v", err)
		}
		if openAICompatTarget != "http://127.0.0.1:8000" {
			t.Fatalf("expected normalized target, got %q", openAICompatTarget)
		}
	})

	t.Run("mcp", func(t *testing.T) {
		prevTarget := mcpTarget
		prevTransport := mcpTransport
		defer func() {
			mcpTarget = prevTarget
			mcpTransport = prevTransport
		}()
		mcpTransport = "http"
		mcpTarget = "127.0.0.1:3000/message"
		if _, err := newMCPClient(); err != nil {
			t.Fatalf("newMCPClient returned error: %v", err)
		}
		if mcpTarget != "http://127.0.0.1:3000/message" {
			t.Fatalf("expected normalized target, got %q", mcpTarget)
		}
	})

	t.Run("ollama", func(t *testing.T) {
		prev := ollamaTarget
		defer func() { ollamaTarget = prev }()
		ollamaTarget = "127.0.0.1:11434"
		if _, _, err := newOllamaClient(); err != nil {
			t.Fatalf("newOllamaClient returned error: %v", err)
		}
		if ollamaTarget != "http://127.0.0.1:11434" {
			t.Fatalf("expected normalized target, got %q", ollamaTarget)
		}
	})

	t.Run("jupyter", func(t *testing.T) {
		prev := jupyterTarget
		defer func() { jupyterTarget = prev }()
		jupyterTarget = "127.0.0.1:8888"
		if _, err := newJupyterClient(); err != nil {
			t.Fatalf("newJupyterClient returned error: %v", err)
		}
		if jupyterTarget != "http://127.0.0.1:8888" {
			t.Fatalf("expected normalized target, got %q", jupyterTarget)
		}
	})

	t.Run("gradio", func(t *testing.T) {
		prev := gradioTarget
		defer func() { gradioTarget = prev }()
		gradioTarget = "127.0.0.1:7860"
		if _, _, err := newGradioClient(); err != nil {
			t.Fatalf("newGradioClient returned error: %v", err)
		}
		if gradioTarget != "http://127.0.0.1:7860" {
			t.Fatalf("expected normalized target, got %q", gradioTarget)
		}
	})

	t.Run("ray", func(t *testing.T) {
		prev := rayTarget
		defer func() { rayTarget = prev }()
		rayTarget = "127.0.0.1:8265"
		if _, _, err := newRayClient(); err != nil {
			t.Fatalf("newRayClient returned error: %v", err)
		}
		if rayTarget != "http://127.0.0.1:8265" {
			t.Fatalf("expected normalized target, got %q", rayTarget)
		}
	})

	t.Run("mlflow", func(t *testing.T) {
		prev := mlflowTarget
		defer func() { mlflowTarget = prev }()
		mlflowTarget = "127.0.0.1:5000"
		if _, _, err := newMLflowClient(); err != nil {
			t.Fatalf("newMLflowClient returned error: %v", err)
		}
		if mlflowTarget != "http://127.0.0.1:5000" {
			t.Fatalf("expected normalized target, got %q", mlflowTarget)
		}
	})

	t.Run("vectordb", func(t *testing.T) {
		prevTarget := vdbTarget
		prevType := vdbType
		defer func() {
			vdbTarget = prevTarget
			vdbType = prevType
		}()
		vdbType = "chromadb"
		vdbTarget = "127.0.0.1:8000"
		if _, _, err := newVDBClient(); err != nil {
			t.Fatalf("newVDBClient returned error: %v", err)
		}
		if vdbTarget != "http://127.0.0.1:8000" {
			t.Fatalf("expected normalized target, got %q", vdbTarget)
		}
	})
}
