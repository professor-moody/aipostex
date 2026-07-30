package credchain

import (
	"strings"
	"testing"
)

// Regression: GenerateChainActions feeds copy-paste command lists (report view
// --commands and the dossier commands.sh). The rag-verify generator used to
// fabricate a `vectordb --target <vectordb-target> ... --collection <collection>`
// command when only an LLM key (no vectordb key) was looted — a command pointed
// at nothing that leaked into the loot Commands section. It must not emit a
// target it never discovered.

// LLM key present, no vectordb key discovered -> no rag-verify command at all
// (no fabricated <vectordb-target>).
func TestRAGVerifyNoFabricatedTarget(t *testing.T) {
	store := NewStore()
	store.Add("172.16.50.20:8265", Credential{Type: "openai-api-key", Value: "sk-lab-FAKE-openai-key"})

	for _, a := range GenerateChainActions(store) {
		if strings.Contains(a.Command, "rag-verify") {
			t.Errorf("rag-verify must not surface without a discovered vectordb target, got: %q", a.Command)
		}
		if strings.Contains(a.Command, "<vectordb-target>") {
			t.Errorf("no command may carry a fabricated <vectordb-target>, got: %q", a.Command)
		}
	}
}

// A concrete vectordb key + an LLM key SHOULD still yield the rag-verify chain
// step (the target is real; only the <collection> detail is left to fill, the
// same intentional pattern as the wandb secrets action).
func TestRAGVerifyEmittedWithConcreteTarget(t *testing.T) {
	store := NewStore()
	store.Add("172.16.50.20:8000", Credential{Type: "api-key", Value: "vdb-FAKE-key"})
	store.Add("172.16.50.20:4000", Credential{Type: "openai-api-key", Value: "sk-lab-FAKE-openai-key"})

	var got bool
	for _, a := range GenerateChainActions(store) {
		if strings.Contains(a.Command, "rag-verify") {
			got = true
			if strings.Contains(a.Command, "<vectordb-target>") {
				t.Errorf("rag-verify target must be the discovered one, not a placeholder: %q", a.Command)
			}
			if !strings.Contains(a.Command, "http://172.16.50.20:8000") {
				t.Errorf("rag-verify must target the discovered vectordb, got: %q", a.Command)
			}
		}
	}
	if !got {
		t.Error("expected a rag-verify chain action when a concrete vectordb key + LLM key are looted")
	}
}
