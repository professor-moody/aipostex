package main

import (
	"reflect"
	"testing"

	"github.com/professor-moody/aipostex/internal/credchain"
)

func TestSplitToolInvocation(t *testing.T) {
	cases := []struct {
		in, tool, args string
	}{
		{`read_file {"path":"/etc/passwd"}`, "read_file", `{"path":"/etc/passwd"}`},
		{`list_tools`, "list_tools", ""},
		{`execute_command  {"cmd":"id"}`, "execute_command", `{"cmd":"id"}`},
		{`get_env`, "get_env", ""},
		{`run{"a":1}`, "run", `{"a":1}`},
	}
	for _, c := range cases {
		tool, args := splitToolInvocation(c.in)
		if tool != c.tool || args != c.args {
			t.Errorf("splitToolInvocation(%q)=(%q,%q), want (%q,%q)", c.in, tool, args, c.tool, c.args)
		}
	}
}

func TestParseToolArgs(t *testing.T) {
	got, err := parseToolArgs(`{"path":"/etc/passwd","n":3}`)
	if err != nil {
		t.Fatal(err)
	}
	if got["path"] != "/etc/passwd" {
		t.Errorf("path=%v", got["path"])
	}
	empty, err := parseToolArgs("")
	if err != nil || len(empty) != 0 {
		t.Errorf("empty args: %v %v", empty, err)
	}
	// Non-object JSON must be rejected — a bare null/array/scalar decodes into a nil
	// map without error if unmarshaled directly, so these must all error.
	for _, bad := range []string{"not json", "null", "[]", "42", `"str"`, "true"} {
		if _, err := parseToolArgs(bad); err == nil {
			t.Errorf("expected error for non-object args %q", bad)
		}
	}
}

func TestDedupeCredsPreferSpecificType(t *testing.T) {
	rec := func(typ, val string) credchain.CredentialRecord {
		return credchain.CredentialRecord{Type: typ, Value: val, TargetURL: "10.0.0.1:3000"}
	}
	// Same value classified three ways -> keep only the most specific.
	got := dedupeCredsPreferSpecificType([]credchain.CredentialRecord{
		rec("service-token", "sk-proj-abc"),
		rec("api-key", "sk-proj-abc"),
		rec("openai-api-key", "sk-proj-abc"),
	})
	if len(got) != 1 || got[0].Type != "openai-api-key" {
		t.Fatalf("expected only openai-api-key, got %v", got)
	}
	// api-key beats service-token when no concrete type exists.
	got = dedupeCredsPreferSpecificType([]credchain.CredentialRecord{
		rec("service-token", "x"), rec("api-key", "x"),
	})
	if len(got) != 1 || got[0].Type != "api-key" {
		t.Fatalf("expected api-key, got %v", got)
	}
	// A lone service-token (no better classification) is kept.
	got = dedupeCredsPreferSpecificType([]credchain.CredentialRecord{rec("service-token", "svc-only")})
	if len(got) != 1 || got[0].Type != "service-token" {
		t.Fatalf("expected the lone service-token kept, got %v", got)
	}
	// Different values are independent.
	got = dedupeCredsPreferSpecificType([]credchain.CredentialRecord{
		rec("api-key", "a"), rec("hf-token", "b"),
	})
	if len(got) != 2 {
		t.Fatalf("distinct values must both survive, got %v", got)
	}
}

func TestChatReplyExtractors(t *testing.T) {
	if got := replyOpenAI([]byte(`{"choices":[{"message":{"content":"hi there"}}]}`)); got != "hi there" {
		t.Errorf("replyOpenAI=%q", got)
	}
	if got := replyOpenAI([]byte(`{"choices":[{"text":"legacy completion"}]}`)); got != "legacy completion" {
		t.Errorf("replyOpenAI text=%q", got)
	}
	if got := replyOllama([]byte(`{"message":{"content":"ollama reply"}}`)); got != "ollama reply" {
		t.Errorf("replyOllama=%q", got)
	}
	if got := replyOllama([]byte(`{"response":"generate reply"}`)); got != "generate reply" {
		t.Errorf("replyOllama response=%q", got)
	}
	if got := replyHF([]byte(`[{"generated_text":"tgi out"}]`)); got != "tgi out" {
		t.Errorf("replyHF array=%q", got)
	}
	if got := replyHF([]byte(`{"generated_text":"tgi obj"}`)); got != "tgi obj" {
		t.Errorf("replyHF obj=%q", got)
	}
	// malformed -> empty, not a panic
	if got := replyOpenAI([]byte(`nonsense`)); got != "" {
		t.Errorf("replyOpenAI malformed=%q", got)
	}
}

func TestChatModelExtractors(t *testing.T) {
	got := modelsOpenAI([]byte(`{"data":[{"id":"gpt-4"},{"id":"claude-sonnet"}]}`))
	if !reflect.DeepEqual(got, []string{"gpt-4", "claude-sonnet"}) {
		t.Errorf("modelsOpenAI=%v", got)
	}
	got = modelsOllama([]byte(`{"models":[{"name":"llama3"},{"name":"smollm"}]}`))
	if !reflect.DeepEqual(got, []string{"llama3", "smollm"}) {
		t.Errorf("modelsOllama=%v", got)
	}
	if got := modelsOpenAI([]byte(`garbage`)); got != nil {
		t.Errorf("modelsOpenAI garbage=%v", got)
	}
}

func TestChatPayloadBuilders(t *testing.T) {
	hist := []chatMsg{{Role: "user", Content: "a"}, {Role: "assistant", Content: "b"}, {Role: "user", Content: "c"}}
	oa := openAIChatPayload("gpt-4", hist, 128)
	if oa["model"] != "gpt-4" || oa["max_tokens"] != 128 {
		t.Errorf("openAIChatPayload=%v", oa)
	}
	if msgs, ok := oa["messages"].([]chatMsg); !ok || len(msgs) != 3 {
		t.Errorf("openAIChatPayload messages=%v", oa["messages"])
	}
	ol := ollamaChatPayload("llama3", hist, 64)
	if ol["stream"] != false {
		t.Errorf("ollamaChatPayload stream=%v", ol["stream"])
	}
	// hf is single-turn: only the last user prompt is sent
	hf := hfGeneratePayload("", hist, 32)
	if hf["inputs"] != "c" {
		t.Errorf("hfGeneratePayload inputs=%v (want last user prompt)", hf["inputs"])
	}
}

func TestTrimRunawayTurns(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"clean reply unchanged", "Hello! How can I help you today?", "Hello! How can I help you today?"},
		{"cut at ### User:", "I'm an assistant.\n\n### User:\nwho are you?\n### Assistant: again", "I'm an assistant."},
		{"cut at ### Assistant:", "Sure, here it is.\n### Assistant: more runaway", "Sure, here it is."},
		{"cut at chatml token", "Answer here.<|im_start|>user\nnext", "Answer here."},
		{"whole reply is a fake turn", "### User: nothing before this", ""},
		{"non-role markdown heading kept", "Here is a list:\n## Questions\nWhat next?", "Here is a list:\n## Questions\nWhat next?"},
		{"role word mid-sentence kept", "As an assistant I can help; the user should note System: is fine.", "As an assistant I can help; the user should note System: is fine."},
	}
	for _, c := range cases {
		if got := trimRunawayTurns(c.in); got != c.want {
			t.Errorf("%s: trimRunawayTurns(%q)=%q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestMCPShellCredentialRecords(t *testing.T) {
	records := mcpShellCredentialRecords("OPENAI_API_KEY=sk-shell-secret-1234567890\nPATH=/usr/bin", "http://127.0.0.1:3000", "shell:get_environment")
	if len(records) != 1 {
		t.Fatalf("expected one credential record, got %#v", records)
	}
	if records[0]["type"] != "openai-api-key" || records[0]["name"] != "OPENAI_API_KEY" {
		t.Fatalf("unexpected credential classification: %#v", records[0])
	}
	if records[0]["value"] != "sk-shell-secret-1234567890" || records[0]["source_target"] != "http://127.0.0.1:3000" {
		t.Fatalf("unexpected credential value/target: %#v", records[0])
	}
	if records[0]["chainable"] != true {
		t.Fatalf("openai-api-key should remain chainable in shell loot: %#v", records[0])
	}
}

func TestModuleShellVerbsRegistered(t *testing.T) {
	want := map[string]bool{
		"ollama": true, "openai-compat": true, "litellm": true,
		"huggingface": true, "jupyter": true, "mcp": true, "a2a": true,
	}
	found := map[string]bool{}
	for _, c := range rootCmd.Commands() {
		if !want[c.Name()] {
			continue
		}
		for _, sub := range c.Commands() {
			if sub.Name() == "shell" {
				found[c.Name()] = true
			}
		}
	}
	for name := range want {
		if !found[name] {
			t.Errorf("module %q is missing its `shell` verb", name)
		}
	}
}
