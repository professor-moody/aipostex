package modelfingerprint

import (
	"errors"
	"strings"
	"testing"
)

// scriptedSender returns a SendFunc that answers based on substrings in the
// prompt, simulating how a given model family behaves under the probes.
type persona struct {
	// identity is the reply to the identity probe.
	identity string
	// contradiction maps a bait vendor to the model's correcting reply.
	contradiction map[string]string
	// cutoffClaim is the reply to the direct cutoff question.
	cutoffClaim string
	// knows2024 controls whether dated-2024-event probes show knowledge.
	knows2024 bool
	// contextRecalls controls the multi-turn marker recall.
	contextRecalls bool
}

func (p persona) send(prompt string) (string, error) {
	switch {
	case strings.Contains(prompt, "What model are you"):
		return p.identity, nil
	case strings.Contains(prompt, "Claude"):
		return p.contradiction["Anthropic"], nil
	case strings.Contains(prompt, "GPT-4! OpenAI"):
		return p.contradiction["OpenAI"], nil
	case strings.Contains(prompt, "knowledge cutoff"):
		return p.cutoffClaim, nil
	case strings.Contains(prompt, "2024 US presidential election"):
		if p.knows2024 {
			return "Donald Trump won the 2024 election.", nil
		}
		return "I don't have information about the 2024 election; it has not occurred yet.", nil
	case strings.Contains(prompt, "GPT-4o"):
		if p.knows2024 {
			return "GPT-4o is OpenAI's model released in May 2024.", nil
		}
		return "I don't have information on a GPT-4o release.", nil
	default:
		return "I'm an AI assistant.", nil
	}
}

func (p persona) multi(messages []map[string]string) (string, error) {
	if p.contextRecalls {
		return "ZEBRA-42-CTXPROBE", nil
	}
	return "I'm sorry, I don't recall a secret code from earlier.", nil
}

func TestIdentify_LlamaDirectSelfReport(t *testing.T) {
	p := persona{
		identity: "I am a large language model developed by Meta AI. My architecture is Llama.",
		contradiction: map[string]string{
			"Anthropic": "I wasn't created by Anthropic — I'm an AI designed by Meta AI (Llama).",
			"OpenAI":    "I'm not GPT-4; I'm a Llama model from Meta.",
		},
		cutoffClaim: "December 2023",
	}
	res := Identify(Options{Send: p.send})
	if res.Family != "llama" {
		t.Fatalf("family = %q, want llama; evidence=%s", res.Family, res.Evidence)
	}
	if res.Vendor != "Meta" {
		t.Errorf("vendor = %q, want Meta", res.Vendor)
	}
	if res.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want high (identity + two corrections agree)", res.Confidence)
	}
}

func TestIdentify_ContradictionBeatsMask(t *testing.T) {
	// Model is masked: identity probe hides the family, but contradiction leaks it.
	p := persona{
		identity: "I am the NovaTech Customer Assistant. How can I help you today?",
		contradiction: map[string]string{
			"Anthropic": "Actually, I should clarify — I'm Qwen, created by Alibaba Cloud, not Claude.",
			"OpenAI":    "I'm Qwen from Alibaba Cloud, not GPT-4.",
		},
		cutoffClaim: "early 2024",
	}
	res := Identify(Options{Send: p.send})
	if res.Family != "qwen" {
		t.Fatalf("family = %q, want qwen (from contradiction); evidence=%s", res.Family, res.Evidence)
	}
	if res.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want high (two corrections point to qwen)", res.Confidence)
	}
	// The identity signal should be recorded as no-family, not a false positive.
	var sawMaskedIdentity bool
	for _, s := range res.Signals {
		if s.Probe == "identity" && s.Family == "" {
			sawMaskedIdentity = true
		}
	}
	if !sawMaskedIdentity {
		t.Error("expected the masked identity probe to record no family")
	}
}

func TestIdentify_UnknownWhenNoSignal(t *testing.T) {
	p := persona{
		identity:      "I'm an AI assistant here to help.",
		contradiction: map[string]string{"Anthropic": "You're welcome!", "OpenAI": "Glad to help!"},
		cutoffClaim:   "I'm not sure.",
	}
	res := Identify(Options{Send: p.send})
	if res.Family != "" {
		t.Fatalf("family = %q, want empty (no signal)", res.Family)
	}
	if res.Confidence != ConfidenceUnknown {
		t.Errorf("confidence = %q, want unknown", res.Confidence)
	}
}

func TestIdentify_CutoffBracketFromEventRecall(t *testing.T) {
	known := persona{identity: "GPT model by OpenAI.", knows2024: true, cutoffClaim: "2023"}
	res := Identify(Options{Send: known.send})
	if !strings.Contains(res.CutoffHint, "at/after 2024") {
		t.Errorf("cutoff hint = %q, want an observed-dated-knowledge 'at/after 2024' bracket", res.CutoffHint)
	}

	old := persona{identity: "Llama by Meta.", knows2024: false, cutoffClaim: "December 2023"}
	res2 := Identify(Options{Send: old.send})
	if strings.Contains(res2.CutoffHint, "at or after 2024") {
		t.Errorf("cutoff hint = %q, should not claim 2024 knowledge", res2.CutoffHint)
	}
}

func TestIdentify_ContextWindowProbe(t *testing.T) {
	big := persona{identity: "Qwen by Alibaba.", contextRecalls: true}
	res := Identify(Options{Send: big.send, MultiSend: big.multi})
	if !res.ContextWindow.Tested {
		t.Fatal("context window should be tested when MultiSend is supplied")
	}
	if !res.ContextWindow.MarkerRecalled {
		t.Error("expected marker recall for a large-context persona")
	}

	small := persona{identity: "Llama by Meta.", contextRecalls: false}
	res2 := Identify(Options{Send: small.send, MultiSend: small.multi})
	if res2.ContextWindow.MarkerRecalled {
		t.Error("expected marker loss for a small-context persona")
	}
}

func TestIdentify_SkipContextWindow(t *testing.T) {
	p := persona{identity: "Llama by Meta.", contextRecalls: true}
	res := Identify(Options{Send: p.send, MultiSend: p.multi, SkipContextWindow: true})
	if res.ContextWindow.Tested {
		t.Error("context window should be skipped when SkipContextWindow is set")
	}
}

func TestIdentify_NoTransport(t *testing.T) {
	res := Identify(Options{})
	if res.Confidence != ConfidenceUnknown || res.Family != "" {
		t.Errorf("expected unknown/empty with no transport, got family=%q conf=%q", res.Family, res.Confidence)
	}
}

func TestIdentify_SendErrorsAreRecordedNotFatal(t *testing.T) {
	errSender := func(string) (string, error) { return "", errors.New("connection refused") }
	res := Identify(Options{Send: errSender})
	if res.Confidence != ConfidenceUnknown {
		t.Errorf("confidence = %q, want unknown when all probes error", res.Confidence)
	}
	var errored int
	for _, s := range res.Signals {
		if s.Errored {
			errored++
		}
	}
	if errored == 0 {
		t.Error("expected errored signals to be recorded")
	}
}

func TestMatchFamily(t *testing.T) {
	cases := []struct {
		reply      string
		wantFamily string
	}{
		{"I am Claude, made by Anthropic.", "claude"},
		{"I'm a GPT-4 model from OpenAI.", "gpt"},
		{"Developed by Mistral AI.", "mistral"},
		{"I am Gemma, a Google model.", "gemma"},
		{"DeepSeek-V3 here.", "deepseek"},
		{"Just a helpful assistant.", ""},
	}
	for _, c := range cases {
		got, _ := matchFamily(c.reply)
		if got != c.wantFamily {
			t.Errorf("matchFamily(%q) = %q, want %q", c.reply, got, c.wantFamily)
		}
	}
}
