package stringutil

import (
	"reflect"
	"testing"
)

// PackParts must measure by VISIBLE width (ANSI escapes ignored), so colored parts —
// e.g. the severity tally — pack by what the operator sees, not by byte length. With the
// old rune/byte count the ANSI codes inflated each part ~2x and wrapped it prematurely.
func TestPackPartsMeasuresVisibleWidthNotANSI(t *testing.T) {
	red := func(s string) string { return "\x1b[31m" + s + "\x1b[0m" }
	parts := []string{red("0 critical"), red("4 high"), red("0 medium"), red("0 low"), red("0 info"), red("(total: 4)")}
	// Visible width of the joined line is ~62; at width 100 it must render as ONE line.
	if lines := PackParts(parts, "  |  ", 100); len(lines) != 1 {
		t.Fatalf("expected colored parts to pack onto one line at width 100, got %d lines: %v", len(lines), lines)
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		value   string
		needles []string
		want    bool
	}{
		{"hello world", []string{"world"}, true},
		{"hello world", []string{"xyz", "world"}, true},
		{"hello", []string{"xyz", "abc"}, false},
		{"", []string{"a"}, false},
		{"test", nil, false},
		{"test", []string{""}, true},
	}
	for _, tc := range tests {
		if got := ContainsAny(tc.value, tc.needles...); got != tc.want {
			t.Errorf("ContainsAny(%q, %v) = %v, want %v", tc.value, tc.needles, got, tc.want)
		}
	}
}

func TestContainsAnyFold(t *testing.T) {
	tests := []struct {
		value   string
		needles []string
		want    bool
	}{
		{"Hello World", []string{"WORLD"}, true},
		{"HELLO", []string{"hello"}, true},
		{"test", []string{"xyz"}, false},
		{"test", []string{""}, false},
		{"", []string{"a"}, false},
	}
	for _, tc := range tests {
		if got := ContainsAnyFold(tc.value, tc.needles...); got != tc.want {
			t.Errorf("ContainsAnyFold(%q, %v) = %v, want %v", tc.value, tc.needles, got, tc.want)
		}
	}
}

func TestBoundedPreview(t *testing.T) {
	tests := []struct {
		raw   string
		limit int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hell…"},
		{"line1\nline2", 20, "line1 line2"},
		{"  spaced  ", 20, "spaced"},
		{"test", 0, "test"},
		{"", 5, ""},
		{"abcdef", 3, "ab…"},
		// prefers a trailing word boundary when one is past the midpoint
		{"alpha bravo charlie", 14, "alpha bravo…"},
	}
	for _, tc := range tests {
		if got := BoundedPreview(tc.raw, tc.limit); got != tc.want {
			t.Errorf("BoundedPreview(%q, %d) = %q, want %q", tc.raw, tc.limit, got, tc.want)
		}
	}
}

func TestWrapWords(t *testing.T) {
	got := WrapWords("the quick brown fox jumps", 10)
	want := []string{"the quick", "brown fox", "jumps"}
	if len(got) != len(want) {
		t.Fatalf("WrapWords lines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("WrapWords line %d = %q, want %q", i, got[i], want[i])
		}
	}
	// a single token longer than width is hard-broken
	hard := WrapWords("abcdefghij", 4)
	if len(hard) != 3 || hard[0] != "abcd" || hard[2] != "ij" {
		t.Fatalf("hard-break = %v, want [abcd efgh ij]", hard)
	}
	if len(WrapWords("", 10)) != 1 {
		t.Fatalf("empty input should yield one line")
	}
}

func TestPackParts(t *testing.T) {
	got := PackParts([]string{"a=1", "b=2", "c=3", "d=4"}, "  ", 12)
	// "a=1  b=2  c=3" = 13 > 12, so "a=1  b=2" (8) then "c=3  d=4" (8)
	want := []string{"a=1  b=2", "c=3  d=4"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("PackParts = %v, want %v", got, want)
	}
	// an over-long single part is hard-broken rather than run off the frame
	long := PackParts([]string{"key=verylongvalue"}, "  ", 6)
	if len(long) < 2 {
		t.Fatalf("over-long part should be hard-broken, got %v", long)
	}
}

func TestVisibleWidth(t *testing.T) {
	if VisibleWidth("plain") != 5 {
		t.Fatalf("plain width = %d, want 5", VisibleWidth("plain"))
	}
	if VisibleWidth("\x1b[31mred\x1b[0m") != 3 {
		t.Fatalf("colored width should ignore ANSI, got %d", VisibleWidth("\x1b[31mred\x1b[0m"))
	}
}

func TestDedupeStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"no dupes", []string{"b", "a"}, []string{"a", "b"}},
		{"with dupes", []string{"a", "b", "a"}, []string{"a", "b"}},
		{"whitespace", []string{" a ", "  ", "b"}, []string{"a", "b"}},
		{"all empty", []string{"", " ", "  "}, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DedupeStrings(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("DedupeStrings(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
