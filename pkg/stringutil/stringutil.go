package stringutil

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// ansiSGR matches ANSI SGR color/style escape sequences so visible width can be
// measured independently of colorization.
var ansiSGR = regexp.MustCompile("\x1b\\[[0-9;]*m")

// VisibleWidth returns the rune count of s ignoring ANSI SGR escape sequences.
func VisibleWidth(s string) int {
	return utf8.RuneCountInString(ansiSGR.ReplaceAllString(s, ""))
}

// WrapWords wraps plain (uncolored) text to width, breaking on spaces. A single
// token longer than width is hard-broken across lines so nothing exceeds the frame.
// Returns at least one line.
func WrapWords(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return []string{""}
	}
	var lines []string
	cur := ""
	curLen := 0
	flush := func() {
		if cur != "" {
			lines = append(lines, cur)
			cur, curLen = "", 0
		}
	}
	for _, word := range fields {
		wl := VisibleWidth(word)
		if wl > width {
			flush()
			runes := []rune(word)
			for len(runes) > 0 {
				take := width
				if take > len(runes) {
					take = len(runes)
				}
				lines = append(lines, string(runes[:take]))
				runes = runes[take:]
			}
			continue
		}
		switch {
		case curLen == 0:
			cur, curLen = word, wl
		case curLen+1+wl <= width:
			cur += " " + word
			curLen += 1 + wl
		default:
			flush()
			cur, curLen = word, wl
		}
	}
	flush()
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

// WrapWordsKeepLong wraps like WrapWords but NEVER breaks a single word mid-token: a word
// wider than width overflows onto its own line whole. Used where a chopped token (a URL,
// DSN, or credential in evidence) would be un-copy-pasteable.
func WrapWordsKeepLong(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return []string{""}
	}
	var lines []string
	cur := ""
	curLen := 0
	flush := func() {
		if cur != "" {
			lines = append(lines, cur)
			cur, curLen = "", 0
		}
	}
	for _, word := range fields {
		wl := VisibleWidth(word)
		switch {
		case curLen == 0:
			cur, curLen = word, wl
		case curLen+1+wl <= width:
			cur += " " + word
			curLen += 1 + wl
		default:
			flush()
			cur, curLen = word, wl
		}
	}
	flush()
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

// PackParts packs pre-formed parts (e.g. key=value pairs) onto lines joined by sep,
// wrapping at part boundaries so a part is never split — unless a single part alone
// exceeds width, in which case it is hard-broken (framing wins over part integrity).
func PackParts(parts []string, sep string, width int) []string {
	if len(parts) == 0 {
		return nil
	}
	if width <= 0 {
		return []string{strings.Join(parts, sep)}
	}
	sepLen := VisibleWidth(sep)
	var lines []string
	cur := ""
	curLen := 0
	for _, p := range parts {
		pl := VisibleWidth(p)
		switch {
		case curLen == 0 && pl > width:
			lines = append(lines, WrapWords(p, width)...)
		case curLen == 0:
			cur, curLen = p, pl
		case curLen+sepLen+pl <= width:
			cur += sep + p
			curLen += sepLen + pl
		default:
			lines = append(lines, cur)
			if pl > width {
				lines = append(lines, WrapWords(p, width)...)
				cur, curLen = "", 0
			} else {
				cur, curLen = p, pl
			}
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// ContainsAny returns true if value contains any of the needles (case-sensitive).
func ContainsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

// ContainsAnyFold returns true if value contains any of the needles (case-insensitive).
func ContainsAnyFold(value string, needles ...string) bool {
	lower := strings.ToLower(value)
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

// BoundedPreview truncates a string to at most limit runes (inclusive of the
// ellipsis), normalizing newlines to spaces. It prefers a trailing word boundary
// and appends a single "…" so the result never exceeds limit or breaks mid-word.
func BoundedPreview(raw string, limit int) string {
	value := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(raw, "\r", ""), "\n", " "))
	if limit <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	cut := limit - 1 // reserve one rune for the ellipsis
	if cut < 1 {
		cut = 1
	}
	truncated := string(runes[:cut])
	if idx := strings.LastIndex(truncated, " "); idx > cut/2 {
		truncated = truncated[:idx]
	}
	return strings.TrimRight(truncated, " ") + "…"
}

// DedupeStrings returns a sorted, deduplicated copy of the input slice,
// trimming whitespace and dropping empty strings.
func DedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
