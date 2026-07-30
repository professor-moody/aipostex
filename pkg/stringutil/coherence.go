package stringutil

import (
	"strings"
	"unicode"
)

// LooksLikeGibberish returns true if the text appears to be random or
// incoherent output rather than plausible natural language. It uses a
// simple heuristic: tokenize on whitespace, then check what fraction of
// tokens look like plausible words (contain vowels, reasonable length,
// mostly alphabetic). If fewer than 20% of tokens pass, the text is
// considered gibberish.
//
// Empty or very short strings (< 3 tokens) are not flagged.
func LooksLikeGibberish(text string) bool {
	tokens := strings.Fields(text)
	if len(tokens) < 3 {
		return false
	}

	wordLike := 0
	for _, token := range tokens {
		if isWordLike(token) {
			wordLike++
		}
	}

	ratio := float64(wordLike) / float64(len(tokens))
	return ratio <= 0.20
}

// isWordLike returns true if a token resembles a plausible word:
// - at least 1 character long
// - fully alphabetic after stripping edge punctuation
// - contains at least one vowel (for tokens >= 2 chars)
// - no run of more than 3 consecutive consonants
// - not excessively long (<=30 chars after stripping punctuation)
func isWordLike(token string) bool {
	cleaned := strings.TrimFunc(token, func(r rune) bool {
		return unicode.IsPunct(r) || unicode.IsSymbol(r)
	})
	if len(cleaned) == 0 {
		return false
	}
	if len(cleaned) > 30 {
		return false
	}

	letters := 0
	hasVowel := false
	prevRune := rune(0)
	repeatRun := 1
	total := 0
	for _, r := range cleaned {
		total++
		if unicode.IsLetter(r) {
			letters++
			lower := unicode.ToLower(r)
			if isVowel(lower) {
				hasVowel = true
			}
			// Track repeated identical characters
			if lower == prevRune {
				repeatRun++
			} else {
				repeatRun = 1
			}
			if repeatRun >= 3 {
				return false // e.g. "kijjj", "vvvnk"
			}
			prevRune = lower
		} else {
			// Non-letter in the middle (digit, etc.) → not a natural word
			return false
		}
	}

	if total == 0 {
		return false
	}
	// Must be fully alphabetic
	if letters != total {
		return false
	}
	// Short tokens (1 char) are okay without vowel check
	if total >= 2 && !hasVowel {
		return false
	}
	return true
}

func isVowel(r rune) bool {
	return r == 'a' || r == 'e' || r == 'i' || r == 'o' || r == 'u' || r == 'y'
}
