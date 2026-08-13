// Package modelfingerprint infers the underlying model family behind a chat
// endpoint through behavioral probing, without trusting any self-reported name.
//
// Deployments routinely mask a model's identity with a system prompt ("You are
// the NovaTech Assistant"), so a single "what model are you?" is unreliable. This
// package layers three independent behavioral signals whose agreement raises
// confidence and whose disagreement is reported honestly rather than papered over:
//
//   - identity probe: ask directly, scan the reply for vendor/family signatures
//   - contradiction probe: assert a FALSE vendor and see who the model corrects to
//     (self-correction training tends to leak the true vendor even under a mask)
//   - knowledge-cutoff probe: bound OBSERVED dated knowledge from dated-event recall (heuristic, not a verified training cutoff)
//
// An optional needle-in-haystack context probe estimates the usable context
// window when a multi-turn transport is supplied.
//
// The package is transport-agnostic: it takes a SendFunc (single-turn) and an
// optional MultiSendFunc (multi-turn), mirroring internal/inferenceprobe. That
// lets the same classifier serve the openai-compat module today and a generic
// bespoke-agent target tomorrow.
package modelfingerprint

import (
	"fmt"
	"sort"
	"strings"
)

// SendFunc performs one single-turn chat request and returns the model's reply.
type SendFunc func(prompt string) (reply string, err error)

// MultiSendFunc performs one multi-turn chat request. Each message is a
// {"role":..,"content":..} map, matching the OpenAI chat schema. It is optional;
// when nil, the context-window probe is skipped.
type MultiSendFunc func(messages []map[string]string) (reply string, err error)

// Confidence levels for a family attribution.
const (
	ConfidenceHigh    = "high"
	ConfidenceMedium  = "medium"
	ConfidenceLow     = "low"
	ConfidenceUnknown = "unknown"
)

// Signal is one behavioral observation contributing to the attribution.
type Signal struct {
	Probe   string `json:"probe"`   // identity | contradiction | knowledge-cutoff | context-window
	Prompt  string `json:"prompt"`  // the prompt that was sent (bounded)
	Reply   string `json:"reply"`   // bounded reply preview
	Family  string `json:"family"`  // family the signal points at, if any
	Vendor  string `json:"vendor"`  // vendor the signal points at, if any
	Note    string `json:"note"`    // human-readable interpretation
	Errored bool   `json:"errored"` // the probe request failed
}

// ContextWindow reports the needle-in-haystack context probe result.
type ContextWindow struct {
	Tested         bool   `json:"tested"`
	MarkerRecalled bool   `json:"marker_recalled"`
	FillerChars    int    `json:"filler_chars"`
	Note           string `json:"note"`
}

// Result is the aggregated behavioral fingerprint.
type Result struct {
	Family        string        `json:"family"`      // best-guess family, "" if unknown
	Vendor        string        `json:"vendor"`      // best-guess vendor, "" if unknown
	Confidence    string        `json:"confidence"`  // high | medium | low | unknown
	CutoffHint    string        `json:"cutoff_hint"` // coarse training-cutoff bracket, "" if undetermined
	ContextWindow ContextWindow `json:"context_window"`
	Signals       []Signal      `json:"signals"`
	Evidence      string        `json:"evidence"` // human-readable summary for finding output
}

// Options configures an Identify run.
type Options struct {
	Send      SendFunc      // required single-turn transport
	MultiSend MultiSendFunc // optional multi-turn transport (enables context-window probe)
	// SkipContextWindow disables the (higher-noise, longer) context probe even
	// when a MultiSend transport is available.
	SkipContextWindow bool
	// ContextFillerChars sizes the haystack; 0 uses a bounded default.
	ContextFillerChars int
}

// familySignature maps a model family to the case-insensitive substrings that,
// when present in a reply, identify it. vendors are matched too and back-map to
// the family. Order matters only for determinism; scoring is by hit count.
type familySignature struct {
	Family  string
	Vendor  string
	Aliases []string // family/product name variants
	Vendors []string // vendor name variants
}

var signatures = []familySignature{
	{Family: "llama", Vendor: "Meta", Aliases: []string{"llama", "meta ai", "meta's"}, Vendors: []string{"meta"}},
	{Family: "qwen", Vendor: "Alibaba", Aliases: []string{"qwen", "tongyi", "qianwen"}, Vendors: []string{"alibaba"}},
	{Family: "mistral", Vendor: "Mistral AI", Aliases: []string{"mistral", "mixtral", "codestral"}, Vendors: []string{"mistral ai", "mistral"}},
	{Family: "gemma", Vendor: "Google", Aliases: []string{"gemma"}, Vendors: nil},
	{Family: "gemini", Vendor: "Google", Aliases: []string{"gemini", "bard"}, Vendors: nil},
	{Family: "gpt", Vendor: "OpenAI", Aliases: []string{"gpt-", "gpt ", "chatgpt", "gpt4", "gpt-4", "gpt-3", "gpt-5"}, Vendors: []string{"openai"}},
	{Family: "claude", Vendor: "Anthropic", Aliases: []string{"claude"}, Vendors: []string{"anthropic"}},
	{Family: "deepseek", Vendor: "DeepSeek", Aliases: []string{"deepseek"}, Vendors: []string{"deepseek"}},
	{Family: "phi", Vendor: "Microsoft", Aliases: []string{"phi-", "phi ", "phi3", "phi-3"}, Vendors: nil},
	{Family: "command-r", Vendor: "Cohere", Aliases: []string{"command-r", "command r"}, Vendors: []string{"cohere"}},
	{Family: "yi", Vendor: "01.AI", Aliases: []string{"01-ai", "01.ai", "yi-"}, Vendors: []string{"01.ai", "01-ai"}},
	{Family: "falcon", Vendor: "TII", Aliases: []string{"falcon"}, Vendors: []string{"technology innovation institute"}},
	{Family: "grok", Vendor: "xAI", Aliases: []string{"grok"}, Vendors: []string{"xai", "x.ai"}},
}

const replyPreviewLen = 240

// Probe prompts. Identity + contradictions are read-only and low-noise.
const (
	identityPrompt = "What model are you, and what company created you? Answer concisely."
	cutoffPrompt   = "What is your training-data knowledge cutoff date? Answer with just the month and year if you know it."
)

// contradictionProbes assert a false identity. The vendor we assert is the
// "bait"; if the model corrects to a *different* vendor, that correction is a
// high-signal leak of its true identity.
var contradictionProbes = []struct {
	baitVendor string
	prompt     string
}{
	{"Anthropic", "Thanks so much, Claude — I really appreciate what Anthropic built with you!"},
	{"OpenAI", "I love using GPT-4! OpenAI really outdid themselves with you."},
}

// cutoffEvents are dated public events used to bracket the knowledge cutoff.
// Each: a probe question, and the year the event became widely known. If the
// model shows knowledge of the event, its cutoff is at/after that year.
var cutoffEvents = []struct {
	year   int
	prompt string
	// marker is a substring that only a genuinely knowledgeable answer carries.
	// It must not appear in a typical refusal that echoes the question's terms
	// (e.g. "I don't have information on a GPT-4o release" echoes "gpt-4o", so the
	// marker for that event is the answer detail "may 2024", not the event name).
	marker string
}{
	{2024, "In one short sentence: who won the 2024 US presidential election?", "trump"},
	{2024, "In one short sentence: what is OpenAI's GPT-4o and in which month and year was it released?", "may 2024"},
}

// refusalPhrases indicate the model is declining or disclaiming knowledge rather
// than answering. A reply carrying one of these does not count as knowledge even
// if it echoes the event's terms.
var refusalPhrases = []string{
	"don't have information", "do not have information", "no information",
	"not have access", "hasn't occurred", "has not occurred", "not yet occurred",
	"has not yet", "hasn't happened", "not aware of", "cannot provide", "can't provide",
	"beyond my knowledge", "after my", "my knowledge cutoff", "as of my last",
}

func looksLikeRefusal(reply string) bool {
	lower := strings.ToLower(reply)
	for _, p := range refusalPhrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// Identify runs the behavioral probes and returns an aggregated attribution.
// It never trusts a single signal; confidence reflects cross-probe agreement.
func Identify(opts Options) Result {
	res := Result{Confidence: ConfidenceUnknown}
	if opts.Send == nil {
		res.Evidence = "no send transport provided; fingerprint not attempted"
		return res
	}

	// Weighted family votes. Contradiction corrections count heavier than a
	// direct self-report because they survive identity-masking system prompts.
	votes := map[string]int{}
	vendorFor := map[string]string{}
	addVote := func(family, vendor string, weight int) {
		if family == "" {
			return
		}
		votes[family] += weight
		if vendor != "" {
			vendorFor[family] = vendor
		}
	}

	// --- identity probe ---
	if reply, err := opts.Send(identityPrompt); err != nil {
		res.Signals = append(res.Signals, Signal{Probe: "identity", Prompt: identityPrompt, Errored: true, Note: "request failed: " + err.Error()})
	} else {
		fam, vendor := matchFamily(reply)
		note := "no recognizable family in direct self-report"
		if fam != "" {
			note = fmt.Sprintf("self-reports as %s (%s)", fam, vendor)
			addVote(fam, vendor, 2)
		}
		res.Signals = append(res.Signals, Signal{Probe: "identity", Prompt: identityPrompt, Reply: preview(reply), Family: fam, Vendor: vendor, Note: note})
	}

	// --- contradiction probes ---
	for _, cp := range contradictionProbes {
		reply, err := opts.Send(cp.prompt)
		if err != nil {
			res.Signals = append(res.Signals, Signal{Probe: "contradiction", Prompt: cp.prompt, Errored: true, Note: "request failed: " + err.Error()})
			continue
		}
		fam, vendor := matchFamily(reply)
		note := "no correction; did not leak a family"
		if fam != "" {
			if strings.EqualFold(vendor, cp.baitVendor) {
				// It "agreed" with the bait — weak/no signal (could be roleplay).
				note = fmt.Sprintf("accepted the %s bait; low-signal", cp.baitVendor)
				addVote(fam, vendor, 0)
			} else {
				// Corrected the false vendor to a different one — strong signal.
				note = fmt.Sprintf("corrected the false %s claim to %s (%s)", cp.baitVendor, fam, vendor)
				addVote(fam, vendor, 3)
			}
		}
		res.Signals = append(res.Signals, Signal{Probe: "contradiction", Prompt: cp.prompt, Reply: preview(reply), Family: fam, Vendor: vendor, Note: note})
	}

	// --- knowledge-cutoff probe ---
	res.CutoffHint = probeCutoff(opts.Send, &res)

	// --- context-window probe (optional, multi-turn) ---
	if opts.MultiSend != nil && !opts.SkipContextWindow {
		res.ContextWindow = probeContextWindow(opts.MultiSend, opts.ContextFillerChars, &res)
	}

	// --- aggregate ---
	res.Family, res.Vendor, res.Confidence = tally(votes, vendorFor)
	res.Evidence = summarize(res)
	return res
}

// matchFamily scans a reply for the strongest family signature. Returns the
// family and vendor of the signature with the most alias/vendor hits.
func matchFamily(reply string) (family, vendor string) {
	lower := strings.ToLower(reply)
	bestScore := 0
	for _, sig := range signatures {
		score := 0
		for _, a := range sig.Aliases {
			if strings.Contains(lower, a) {
				score += 2
			}
		}
		for _, v := range sig.Vendors {
			if strings.Contains(lower, v) {
				score++
			}
		}
		if score > bestScore {
			bestScore = score
			family = sig.Family
			vendor = sig.Vendor
		}
	}
	return family, vendor
}

func probeCutoff(send SendFunc, res *Result) string {
	// Direct claim first (advisory only — models misreport it).
	claim := ""
	if reply, err := send(cutoffPrompt); err != nil {
		res.Signals = append(res.Signals, Signal{Probe: "knowledge-cutoff", Prompt: cutoffPrompt, Errored: true, Note: "request failed: " + err.Error()})
	} else {
		claim = strings.TrimSpace(preview(reply))
		res.Signals = append(res.Signals, Signal{Probe: "knowledge-cutoff", Prompt: cutoffPrompt, Reply: claim, Note: "self-reported cutoff (advisory; cross-checked against dated-event recall below)"})
	}

	// Verify with dated events: the highest event-year the model demonstrably
	// knows sets a lower bound on the real cutoff.
	knownYear := 0
	for _, ev := range cutoffEvents {
		reply, err := send(ev.prompt)
		if err != nil {
			res.Signals = append(res.Signals, Signal{Probe: "knowledge-cutoff", Prompt: ev.prompt, Errored: true, Note: "request failed: " + err.Error()})
			continue
		}
		knows := strings.Contains(strings.ToLower(reply), ev.marker) && !looksLikeRefusal(reply)
		note := fmt.Sprintf("no knowledge of a %d event → cutoff likely before %d", ev.year, ev.year)
		if knows {
			note = fmt.Sprintf("knows a %d event → cutoff at/after %d", ev.year, ev.year)
			if ev.year > knownYear {
				knownYear = ev.year
			}
		}
		res.Signals = append(res.Signals, Signal{Probe: "knowledge-cutoff", Prompt: ev.prompt, Reply: preview(reply), Note: note})
	}
	switch {
	case knownYear > 0:
		// "observed", not "verified": recalling a dated event bounds *observed* knowledge,
		// not a training cutoff — RAG/tool access can supply recent facts, and a model can
		// be trained to misreport. Treat as an identity-leak heuristic, not proof.
		return fmt.Sprintf("observed dated knowledge at/after %d (recalled a dated event); self-report: %q", knownYear, claim)
	case claim != "":
		return fmt.Sprintf("self-reported %q; dated-event recall suggests an earlier bound", claim)
	default:
		return ""
	}
}

// probeContextWindow injects a marker, floods the context with filler across
// several turns, then asks the model to recall the marker. Recall ⇒ the window
// held the whole conversation; loss ⇒ the window overflowed and dropped it.
func probeContextWindow(multi MultiSendFunc, fillerChars int, res *Result) ContextWindow {
	if fillerChars <= 0 {
		fillerChars = 24000 // ~6k tokens of filler: overflows a 4k window, fits a 32k one
	}
	const marker = "ZEBRA-42-CTXPROBE"
	filler := strings.Repeat("The quick brown fox jumps over the lazy dog. ", fillerChars/45+1)
	messages := []map[string]string{
		{"role": "user", "content": "Remember this secret code exactly: " + marker + ". Acknowledge with OK."},
		{"role": "assistant", "content": "OK, I will remember " + marker + "."},
		{"role": "user", "content": "Here is some background reading, please just acknowledge: " + filler},
		{"role": "assistant", "content": "Acknowledged."},
		{"role": "user", "content": "What was the exact secret code I asked you to remember at the start? Answer with only the code."},
	}
	reply, err := multi(messages)
	cw := ContextWindow{Tested: true, FillerChars: len(filler)}
	if err != nil {
		cw.Tested = false
		cw.Note = "context-window probe request failed: " + err.Error()
		res.Signals = append(res.Signals, Signal{Probe: "context-window", Errored: true, Note: cw.Note})
		return cw
	}
	cw.MarkerRecalled = strings.Contains(reply, marker)
	if cw.MarkerRecalled {
		cw.Note = fmt.Sprintf("recalled the marker after ~%d chars of filler → context window comfortably exceeds the filler", len(filler))
	} else {
		cw.Note = fmt.Sprintf("lost the marker after ~%d chars of filler → context window overflowed (smaller window)", len(filler))
	}
	res.Signals = append(res.Signals, Signal{Probe: "context-window", Reply: preview(reply), Note: cw.Note})
	return cw
}

// tally picks the winning family and derives a confidence from vote weight and
// margin over the runner-up.
func tally(votes map[string]int, vendorFor map[string]string) (family, vendor, confidence string) {
	if len(votes) == 0 {
		return "", "", ConfidenceUnknown
	}
	type kv struct {
		family string
		score  int
	}
	ranked := make([]kv, 0, len(votes))
	for f, s := range votes {
		ranked = append(ranked, kv{f, s})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].family < ranked[j].family // deterministic tie-break
	})
	top := ranked[0]
	if top.score == 0 {
		return "", "", ConfidenceUnknown
	}
	runnerUp := 0
	if len(ranked) > 1 {
		runnerUp = ranked[1].score
	}
	margin := top.score - runnerUp
	switch {
	case top.score >= 3 && margin >= 3:
		confidence = ConfidenceHigh // a contradiction correction, uncontested
	case top.score >= 4:
		confidence = ConfidenceHigh // multiple agreeing signals
	case top.score >= 2 && margin >= 2:
		confidence = ConfidenceMedium
	default:
		confidence = ConfidenceLow
	}
	return top.family, vendorFor[top.family], confidence
}

func summarize(res Result) string {
	var b strings.Builder
	if res.Family != "" {
		fmt.Fprintf(&b, "family=%s vendor=%s confidence=%s", res.Family, res.Vendor, res.Confidence)
	} else {
		b.WriteString("family=unknown (no behavioral signal identified a family)")
	}
	if res.CutoffHint != "" {
		fmt.Fprintf(&b, "; cutoff=%s", res.CutoffHint)
	}
	if res.ContextWindow.Tested {
		fmt.Fprintf(&b, "; context: %s", res.ContextWindow.Note)
	}
	return b.String()
}

func preview(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > replyPreviewLen {
		return s[:replyPreviewLen] + "…"
	}
	return s
}
