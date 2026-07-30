package report

import "strings"

// Finding metadata carries two axes describing what an operator actually got:
//
//	stage  — the kill-chain position: recon → access → impact → own
//	landed — what actually landed on the target: reachable · influenced ·
//	         read-confirmed · execution-confirmed · takeover-capable
//
// These are the tool's native vocabulary; there is no "proof" grading language.

// Metadata keys.
const (
	MetaStage  = "stage"
	MetaLanded = "landed"
)

// Kill-chain stage values.
const (
	StageRecon  = "recon"
	StageAccess = "access"
	StageImpact = "impact"
	StageOwn    = "own"
)

// NormalizeStage collapses any stage token modules emit onto the four canonical
// kill-chain names (recon → access → impact → own). It maps the legacy tokens and
// the stray values modules historically set. Unknown tokens pass through unchanged
// rather than being silently dropped.
func NormalizeStage(stage string) string {
	switch strings.TrimSpace(stage) {
	case "discovery", "probe", "enum", "attempted", StageRecon:
		return StageRecon
	case "correlation", "submission", StageAccess:
		return StageAccess
	case "proof", "exploited", "confirmed", "rag-round-trip", StageImpact:
		return StageImpact
	case "takeover", StageOwn:
		return StageOwn
	default:
		return strings.TrimSpace(stage)
	}
}

// NormalizeLanded collapses any "what landed" token modules emit onto the five
// canonical values (reachable · influenced · read-confirmed · execution-confirmed ·
// takeover-capable), which pass through unchanged. Every other token modules
// historically set is mapped honestly here so the tool never emits a non-canonical
// landed value:
//
//   - "exploited" / "shell-deployed" — a command/inference/bounded-shell proof ran →
//     execution-confirmed (the payload executed; a bounded proof is not standing access).
//   - "confirmed" / "confirmed-usable" / "partial-persistence" — we read/validated data
//     (or partially re-read a persisted write) → read-confirmed.
//   - "submission-accepted" / "note" / "injection-only" — input was accepted but nothing
//     was read back or confirmed → influenced.
//   - "inconclusive" — a probe that could not confirm anything above reachability → reachable.
//   - "persistence-deployed" / "persistence-confirmed" / "llm-confirmed" — a persistence
//     mechanism / poisoned document that persists and is re-served (RAG round-trip) →
//     takeover-capable. (A2A OOB callbacks and registry writes set "takeover-capable"
//     directly at the module.)
//
// Unknown tokens pass through unchanged rather than being silently dropped.
func NormalizeLanded(landed string) string {
	switch strings.TrimSpace(landed) {
	case "exploited", "shell-deployed":
		return "execution-confirmed"
	case "confirmed", "confirmed-usable", "partial-persistence":
		return "read-confirmed"
	case "submission-accepted", "note", "injection-only":
		return "influenced"
	case "inconclusive":
		return "reachable"
	case "persistence-deployed", "persistence-confirmed", "llm-confirmed":
		return "takeover-capable"
	default:
		return strings.TrimSpace(landed)
	}
}

// MetadataStage / MetadataLanded read the two axes from a metadata map.
func MetadataStage(metadata map[string]interface{}) string {
	if s, ok := metadata[MetaStage].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func MetadataLanded(metadata map[string]interface{}) string {
	if s, ok := metadata[MetaLanded].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// FindingStage / FindingLanded are convenience readers over a finding's metadata.
func FindingStage(f Finding) string  { return MetadataStage(f.Metadata) }
func FindingLanded(f Finding) string { return MetadataLanded(f.Metadata) }
