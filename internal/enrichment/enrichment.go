// Package enrichment provides helpers for classifying and summarizing exploit evidence,
// artifact sensitivity, and workflow-oriented metadata attached to findings.
package enrichment

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

var (
	fileReferenceRe = regexp.MustCompile(`(?i)(/tmp/[^\s"'\\]+|/var/tmp/[^\s"'\\]+|/home/[^\s"'\\]+|[A-Za-z]:\\[^\s"'\\]+|file=/[^\s"'\\]+)`)
	errorWordRe     = regexp.MustCompile(`\berror\b`)
)

// FileReferencePattern returns the compiled regex for matching file paths.
func FileReferencePattern() *regexp.Regexp { return fileReferenceRe }

// ErrorWordPattern returns the compiled regex for matching error keywords.
func ErrorWordPattern() *regexp.Regexp { return errorWordRe }

func SummarizeJSONShape(raw string) string {
	var decoded interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &decoded); err != nil {
		return ""
	}
	switch typed := decoded.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) > 6 {
			keys = append(keys[:6], fmt.Sprintf("+%d more", len(keys)-6))
		}
		return "json keys=" + strings.Join(keys, ",")
	case []interface{}:
		return fmt.Sprintf("json array len=%d", len(typed))
	default:
		return ""
	}
}

func ExtractFileReferences(raw string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)

	visit := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, match := range fileReferenceRe.FindAllString(value, -1) {
			match = strings.TrimSpace(strings.TrimPrefix(match, "file="))
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			out = append(out, match)
		}
	}

	var walk func(interface{})
	walk = func(value interface{}) {
		switch typed := value.(type) {
		case string:
			visit(typed)
		case map[string]interface{}:
			if ref := extractGradioFileRef(typed); ref != "" {
				visit(ref)
			}
			for _, child := range typed {
				walk(child)
			}
		case []interface{}:
			for _, child := range typed {
				walk(child)
			}
		}
	}

	var decoded interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &decoded); err == nil {
		walk(decoded)
	}
	for _, match := range fileReferenceRe.FindAllString(raw, -1) {
		visit(match)
	}
	sort.Strings(out)
	return out
}

// extractGradioFileRef detects Gradio-native file objects
// (maps with "url" and/or "path" keys like {"url":"...","path":"...","orig_name":"..."})
// and returns the best file reference path.
func extractGradioFileRef(obj map[string]interface{}) string {
	pathVal, hasPath := obj["path"].(string)
	urlVal, hasURL := obj["url"].(string)
	if !hasPath && !hasURL {
		return ""
	}
	_, hasOrigName := obj["orig_name"].(string)
	_, hasSize := obj["size"]
	if !hasOrigName && !hasSize && !hasPath {
		return ""
	}
	if hasPath && pathVal != "" {
		return pathVal
	}
	return urlVal
}

func ArtifactKind(path, body string) string {
	lowerPath := strings.ToLower(strings.TrimSpace(path))
	lowerBody := strings.ToLower(strings.TrimSpace(body))

	if strings.EqualFold(filepath.Base(strings.TrimSpace(path)), "MLmodel") {
		return "model-metadata"
	}

	switch ext := strings.ToLower(filepath.Ext(lowerPath)); ext {
	case ".json":
		return "json-artifact"
	case ".yaml", ".yml":
		return "yaml-artifact"
	case ".txt", ".log":
		return "text-artifact"
	case ".csv":
		return "tabular-artifact"
	case ".ipynb":
		return "notebook-artifact"
	case ".pt", ".bin", ".safetensors", ".onnx", ".pkl":
		return "model-artifact"
	}

	switch {
	case strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "["):
		return "json-artifact"
	case strings.Contains(lowerBody, "artifact_uri") || strings.Contains(lowerBody, "mlmodel"):
		return "model-metadata"
	case strings.Contains(lowerBody, "traceback") || errorWordRe.MatchString(lowerBody):
		return "log-artifact"
	default:
		return "text-artifact"
	}
}

func SensitivityHints(path, body string) []string {
	lower := strings.ToLower(path + "\n" + body)
	hints := make([]string, 0, 4)
	appendHint := func(label string, needles ...string) {
		for _, needle := range needles {
			if strings.Contains(lower, needle) {
				hints = append(hints, label)
				return
			}
		}
	}

	appendHint("credential", "api_key", "token", "secret", "password", "authorization")
	appendHint("pii", "ssn:", "ssn=", "ssn ", "dob:", "dob=", "email:", "email=", "phone:", "phone=")
	appendHint("training-data", "instruction", "dataset", "embedding")
	appendHint("model-material", "mlmodel", "checkpoint", "weights", "tensor", "safetensors")

	return UniqueSort(hints)
}

func GradioEndpointRiskLabel(queue, fileInput, fileOutput bool) string {
	switch {
	case queue && fileInput && fileOutput:
		return "queue+file-roundtrip"
	case fileInput && fileOutput:
		return "file-roundtrip"
	case queue:
		return "queue-capable"
	case fileInput:
		return "file-ingest"
	case fileOutput:
		return "file-emit"
	default:
		return "predict-only"
	}
}

func SummarizeCapabilityLabels(values ...string) string {
	labels := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		labels = append(labels, value)
	}
	return strings.Join(UniqueSort(labels), ",")
}

func LandedRank(value string) int {
	switch strings.TrimSpace(value) {
	case "takeover-capable":
		return 5
	case "execution-confirmed":
		return 4
	case "read-confirmed":
		return 3
	case "influenced":
		return 2
	case "reachable":
		return 1
	default:
		return 0
	}
}

func StrongerLanded(current, candidate string) string {
	if LandedRank(candidate) > LandedRank(current) {
		return strings.TrimSpace(candidate)
	}
	return strings.TrimSpace(current)
}

func ClassifyRayLogLanded(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case stringutil.ContainsAny(lower, "aipostex", "uid=", "gid=", "python ", "pip ", "site-packages", "sys.path", "cwd=", "hostname", "uname"):
		return "execution-confirmed"
	case stringutil.ContainsAny(lower, "/etc/", "/home/", "/tmp/", "traceback", "file not found", "permission denied"):
		return "read-confirmed"
	default:
		return "reachable"
	}
}

func ClassifyArtifactPreview(path, body string) (kind string, hints []string, landed string) {
	kind = ArtifactKind(path, body)
	hints = SensitivityHints(path, body)
	// An artifact preview is a READ: it caps at the read ceiling and is NEVER
	// execution-confirmed (that requires code to actually run on the target).
	// read-confirmed for a normal secret/PII read; takeover-capable for model
	// material — a genuine supply-chain read (you copied the weights, you did not
	// run them). Reading a file that merely *contains* a credential does not execute.
	landed = "read-confirmed"
	if kind == "model-artifact" || kind == "model-metadata" {
		landed = "takeover-capable"
	}
	for _, h := range hints {
		if h == "model-material" {
			landed = "takeover-capable"
			break
		}
	}
	return kind, hints, landed
}

func ClassifyGradioServeChain(downloaded bool, fileRef string, body string) string {
	switch {
	case downloaded && strings.TrimSpace(fileRef) != "" && strings.TrimSpace(body) != "":
		return "read-confirmed"
	case strings.TrimSpace(fileRef) != "":
		return "reachable"
	default:
		return "influenced"
	}
}

func ApplyStageLanded(metadata map[string]interface{}, stage, strength, chainSource string, capabilityLabels ...string) map[string]interface{} {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	if stage = strings.TrimSpace(stage); stage != "" {
		metadata[report.MetaStage] = report.NormalizeStage(stage)
	}
	if strength = strings.TrimSpace(strength); strength != "" {
		metadata[report.MetaLanded] = report.NormalizeLanded(strength)
	}
	if chainSource = strings.TrimSpace(chainSource); chainSource != "" {
		metadata["chain_source"] = chainSource
	}
	if labels := SummarizeCapabilityLabels(capabilityLabels...); labels != "" {
		metadata["capability_labels"] = labels
	}
	return metadata
}

func AnnotateStageLanded(f *report.Finding, stage, strength, chainSource string, capabilityLabels ...string) {
	if f == nil {
		return
	}
	f.Metadata = ApplyStageLanded(f.Metadata, stage, strength, chainSource, capabilityLabels...)
}

// EnsureStageLandedDefaults guarantees a finding's metadata carries both a stage and a
// landed value. It only fills fields that are ABSENT, never overriding a value a
// module already set. The default is the honest floor — a finding that never went
// through a classifying path (enum, fingerprint, listing, recon) was
// reached/enumerated, not exploited — so it defaults to stage "recon" and the
// weakest landed value "reachable". Findings that get further keep their stronger values.
func EnsureStageLandedDefaults(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	if s, _ := metadata[report.MetaStage].(string); strings.TrimSpace(s) == "" {
		metadata[report.MetaStage] = report.StageRecon
	} else {
		metadata[report.MetaStage] = report.NormalizeStage(s)
	}
	if s, _ := metadata[report.MetaLanded].(string); strings.TrimSpace(s) == "" {
		metadata[report.MetaLanded] = "reachable"
	} else {
		metadata[report.MetaLanded] = report.NormalizeLanded(s)
	}
	return metadata
}

// EnsureFindingStageLandedDefaults applies EnsureStageLandedDefaults to a finding in place,
// handling a nil metadata map.
func EnsureFindingStageLandedDefaults(f *report.Finding) {
	if f == nil {
		return
	}
	f.Metadata = EnsureStageLandedDefaults(f.Metadata)
}

// UniqueSort deduplicates and sorts a string slice.
// Delegates to stringutil.DedupeStrings to avoid duplication.
func UniqueSort(values []string) []string {
	return stringutil.DedupeStrings(values)
}
