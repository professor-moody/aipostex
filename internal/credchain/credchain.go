package credchain

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/professor-moody/aipostex/pkg/report"
)

type Credential struct {
	Type   string // "token", "api-key", "bearer"
	Value  string
	Source string // finding ID that discovered it
}

type CredentialRecord struct {
	Type         string
	Name         string
	Value        string
	Source       string
	SourceTarget string
	TargetURL    string
	Chainable    bool
	Note         string
}

type Store struct {
	mu    sync.RWMutex
	creds map[string][]Credential // keyed by host:port
	// hfTargets maps a discovered HuggingFace inference endpoint (host:port) to its kind:
	// "tgi" (text generation — supports /generate), "tei" (embeddings — supports /embed but
	// NOT /generate), or "hf" (HF-compatible, kind not yet pinned — treated as generate-
	// capable). A looted hf-token carries no target of its own, so it can only be replayed
	// against a separately-discovered HF endpoint — these are those endpoints, and the kind
	// decides whether the replay is a `generate` or an `embed` (a `generate` 404s on a TEI box).
	hfTargets map[string]string
}

func NewStore() *Store {
	return &Store{creds: make(map[string][]Credential), hfTargets: make(map[string]string)}
}

// hfKindRank orders endpoint kinds so a positive TGI signal always wins over TEI, and any
// typed signal wins over an untyped "hf". A port that fingerprints ambiguously as BOTH TGI
// and TEI (real TGI gateways often do — they expose /info, /v1/models, /metrics like several
// servers) is therefore treated as TGI: it can generate.
func hfKindRank(kind string) int {
	switch kind {
	case "tgi":
		return 2
	case "tei":
		return 1
	default: // "hf" / unknown
		return 0
	}
}

// AddHFInferenceTarget records a discovered HF endpoint whose kind is not (yet) known; it is
// treated as generate-capable. Prefer AddHFInferenceTargetKind when the discovery fingerprint
// knows whether the endpoint is TGI or TEI.
func (s *Store) AddHFInferenceTarget(hostPort string) {
	s.AddHFInferenceTargetKind(hostPort, "hf")
}

// AddHFInferenceTargetKind records a discovered HF endpoint and its kind ("tgi"/"tei"/"hf").
// The strongest signal wins (tgi > tei > hf), so a later untyped or embeddings-only sighting
// never downgrades an endpoint already known to be TGI.
func (s *Store) AddHFInferenceTargetKind(hostPort, kind string) {
	hostPort = normalizeHostPort(strings.TrimSpace(hostPort))
	if hostPort == "" || strings.Contains(hostPort, "/") {
		return
	}
	if kind != "tgi" && kind != "tei" {
		kind = "hf"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.hfTargets[hostPort]; ok && hfKindRank(existing) >= hfKindRank(kind) {
		return
	}
	s.hfTargets[hostPort] = kind
}

// HFInferenceTargets returns the discovered HF endpoints (host:port), sorted.
func (s *Store) HFInferenceTargets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.hfTargets))
	for hp := range s.hfTargets {
		out = append(out, hp)
	}
	sort.Strings(out)
	return out
}

// HFTargetKind returns the recorded kind ("tgi"/"tei"/"hf") for a discovered HF endpoint, or
// "" if the endpoint is not a known HF target.
func (s *Store) HFTargetKind(hostPort string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hfTargets[normalizeHostPort(strings.TrimSpace(hostPort))]
}

func (s *Store) Add(hostPort string, cred Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Never index obvious template placeholders (YOUR_OPENAI_KEY_HERE, <api-key>, …).
	if looksLikePlaceholderSecret(cred.Value) {
		return
	}
	hostPort = normalizeHostPort(hostPort)
	for _, existing := range s.creds[hostPort] {
		if existing.Type == cred.Type && existing.Value == cred.Value {
			return
		}
	}
	s.creds[hostPort] = append(s.creds[hostPort], cred)
}

func (s *Store) ForTarget(hostPort string) []Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.creds[normalizeHostPort(hostPort)]
}

func (s *Store) All() map[string][]Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]Credential, len(s.creds))
	for k, v := range s.creds {
		out[k] = append([]Credential(nil), v...)
	}
	return out
}

func (s *Store) TotalCredentials() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, v := range s.creds {
		total += len(v)
	}
	return total
}

func (s *Store) TotalTargets() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.creds)
}

func (s *Store) Summary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.creds) == 0 {
		return ""
	}
	var b strings.Builder
	for hostPort, creds := range s.creds {
		for _, c := range creds {
			fmt.Fprintf(&b, "    %-30s  %s (from %s)\n", hostPort, c.Type, c.Source)
		}
	}
	return b.String()
}

var (
	jupyterTokenURLRe  = regexp.MustCompile(`[?&]token=([a-zA-Z0-9_-]{10,})`)
	jupyterTokenBodyRe = regexp.MustCompile(`(?i)([a-z0-9_-]*token)["\s:=]+([a-zA-Z0-9_-]{20,})`)
	openAIKeyRe        = regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`)
	genericAPIKeyRe    = regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)["\s:=]+["']?([a-zA-Z0-9_-]{16,})["']?`)
	// bearerTokenRe requires "bearer" to be a standalone word (not the tail of a
	// compound like "empty-bearer") and the token on the SAME line ([ \t]+, never
	// \s+ across a newline) — otherwise a serialized metadata blob such as
	// "auth_pattern=empty-bearer\nacceptance_class=..." falsely yields the key
	// "acceptance_class" as a bearer token.
	bearerTokenRe = regexp.MustCompile(`(?i)(?:^|[^a-zA-Z0-9_-])bearer[ \t]+([a-zA-Z0-9_.-]{16,})`)
	// fieldNameLikeRe matches snake_case identifiers (acceptance_class, auth_pattern,
	// failure_class, model_attempts, …) — finding-metadata KEYS, never real credentials.
	fieldNameLikeRe = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$`)
	// jwtRe matches a full JWT/JWS (header segment starts with "eyJ") including its
	// dot-separated payload/signature. Captured whole so it is never truncated at the
	// first dot the way the token= regexes (which exclude ".") would.
	jwtRe              = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_.\-]+`)
	hfTokenRe          = regexp.MustCompile(`hf_[a-zA-Z0-9_]{20,}`)
	anthropicKeyRe     = regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{20,}`)
	wandbKeyRe         = regexp.MustCompile(`(?i)wandb[_-]?(?:api[_-]?)?key["\s:=]+["']?([a-zA-Z0-9]{32,})["']?`)
	litellmMasterKeyRe = regexp.MustCompile(`(?i)(?:litellm[_-]?)?master[_-]?key["\s:=]+["']?([a-zA-Z0-9_-]{16,})["']?`)
	rayTokenRe         = regexp.MustCompile(`(?i)ray[_-]?dashboard[_-]?(?:token|key)["\s:=]+["']?([a-zA-Z0-9_-]{16,})["']?`)
	// {16,} (not {16}) so a longer token is captured WHOLE, not truncated to a 20-char
	// partial that then reads as a second, bogus credential next to the structured one.
	awsAccessKeyRe = regexp.MustCompile(`AKIA[A-Z0-9]{16,}`)
	awsSecretKeyRe = regexp.MustCompile(`(?i)aws_secret_access_key["\s:=]+["']?([A-Za-z0-9/+=]{40})`)
	// awsPairRe captures an access-key ID immediately followed by its secret ("AKIA… / secret"),
	// so the index carries a USABLE pair rather than a lone access-key ID that cannot authenticate.
	awsPairRe      = regexp.MustCompile(`AKIA[A-Z0-9]{16,}\s*/\s*[A-Za-z0-9/+=]{20,}`)
	slackWebhookRe = regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+`)
	githubPATRe    = regexp.MustCompile(`gh[opusr]_[A-Za-z0-9]{36,}`)
	pagerDutyKeyRe = regexp.MustCompile(`(?i)pagerduty[_-]?(?:api|routing|integration|service)[_-]?key["\s:=]+["']?([A-Za-z0-9_+-]{16,})`)
	// dbConnStringRe matches a database connection URI that embeds credentials
	// (user:pass@host…). The embedded user:pass@ is required so plain URLs and
	// no-auth URIs don't match — only genuinely credential-bearing connection strings.
	// The user segment is optional (redis://:pass@host has an empty user); a password before
	// the @ is still required so no-auth URIs (redis://host:6379) never match.
	dbConnStringRe = regexp.MustCompile("(?i)(?:postgresql|postgres|mysql|mongodb(?:\\+srv)?|redis|amqp|snowflake)://[^:@\\s/\"']*:[^@\\s\"']+@[^\\s\"'`]+")
	// hyphenSvcTokenRe catches hyphenated service tokens the alnum-only sk- regex misses,
	// e.g. an MCP build-admin token "sk-mcp-FAKE-build-admin-9f3a2b1c".
	hyphenSvcTokenRe = regexp.MustCompile(`sk-[a-z]{2,}(?:-[A-Za-z0-9]+){2,}`)
	// servicePairRe captures a "Service: user / pass" credential pair from prose evidence
	// (e.g. "Jira: svc-jira-bot / J1r4B0t#2024!"). The " / " separator with two tokens is the anchor.
	servicePairRe = regexp.MustCompile(`(?i)\b([A-Za-z][A-Za-z0-9 ]{1,24}?)\s*:\s*([A-Za-z0-9._@+-]{3,60})\s*/\s*([A-Za-z0-9._@#!$%+=-]{4,60})`)
	// labeledSecretRe captures a labeled secret whose label ends in a credential noun, e.g.
	// "PagerDuty API: pd-…", "CRM API Key: sk-…", "Manager Override Code: ESC-2024-ADMIN".
	labeledSecretRe = regexp.MustCompile(`(?i)\b([A-Za-z][A-Za-z0-9 ]{1,30}?(?:API Key|API|Access Key|Token|Password|Secret|Code))\s*:\s*["']?([A-Za-z0-9._+/=-]{6,80})`)
)

func ExtractFromFindings(findings []report.Finding) *Store {
	store := NewStore()
	for _, f := range findings {
		extractFromFinding(store, f)
	}
	return store
}

func ExtractCredentialRecords(findings []report.Finding) []CredentialRecord {
	records := make([]CredentialRecord, 0)
	seen := make(map[string]struct{})
	for _, f := range findings {
		for _, rec := range credentialRecordsFromFinding(f) {
			key := rec.Type + "\x00" + rec.Name + "\x00" + rec.Value + "\x00" + rec.Source + "\x00" + rec.TargetURL
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			records = append(records, rec)
		}
	}
	upgradeHFTokenRecords(records, discoverHFInferenceTargets(findings))
	return records
}

// isHFInferenceEndpoint reports whether a finding names a HuggingFace-compatible inference
// endpoint (TGI/TEI): a discovery fingerprint tagged the service/provider hf-tgi/hf-tei, the
// huggingface module ran against it, or the title names a TGI/TEI service.
func isHFInferenceEndpoint(f report.Finding) bool {
	for _, key := range []string{"service", "provider", "module"} {
		switch strings.ToLower(stringMapValue(f.Metadata, key)) {
		case "hf-tgi", "hf-tei", "huggingface":
			return true
		}
	}
	return strings.Contains(f.Title, "TGI") || strings.Contains(f.Title, "TEI")
}

// hfEndpointKind returns the AUTHORITATIVE kind of an HF endpoint from a discovery fingerprint —
// "tgi" (generation) or "tei" (embeddings) — or "" when the finding marks the host as HF but
// does not pin the kind. Only the discovery service/provider tag is trusted: a huggingface-
// MODULE finding merely means the module ran against the host (a FAILED `generate` attempt
// included), and a "TGI"/"TEI" title can be produced by an ambiguous fingerprint — neither is a
// reliable signal that the endpoint can actually generate, so both fall through to "" (unknown,
// which routing treats as generate-capable, matching prior behavior).
func hfEndpointKind(f report.Finding) string {
	for _, key := range []string{"service", "provider"} {
		switch strings.ToLower(stringMapValue(f.Metadata, key)) {
		case "hf-tgi":
			return "tgi"
		case "hf-tei":
			return "tei"
		}
	}
	return ""
}

// discoverHFInferenceTargets returns the host:ports of HF/TGI/TEI inference endpoints seen
// across the findings, TGI (generate-capable) endpoints first so a looted hf-token's default
// replay target is one that can actually generate. A looted hf-token carries no target of its
// own, so it can only be replayed if the operator has ALSO discovered where an HF endpoint lives.
func discoverHFInferenceTargets(findings []report.Finding) []string {
	kind := map[string]string{}
	for _, f := range findings {
		if !isHFInferenceEndpoint(f) {
			continue
		}
		hp := targetToHostPort(f.Target)
		if hp == "" || strings.Contains(hp, "/") {
			continue
		}
		k := hfEndpointKind(f)
		if k == "" {
			k = "hf"
		}
		if existing, ok := kind[hp]; !ok || hfKindRank(k) > hfKindRank(existing) {
			kind[hp] = k
		}
	}
	out := make([]string, 0, len(kind))
	for hp := range kind {
		out = append(out, hp)
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := hfKindRank(kind[out[i]]), hfKindRank(kind[out[j]]); ri != rj {
			return ri > rj // generate-capable endpoints first
		}
		return out[i] < out[j]
	})
	return out
}

// upgradeHFTokenRecords marks looted hf-token records actionable and points them at a
// discovered HF/TGI endpoint, so `report view --credentials --commands` shows a runnable
// replay instead of a viewer-only secret. No discovered endpoint → left viewer-only.
func upgradeHFTokenRecords(records []CredentialRecord, hfTargets []string) {
	if len(hfTargets) == 0 {
		return
	}
	ep := ensureScheme(hfTargets[0])
	for i := range records {
		if records[i].Type == "hf-token" {
			records[i].Chainable = true
			records[i].TargetURL = ep
			records[i].Note = "routed to discovered HF/TGI inference endpoint"
		}
	}
}

func extractFromFinding(store *Store, f report.Finding) {
	hostPort := targetToHostPort(f.Target)
	if hostPort == "" {
		return
	}

	// Record HF/TGI/TEI inference endpoints as they are discovered, so a looted hf-token
	// (which has no target of its own) can be routed to one for a real replay. Carry the
	// fingerprinted kind (tgi/tei) so the replay uses `generate` on a TGI box and `embed` on
	// a TEI box — a `generate` 404s on an embeddings endpoint.
	if isHFInferenceEndpoint(f) {
		store.AddHFInferenceTargetKind(hostPort, hfEndpointKind(f))
	}

	structured := credentialRecordsFromFinding(f)
	for _, rec := range structured {
		if strings.TrimSpace(rec.Value) == "" {
			continue
		}
		// hf-token is routable even when the producing module flagged it non-chainable
		// (a bare token has no target of its own): retargetHFTokens re-keys it to a
		// discovered HF/TGI endpoint, or drops it if none was found.
		if !rec.Chainable && rec.Type != "hf-token" {
			continue
		}
		target := rec.TargetURL
		if strings.TrimSpace(target) == "" {
			target = f.Target
		}
		store.Add(targetToHostPort(target), Credential{Type: rec.Type, Value: rec.Value, Source: rec.Source})
	}
	searchText := f.Evidence
	if f.Description != "" {
		searchText += "\n" + f.Description
	}
	if f.Target != "" {
		searchText += "\n" + f.Target
	}

	for k, v := range f.Metadata {
		if s, ok := v.(string); ok {
			searchText += "\n" + k + "=" + s
		}
	}

	// Pattern-anchored extractors run ALWAYS — even when the finding already carries
	// structured extracted_credentials — because URI connection strings, key pairs, and
	// labeled prose secrets frequently appear in evidence WITHOUT being in the structured
	// list (e.g. a ray runtime-env finding structures 4 creds but leaks REDIS_URL/
	// SNOWFLAKE_URI only in evidence). These patterns are specific enough that they never
	// add the count-noise the broad heuristics below do.
	extractDBConnString(store, hostPort, searchText, f.ID)
	extractAWSKeys(store, hostPort, searchText, f.ID)
	extractSlackWebhook(store, hostPort, searchText, f.ID)
	extractGitHubPAT(store, hostPort, searchText, f.ID)
	extractPagerDuty(store, hostPort, searchText, f.ID)
	extractHyphenSvcToken(store, hostPort, searchText, f.ID)
	extractServicePair(store, hostPort, searchText, f.ID)
	extractLabeledSecret(store, hostPort, searchText, f.ID)

	// The broad/heuristic extractors re-scrape loosely, so they run ONLY when the finding
	// has no structured creds — otherwise they emit noise (e.g. wandb's secret COUNT
	// "wandb-secrets-found = 6") alongside the real named secrets.
	if len(structured) > 0 {
		return
	}
	extractJWT(store, hostPort, searchText, f.ID)
	extractJupyterToken(store, hostPort, searchText, f.ID)
	extractOpenAIKey(store, hostPort, searchText, f.ID)
	extractHFToken(store, hostPort, searchText, f.ID)
	extractAnthropicKey(store, hostPort, searchText, f.ID)
	extractWandbKey(store, hostPort, searchText, f.ID)
	extractLiteLLMMasterKey(store, hostPort, searchText, f.ID)
	extractRayToken(store, hostPort, searchText, f.ID)
	extractBearerToken(store, hostPort, searchText, f.ID)
	extractGenericAPIKey(store, hostPort, searchText, f.ID)
	extractMLflowRunHint(store, hostPort, f)
	extractWandbSourceHint(store, hostPort, f)
}

func credentialRecordsFromFinding(f report.Finding) []CredentialRecord {
	if len(f.Metadata) == 0 {
		return nil
	}
	raw, ok := f.Metadata["extracted_credentials"]
	if !ok {
		return nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		if maps, ok := raw.([]map[string]interface{}); ok {
			items = make([]interface{}, 0, len(maps))
			for _, m := range maps {
				items = append(items, m)
			}
		}
	}
	records := make([]CredentialRecord, 0)
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		rec := CredentialRecord{
			Type:         stringMapValue(m, "type"),
			Name:         stringMapValue(m, "name"),
			Value:        stringMapValue(m, "value"),
			Source:       stringMapValue(m, "source"),
			SourceTarget: stringMapValue(m, "source_target"),
			TargetURL:    stringMapValue(m, "target_url"),
			Note:         stringMapValue(m, "note"),
		}
		if rec.Source == "" {
			rec.Source = f.ID
		}
		if rec.SourceTarget == "" {
			rec.SourceTarget = f.Target
		}
		if chainable, ok := m["chainable"].(bool); ok {
			rec.Chainable = chainable
		}
		// Trim trailing-punctuation/escape artifacts off DB connection strings, and drop
		// obvious template placeholders (YOUR_OPENAI_KEY_HERE, <api-key>, …).
		if rec.Type == "db-connection-string" {
			rec.Value = cleanExtractedValue(rec.Value)
		}
		if rec.Type == "" || rec.Value == "" || looksLikePlaceholderSecret(rec.Value) {
			continue
		}
		records = append(records, rec)
	}
	return records
}

func stringMapValue(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func extractJupyterToken(store *Store, hostPort, text, findingID string) {
	if m := jupyterTokenURLRe.FindStringSubmatch(text); len(m) > 1 && !looksLikeJWTHeader(m[1]) {
		store.Add(hostPort, Credential{Type: "jupyter-token", Value: m[1], Source: findingID})
		return
	}
	if m := jupyterTokenBodyRe.FindStringSubmatch(text); len(m) > 2 {
		key, val := strings.ToLower(m[1]), m[2]
		// A JWT header (eyJ…) is truncated at the first dot by this regex and is not a
		// Jupyter token — extractJWT captures it whole as a bearer token.
		if isKnownTokenFormat(val) || looksLikeJWTHeader(val) {
			return
		}
		// Only a bare "token" or a jupyter-prefixed key is a Jupyter token. A service
		// token that merely ends in "_token" (INTERNAL_SERVICE_TOKEN, AWS_ACCESS_TOKEN)
		// is not — leave it for the generic extractors so it isn't mislabeled and doesn't
		// generate a bogus jupyter follow-up command.
		if key == "token" || strings.Contains(key, "jupyter") {
			store.Add(hostPort, Credential{Type: "jupyter-token", Value: val, Source: findingID})
		}
	}
}

func isKnownTokenFormat(val string) bool {
	return strings.HasPrefix(val, "hf_") ||
		strings.HasPrefix(val, "sk-") ||
		strings.HasPrefix(val, "sk-ant-")
}

// looksLikeJWTHeader reports whether a value begins with a base64url-encoded JWT
// header ("eyJ" == `{"` base64url). Jupyter tokens are opaque random strings and
// never start this way.
func looksLikeJWTHeader(val string) bool {
	return strings.HasPrefix(strings.TrimSpace(val), "eyJ")
}

// extractJWT captures full JWT/JWS tokens (header.payload[.signature]) as bearer
// tokens, untruncated. Runs before the jupyter/bearer extractors so a JWT is
// recorded once, whole, and correctly typed.
func extractJWT(store *Store, hostPort, text, findingID string) {
	for _, m := range jwtRe.FindAllString(text, -1) {
		store.Add(hostPort, Credential{Type: "bearer-token", Value: m, Source: findingID})
	}
}

func extractOpenAIKey(store *Store, hostPort, text, findingID string) {
	if m := openAIKeyRe.FindString(text); m != "" {
		store.Add(hostPort, Credential{Type: "openai-api-key", Value: m, Source: findingID})
	}
}

func extractHFToken(store *Store, hostPort, text, findingID string) {
	if m := hfTokenRe.FindString(text); m != "" {
		store.Add(hostPort, Credential{Type: "hf-token", Value: m, Source: findingID})
	}
}

func extractAnthropicKey(store *Store, hostPort, text, findingID string) {
	if m := anthropicKeyRe.FindString(text); m != "" {
		store.Add(hostPort, Credential{Type: "anthropic-api-key", Value: m, Source: findingID})
	}
}

func extractBearerToken(store *Store, hostPort, text, findingID string) {
	if m := bearerTokenRe.FindStringSubmatch(text); len(m) > 1 {
		if openAIKeyRe.MatchString(m[1]) || hfTokenRe.MatchString(m[1]) || anthropicKeyRe.MatchString(m[1]) {
			return
		}
		// A snake_case identifier is a metadata field name, not a credential.
		if LooksLikeMetadataKey(m[1]) {
			return
		}
		store.Add(hostPort, Credential{Type: "bearer-token", Value: m[1], Source: findingID})
	}
}

// LooksLikeMetadataKey reports whether s is a snake_case identifier — a
// finding-metadata field name (acceptance_class, auth_pattern, failure_class),
// never a real credential value. Callers that inject a looted value into a
// suggested command use it as a safety net against a mis-extracted credential.
func LooksLikeMetadataKey(s string) bool {
	return fieldNameLikeRe.MatchString(strings.TrimSpace(s))
}

func extractAWSKeys(store *Store, hostPort, text, findingID string) {
	// Prefer the paired form (access-key ID + secret) so the index carries usable loot;
	// fall back to a lone access-key ID only when no secret is adjacent.
	if pair := awsPairRe.FindString(text); pair != "" {
		store.Add(hostPort, Credential{Type: "aws-access-key", Value: pair, Source: findingID})
	} else if m := awsAccessKeyRe.FindString(text); m != "" {
		store.Add(hostPort, Credential{Type: "aws-access-key", Value: m, Source: findingID})
	}
	if m := awsSecretKeyRe.FindStringSubmatch(text); len(m) > 1 {
		store.Add(hostPort, Credential{Type: "aws-secret-key", Value: m[1], Source: findingID})
	}
}

// extractHyphenSvcToken captures hyphenated sk- service tokens the alnum-only openAI/anthropic
// regexes miss (e.g. an MCP build-admin token embedded in a tool description).
func extractHyphenSvcToken(store *Store, hostPort, text, findingID string) {
	for _, m := range hyphenSvcTokenRe.FindAllString(text, -1) {
		if strings.HasPrefix(m, "sk-ant-") { // anthropic keys have their own extractor
			continue
		}
		store.Add(hostPort, Credential{Type: "service-token", Value: m, Source: findingID})
	}
}

// extractServicePair captures "Service: user / pass" pairs from prose evidence.
func extractServicePair(store *Store, hostPort, text, findingID string) {
	for _, m := range servicePairRe.FindAllStringSubmatch(text, -1) {
		if len(m) < 4 {
			continue
		}
		user, pass := strings.TrimSpace(m[2]), strings.TrimSpace(m[3])
		// Reject non-credential matches this "Label: a / b" shape also captures:
		//   - the AWS pair (handled by extractAWSKeys)
		//   - a DSN port + db name ("host:5432/acme_hr" → user="5432")
		//   - an HTTP request line ("method: GET /playground")
		//   - a "password" with no password-complexity (a bare word / route / db name)
		if awsAccessKeyRe.MatchString(user) || isAllDigits(user) || isHTTPVerb(user) || isHTTPVerb(pass) {
			continue
		}
		if !hasSecretComplexity(pass) {
			continue
		}
		store.Add(hostPort, Credential{Type: "service-credential", Value: user + " / " + pass, Source: findingID})
	}
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isHTTPVerb(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	}
	return false
}

// hasSecretComplexity requires a digit AND (an uppercase letter OR a symbol) — enough to
// keep real passwords ("J1r4B0t#2024!", "Sh4r3P01nt@dm1n") while rejecting bare words a
// "Label: a / b" match also catches (db names like "acme_hr", routes like "playground").
func hasSecretComplexity(s string) bool {
	var digit, upperOrSym bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'A' && r <= 'Z':
			upperOrSym = true
		case !(r >= 'a' && r <= 'z'):
			upperOrSym = true // anything not a-z/A-Z/0-9 is a symbol
		}
	}
	return digit && upperOrSym
}

// extractLabeledSecret captures a labeled secret whose label ends in a credential noun
// ("PagerDuty API: …", "CRM API Key: …", "Manager Override Code: …").
func extractLabeledSecret(store *Store, hostPort, text, findingID string) {
	for _, m := range labeledSecretRe.FindAllStringSubmatch(text, -1) {
		if len(m) < 3 {
			continue
		}
		val := strings.TrimSpace(m[2])
		// Skip values already typed by a more specific extractor (avoids duplicate/mistyped rows).
		if awsAccessKeyRe.MatchString(val) || openAIKeyRe.MatchString(val) || hfTokenRe.MatchString(val) ||
			anthropicKeyRe.MatchString(val) || githubPATRe.MatchString(val) {
			continue
		}
		store.Add(hostPort, Credential{Type: "labeled-secret", Value: val, Source: findingID})
	}
}

func extractSlackWebhook(store *Store, hostPort, text, findingID string) {
	// A single finding often leaks several webhooks (alerts, deploy, …) — capture every
	// one, not just the first, so the credential index is complete.
	for _, m := range slackWebhookRe.FindAllString(text, -1) {
		store.Add(hostPort, Credential{Type: "slack-webhook", Value: m, Source: findingID})
	}
}

func extractGitHubPAT(store *Store, hostPort, text, findingID string) {
	for _, m := range githubPATRe.FindAllString(text, -1) {
		store.Add(hostPort, Credential{Type: "github-pat", Value: m, Source: findingID})
	}
}

func extractPagerDuty(store *Store, hostPort, text, findingID string) {
	if m := pagerDutyKeyRe.FindStringSubmatch(text); len(m) > 1 {
		store.Add(hostPort, Credential{Type: "pagerduty-key", Value: m[1], Source: findingID})
	}
}

// extractDBConnString captures database connection URIs that embed credentials
// (postgresql://user:pass@host…). Added as a viewer-only "db-connection-string" — there's
// no DB module to chain into, so it honestly reports as captured-but-no-follow-on.
func extractDBConnString(store *Store, hostPort, text, findingID string) {
	for _, m := range dbConnStringRe.FindAllString(text, -1) {
		store.Add(hostPort, Credential{Type: "db-connection-string", Value: cleanExtractedValue(m), Source: findingID})
	}
}

// cleanExtractedValue trims trailing punctuation, quotes, and escaped-newline artifacts
// that the greedy URI/secret regexes pick up from surrounding prose or JSON string
// escapes (e.g. "…/acme_saas.", "…/acme_prod).", "…/acme_hr\n").
func cleanExtractedValue(s string) string {
	s = strings.TrimSpace(s)
	for _, suf := range []string{`\n`, `\r`, `\t`, `\`} {
		s = strings.TrimSuffix(s, suf)
	}
	return strings.TrimRight(s, " \t\r\n.,;:)]}>\"'`")
}

// looksLikePlaceholderSecret rejects obvious non-secrets — template placeholders such as
// YOUR_OPENAI_KEY_HERE / <api-key> / changeme — so they never enter the credential index.
func looksLikePlaceholderSecret(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return true
	}
	up := strings.ToUpper(t)
	if strings.HasPrefix(up, "YOUR_") || strings.HasPrefix(up, "YOUR-") {
		return true
	}
	for _, suf := range []string{"_KEY_HERE", "_TOKEN_HERE", "_SECRET_HERE", "-KEY-HERE", "_HERE"} {
		if strings.HasSuffix(up, suf) {
			return true
		}
	}
	switch up {
	case "CHANGEME", "PLACEHOLDER", "EXAMPLE", "XXX", "XXXX", "TODO", "REDACTED", "...":
		return true
	}
	if strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">") {
		return true
	}
	return false
}

func extractGenericAPIKey(store *Store, hostPort, text, findingID string) {
	matches := genericAPIKeyRe.FindAllStringSubmatch(text, 3)
	for _, m := range matches {
		if len(m) > 2 {
			val := m[2]
			if openAIKeyRe.MatchString(val) || hfTokenRe.MatchString(val) || anthropicKeyRe.MatchString(val) || bearerTokenRe.MatchString(val) {
				continue
			}
			store.Add(hostPort, Credential{Type: "api-key", Value: val, Source: findingID})
		}
	}
}

func extractMLflowRunHint(store *Store, hostPort string, f report.Finding) {
	if f.Source != report.SourceMLflow {
		return
	}
	rid, _ := f.Metadata["run_id"].(string)
	rid = strings.TrimSpace(rid)
	if rid == "" {
		return
	}
	store.Add(hostPort, Credential{Type: "mlflow-run-id", Value: rid, Source: f.ID})
}

func extractWandbKey(store *Store, hostPort, text, findingID string) {
	if m := wandbKeyRe.FindStringSubmatch(text); len(m) > 1 {
		store.Add(hostPort, Credential{Type: "wandb-api-key", Value: m[1], Source: findingID})
	}
}

func extractLiteLLMMasterKey(store *Store, hostPort, text, findingID string) {
	if m := litellmMasterKeyRe.FindStringSubmatch(text); len(m) > 1 {
		store.Add(hostPort, Credential{Type: "litellm-master-key", Value: m[1], Source: findingID})
	}
}

func extractRayToken(store *Store, hostPort, text, findingID string) {
	if m := rayTokenRe.FindStringSubmatch(text); len(m) > 1 {
		store.Add(hostPort, Credential{Type: "ray-dashboard-token", Value: m[1], Source: findingID})
	}
}

func extractWandbSourceHint(store *Store, hostPort string, f report.Finding) {
	if f.Source != report.SourceWandB {
		return
	}
	if sc, ok := positiveMetadataCount(f.Metadata["secret_count"]); ok {
		store.Add(hostPort, Credential{Type: "wandb-secrets-found", Value: sc, Source: f.ID})
	}
}

func positiveMetadataCount(v interface{}) (string, bool) {
	switch count := v.(type) {
	case int:
		if count > 0 {
			return strconv.Itoa(count), true
		}
	case int64:
		if count > 0 {
			return strconv.FormatInt(count, 10), true
		}
	case float64:
		if count > 0 {
			return strconv.FormatFloat(count, 'f', -1, 64), true
		}
	case string:
		trimmed := strings.TrimSpace(count)
		if trimmed == "" {
			return "", false
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err == nil {
			return trimmed, parsed > 0
		}
		if trimmed != "0" {
			return trimmed, true
		}
	}
	return "", false
}

func targetToHostPort(target string) string {
	if target == "" {
		return ""
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return target
	}
	return parsed.Host
}

func normalizeHostPort(hp string) string {
	return strings.TrimSpace(strings.ToLower(hp))
}
