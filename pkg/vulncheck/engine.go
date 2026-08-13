package vulncheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tidwall/gjson"

	"github.com/professor-moody/aipostex/internal/runtimehttp"
	"github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/report"
)

// ProgressFunc is called during template scanning to report progress.
type ProgressFunc func(event ProgressEvent)

// ProgressEvent describes a template scan progress update.
type ProgressEvent struct {
	Type         string // "start", "match", "error", "complete"
	TemplateID   string
	Target       string
	Error        string // populated on Type="error"
	FindingCount int
	Severity     string
	Title        string
	Current      int
	Total        int
	Findings     []report.Finding
}

// ScanMode controls which template types the engine will execute.
type ScanMode string

const (
	// ModeDetect runs only detection templates (safe, no exploitation).
	ModeDetect ScanMode = "detect"
	// ModeFull runs all templates including exploitation.
	ModeFull ScanMode = "full"
)

// Engine executes vulnerability templates against targets
type Engine struct {
	Context        context.Context
	Templates      []*Template
	HTTPClient     *http.Client
	Concurrency    int
	Verbose        bool
	Mode           ScanMode
	OnProgress     ProgressFunc
	defaultTimeout time.Duration
	httpOnce       sync.Once
}

type ScanMetrics struct {
	RequestErrors   int
	TemplateErrors  int
	DetectErrors    int
	FailedTemplates []TemplateFailure
}

// TemplateFailure records a template that could not be executed.
type TemplateFailure struct {
	TemplateID string
	Target     string
	Error      string
}

const compiledRegexCacheLimit = 1024

// compiledRegexCache caches compiled regular expressions keyed by pattern string.
// The cache is soft-bounded: once the stored count reaches compiledRegexCacheLimit,
// new patterns are still compiled but no longer cached.
var compiledRegexCache sync.Map
var compiledRegexCacheCount atomic.Int64

// NewEngine creates a new template execution engine
func NewEngine(timeout time.Duration, concurrency int) *Engine {
	return &Engine{
		Context:        context.Background(),
		Templates:      make([]*Template, 0),
		Concurrency:    concurrency,
		Mode:           ModeDetect,
		defaultTimeout: timeout,
	}
}

func (e *Engine) httpClient() *http.Client {
	e.httpOnce.Do(func() {
		if e.HTTPClient == nil {
			c, err := common.NewHTTPClient(e.defaultTimeout)
			if err != nil {
				e.HTTPClient = &http.Client{
					Timeout:       e.defaultTimeout,
					CheckRedirect: runtimehttp.LimitRedirects(3),
				}
				return
			}
			e.HTTPClient = c
		}
	})
	return e.HTTPClient
}

// LoadTemplates loads templates from one or more directories
func (e *Engine) LoadTemplates(dirs ...string) error {
	for _, dir := range dirs {
		templates, err := LoadTemplatesFromDir(dir)
		if err != nil {
			return err
		}
		for _, tmpl := range templates {
			e.addTemplate(tmpl, true)
		}
	}
	return nil
}

func (e *Engine) LoadEmbeddedTemplates() error {
	templates, err := LoadEmbeddedTemplates()
	if err != nil {
		return err
	}
	for _, tmpl := range templates {
		e.addTemplate(tmpl, true)
	}
	return nil
}

// AddTemplate validates and adds a single template to the engine.
func (e *Engine) AddTemplate(tmpl *Template) error {
	if err := tmpl.Validate(); err != nil {
		return fmt.Errorf("invalid template %q: %w", tmpl.ID, err)
	}
	e.addTemplate(tmpl, false)
	return nil
}

func (e *Engine) addTemplate(tmpl *Template, warnOnDuplicate bool) {
	for i, existing := range e.Templates {
		if existing.ID != tmpl.ID {
			continue
		}
		if warnOnDuplicate {
			fmt.Fprintf(os.Stderr, "warning: duplicate template id %s: %s overridden by %s\n", tmpl.ID, existing.SourcePath, tmpl.SourcePath)
		}
		e.Templates[i] = tmpl
		return
	}
	e.Templates = append(e.Templates, tmpl)
}

// FilteredTemplates returns templates matching the given tags, severities,
// and the engine's scan mode. In ModeDetect, exploit-type templates are
// excluded automatically.
func (e *Engine) FilteredTemplates(tags, severities []string) []*Template {
	var filtered []*Template
	for _, tmpl := range e.Templates {
		if e.Mode == ModeDetect && tmpl.IsExploit() {
			continue
		}
		tagMatch := len(tags) == 0 || tmpl.HasAnyTag(tags)
		sevMatch := len(severities) == 0 || tmpl.MatchesSeverity(severities)
		if tagMatch && sevMatch {
			filtered = append(filtered, tmpl)
		}
	}
	return filtered
}

// Scan runs all matching templates against a target
func (e *Engine) Scan(target string, tags, severities []string) ([]report.Finding, error) {
	findings, _, err := e.ScanDetailed(target, tags, severities)
	return findings, err
}

// ScanDetailed runs all matching templates against a target and reports request-error accounting.
func (e *Engine) ScanDetailed(target string, tags, severities []string) ([]report.Finding, ScanMetrics, error) {
	templates := e.FilteredTemplates(tags, severities)
	if len(templates) == 0 {
		return nil, ScanMetrics{}, fmt.Errorf("no templates match the specified filters")
	}

	var (
		findings  []report.Finding
		metrics   ScanMetrics
		mu        sync.Mutex
		wg        sync.WaitGroup
		sem       = make(chan struct{}, e.Concurrency)
		completed int
		total     = len(templates)
	)

	for _, tmpl := range templates {
		if e.Context != nil && e.Context.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}

		go func(t *Template) {
			defer wg.Done()
			defer func() { <-sem }()
			if e.Context != nil && e.Context.Err() != nil {
				return
			}

			if e.OnProgress != nil {
				e.OnProgress(ProgressEvent{Type: "start", TemplateID: t.ID, Target: target, Total: total})
			}

			results, templateMetrics, err := e.ExecuteTemplateDetailed(t, target)
			if err != nil {
				if e.Verbose {
					fmt.Fprintf(os.Stderr, "  [debug] template %s error: %v\n", t.ID, err)
				}
				mu.Lock()
				metrics.FailedTemplates = append(metrics.FailedTemplates, TemplateFailure{
					TemplateID: t.ID,
					Target:     target,
					Error:      err.Error(),
				})
				mu.Unlock()
				if e.OnProgress != nil {
					e.OnProgress(ProgressEvent{Type: "error", TemplateID: t.ID, Target: target, Total: total, Error: err.Error()})
				}
				return
			}

			mu.Lock()
			findings = append(findings, results...)
			metrics.RequestErrors += templateMetrics.RequestErrors
			metrics.TemplateErrors += templateMetrics.TemplateErrors
			if templateMetrics.TemplateErrors > 0 || templateMetrics.RequestErrors > 0 {
				metrics.FailedTemplates = append(metrics.FailedTemplates, TemplateFailure{
					TemplateID: t.ID,
					Target:     target,
					Error:      fmt.Sprintf("%d template error(s), %d request error(s)", templateMetrics.TemplateErrors, templateMetrics.RequestErrors),
				})
			}
			completed++
			cur := completed
			mu.Unlock()

			if e.OnProgress != nil && len(results) > 0 {
				e.OnProgress(ProgressEvent{
					Type:         "match",
					TemplateID:   t.ID,
					Target:       target,
					FindingCount: len(results),
					Current:      cur,
					Total:        total,
					Findings:     results,
				})
			}
		}(tmpl)
	}

	wg.Wait()
	return findings, metrics, nil
}

// ExecuteTemplate runs a single template against a target
func (e *Engine) ExecuteTemplate(tmpl *Template, target string) ([]report.Finding, error) {
	findings, _, err := e.ExecuteTemplateDetailed(tmpl, target)
	return findings, err
}

// ExecuteTemplateDetailed runs a single template against a target and reports request-error accounting.
func (e *Engine) ExecuteTemplateDetailed(tmpl *Template, target string) ([]report.Finding, ScanMetrics, error) {
	// Normalize target URL
	target = strings.TrimRight(target, "/")

	// MCP-transport templates can't be driven over raw HTTP — they need the
	// stateful initialize → session → tools/call handshake. Hand them to the
	// MCP executor, which speaks the protocol via pkg/exploit/mcp.
	if strings.EqualFold(tmpl.Transport, TransportMCP) {
		return e.executeTemplateMCP(tmpl, target)
	}

	metrics := ScanMetrics{}
	variables := make(map[string]string, len(tmpl.Vars)) // Cross-step variable storage
	for k, v := range tmpl.Vars {
		variables[k] = v
	}

	// Phase 1: Detection — skip if service doesn't match
	if len(tmpl.Detect) > 0 {
		detected := false
		detectErrs := 0
		for _, step := range tmpl.Detect {
			if e.Context != nil && e.Context.Err() != nil {
				return nil, metrics, nil
			}
			matched, extractedVars, stepMetrics := e.executeStep(step, target, variables)
			metrics.RequestErrors += stepMetrics.RequestErrors
			metrics.TemplateErrors += stepMetrics.TemplateErrors
			detectErrs += stepMetrics.RequestErrors
			if matched {
				for k, v := range extractedVars {
					variables[k] = v
				}
				detected = true
				break // Any detect step matching is sufficient
			}
		}
		if !detected {
			if detectErrs > 0 {
				metrics.DetectErrors += detectErrs
				fmt.Fprintf(os.Stderr, "  [warn] template %s: detect phase had %d error(s) against %s, service may be present but unreachable\n", tmpl.ID, detectErrs, target)
			}
			return nil, metrics, nil
		}
	}

	// Phase 2: Execute checks
	var findings []report.Finding

	for _, check := range tmpl.Checks {
		if e.Context != nil && e.Context.Err() != nil {
			return findings, metrics, nil
		}
		finding, extractedVars, matched, checkMetrics := e.executeCheck(check, tmpl, target, variables)
		metrics.RequestErrors += checkMetrics.RequestErrors
		metrics.TemplateErrors += checkMetrics.TemplateErrors
		if matched && finding != nil {
			findings = append(findings, *finding)
		}
		// Merge extracted variables for use in subsequent checks
		for k, v := range extractedVars {
			variables[k] = v
		}
	}

	return findings, metrics, nil
}

// executeStep runs an HTTP step and returns whether all matchers matched.
// The returned ScanMetrics distinguishes template errors (e.g. malformed URLs
// from interpolation) from network errors.
func (e *Engine) executeStep(step HTTPStep, target string, variables map[string]string) (bool, map[string]string, ScanMetrics) {
	stepURL := target + interpolate(step.Path, variables)

	body := interpolate(step.Body, variables)
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}

	req, err := http.NewRequestWithContext(e.requestContext(), step.Method, stepURL, bodyReader)
	if err != nil {
		return false, nil, ScanMetrics{TemplateErrors: 1}
	}

	for k, v := range step.Headers {
		req.Header.Set(k, interpolate(v, variables))
	}
	applyDefaultContentType(req, body)

	resp, err := e.httpClient().Do(req)
	if err != nil {
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "  [debug] %s %s: %v\n", step.Method, stepURL, err)
		}
		return false, nil, ScanMetrics{RequestErrors: 1}
	}
	defer resp.Body.Close()

	respBody, truncated, err := common.ReadAllCapped(resp.Body, common.TemplateBodyLimit)
	if err != nil {
		return false, nil, ScanMetrics{RequestErrors: 1}
	}
	if truncated {
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "  [debug] response exceeded %d bytes for %s %s; treating detect step as incomplete\n",
				common.TemplateBodyLimit, step.Method, stepURL)
		}
		return false, nil, ScanMetrics{RequestErrors: 1}
	}
	if int64(len(respBody)) == common.TemplateBodyLimit && e.Verbose {
		fmt.Fprintf(os.Stderr, "  [debug] response read reached %d bytes for %s %s\n",
			common.TemplateBodyLimit, step.Method, stepURL)
	}

	respBodyStr := string(respBody)
	if !matchAll(step.Matchers, resp.StatusCode, respBodyStr, resp.Header) {
		return false, nil, ScanMetrics{}
	}

	extracted := make(map[string]string)
	for _, ext := range step.Extractors {
		value := extract(ext, respBodyStr, resp.Header)
		if value != "" {
			extracted[ext.Name] = value
		}
	}

	return true, extracted, ScanMetrics{}
}

// executeCheck runs a check and returns a finding if matched, plus extracted variables.
// The returned ScanMetrics distinguishes template errors from network errors.
func (e *Engine) executeCheck(check Check, tmpl *Template, target string, variables map[string]string) (*report.Finding, map[string]string, bool, ScanMetrics) {
	checkURL := target + interpolate(check.Path, variables)

	body := interpolate(check.Body, variables)
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}

	req, err := http.NewRequestWithContext(e.requestContext(), check.Method, checkURL, bodyReader)
	if err != nil {
		return nil, nil, false, ScanMetrics{TemplateErrors: 1}
	}

	for k, v := range check.Headers {
		req.Header.Set(k, interpolate(v, variables))
	}
	applyDefaultContentType(req, body)

	resp, err := e.httpClient().Do(req)
	if err != nil {
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "  [debug] %s %s: %v\n", check.Method, checkURL, err)
		}
		return nil, nil, false, ScanMetrics{RequestErrors: 1}
	}
	defer resp.Body.Close()

	respBody, truncated, err := common.ReadAllCapped(resp.Body, common.TemplateBodyLimit)
	if err != nil {
		return nil, nil, false, ScanMetrics{RequestErrors: 1}
	}
	if truncated {
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "  [debug] response exceeded %d bytes for %s %s; treating check as incomplete\n",
				common.TemplateBodyLimit, check.Method, checkURL)
		}
		return nil, nil, false, ScanMetrics{RequestErrors: 1}
	}
	if int64(len(respBody)) == common.TemplateBodyLimit && e.Verbose {
		fmt.Fprintf(os.Stderr, "  [debug] response read reached %d bytes for %s %s\n",
			common.TemplateBodyLimit, check.Method, checkURL)
	}

	respBodyStr := string(respBody)

	// Check matchers
	if !matchAll(check.Matchers, resp.StatusCode, respBodyStr, resp.Header) {
		return nil, nil, false, ScanMetrics{}
	}

	// Extract variables
	extracted := make(map[string]string)
	for _, ext := range check.Extractors {
		value := extract(ext, respBodyStr, resp.Header)
		if value != "" {
			extracted[ext.Name] = value
		}
	}

	// Merge with existing variables for interpolation
	allVars := make(map[string]string)
	for k, v := range variables {
		allVars[k] = v
	}
	for k, v := range extracted {
		allVars[k] = v
	}

	advisoryConfidence := ""
	versionUnparseable := false
	if check.AffectedVersion != nil {
		versionValue := strings.TrimSpace(allVars[check.AffectedVersion.Variable])
		if versionValue != "" {
			affected, err := VersionSatisfies(versionValue, check.AffectedVersion.Range)
			switch {
			case err != nil:
				// The target's version string could not be parsed (e.g.
				// "1.2.3rc1", "2.10.0.dev0", "1.0.0.post1"). Suppressing the
				// finding here would conflate "couldn't determine the version"
				// with "not affected" — a silent false negative on a CVE check.
				// Report at the same lower confidence used when no version was
				// extracted, and annotate so the operator can verify manually.
				advisoryConfidence = "service-exposed-risk"
				versionUnparseable = true
			case !affected:
				return nil, extracted, false, ScanMetrics{}
			default:
				advisoryConfidence = "affected-version-confirmed"
			}
		} else if tmpl.IsExploit() {
			advisoryConfidence = "exploit-proof"
		} else {
			advisoryConfidence = "service-exposed-risk"
		}
	}

	finding := e.buildCheckFinding(check, tmpl, target, allVars, extracted,
		advisoryConfidence, versionUnparseable, check.Method, checkURL, resp.StatusCode, respBodyStr)
	return finding, extracted, true, ScanMetrics{}
}

// buildCheckFinding constructs the report.Finding for a matched check. It is
// shared by the HTTP (executeCheck) and MCP (executeMCPCheck) execution paths so
// landed, evidence, and metadata are derived identically regardless of
// transport. evidenceMethod/evidenceURL/status/body feed the auto-evidence
// fallback used when the template supplies no explicit evidence string. The
// caller guarantees advisoryConfidence is only non-empty when check.AffectedVersion
// is set (it is derived from it).
func (e *Engine) buildCheckFinding(check Check, tmpl *Template, target string, allVars, extracted map[string]string,
	advisoryConfidence string, versionUnparseable bool, evidenceMethod, evidenceURL string, status int, body string) *report.Finding {
	severity := check.Severity
	if severity == "" {
		severity = tmpl.Info.Severity
	}

	finding := &report.Finding{
		// Include a short deterministic target discriminator so the SAME check run
		// against DIFFERENT hosts does not collide on one ID (the dossier writes
		// evidence/<ID>.txt; colliding IDs would overwrite each other). Re-running the
		// same check on the same target is still stable.
		ID:          fmt.Sprintf("%s-%s-%s", tmpl.ID, sanitizeID(check.Name), shortTargetHash(target)),
		Timestamp:   time.Now().UTC(),
		Source:      report.SourceVulnCheck,
		TemplateID:  tmpl.ID,
		Target:      target,
		Title:       interpolate(check.Finding.Title, allVars),
		Severity:    severity,
		CVSS:        tmpl.Info.CVSS,
		Description: interpolate(check.Finding.Description, allVars),
		Remediation: interpolate(check.Finding.Remediation, allVars),
		Evidence:    interpolate(check.Finding.Evidence, allVars),
		Tags:        tmpl.Info.Tags,
		References:  tmpl.Info.References,
		Metadata:    map[string]interface{}{"scan_mode": string(e.Mode)},
	}
	if advisoryConfidence != "" && check.AffectedVersion != nil {
		finding.Metadata["advisory_confidence"] = advisoryConfidence
		finding.Metadata["affected_version_range"] = check.AffectedVersion.Range
		if versionValue := strings.TrimSpace(allVars[check.AffectedVersion.Variable]); versionValue != "" {
			finding.Metadata["affected_version"] = versionValue
		}
		if versionUnparseable {
			finding.Metadata["version_unparseable"] = true
		}
	}
	if len(extracted) > 0 {
		extractedMetadata := make(map[string]interface{}, len(extracted))
		for key, value := range extracted {
			extractedMetadata[key] = value
			finding.Metadata[key] = value
		}
		finding.Metadata["extracted"] = extractedMetadata
	}

	if check.Stage != "" || check.Landed != "" {
		if check.Stage != "" {
			finding.Metadata["stage"] = check.Stage
		}
		if check.Landed != "" {
			finding.Metadata["landed"] = check.Landed
		}
	} else {
		// Honesty floor: a template that does not declare what it actually proved is
		// graded at the conservative minimum — never inferred up from the
		// detection-vs-exploit classification. A bare check that only observed a 2xx
		// is `recon`/`reachable`, NOT `impact`/`takeover-capable`. Templates that
		// genuinely read/execute/take over MUST declare stage+landed explicitly.
		finding.Metadata["stage"] = report.StageRecon
		finding.Metadata["landed"] = "reachable"
	}
	if finding.Evidence == "" {
		finding.Evidence = buildAutoEvidence(evidenceMethod, evidenceURL, status, body)
	}

	return finding
}

const autoEvidenceMaxBody = 2048

func buildAutoEvidence(method, url string, status int, body string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("=== REQUEST ===\n%s %s\n\n", method, url))
	b.WriteString(fmt.Sprintf("=== RESPONSE (%d) ===\n", status))
	if len(body) > autoEvidenceMaxBody {
		b.WriteString(body[:autoEvidenceMaxBody])
		b.WriteString(fmt.Sprintf("\n... truncated (%d bytes total)", len(body)))
	} else {
		b.WriteString(body)
	}
	return b.String()
}

// applyDefaultContentType sets Content-Type when a body is present but no
// Content-Type header has been specified. JSON-like bodies get
// application/json; everything else gets application/x-www-form-urlencoded.
func applyDefaultContentType(req *http.Request, body string) {
	if body == "" || req.Header.Get("Content-Type") != "" {
		return
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
}

// matchAll returns true if ALL matchers match the response
func matchAll(matchers []Matcher, statusCode int, body string, headers http.Header) bool {
	for _, m := range matchers {
		if !matchOne(m, statusCode, body, headers) {
			return false
		}
	}
	return true
}

// matchOne evaluates a single matcher against the response
func matchOne(m Matcher, statusCode int, body string, headers http.Header) bool {
	result := false

	switch m.Type {
	case MatchStatus:
		expected, err := strconv.Atoi(m.Value)
		if err != nil {
			return false
		}
		result = statusCode == expected

	case MatchBodyContains:
		result = strings.Contains(body, m.Value)

	case MatchBodyNotContains:
		result = !strings.Contains(body, m.Value)

	case MatchBodyRegex:
		re, err := compileRegexCached(m.Value)
		if err != nil {
			return false
		}
		result = re.MatchString(body)

	case MatchHeaderContains:
		headerVal := headers.Get(m.Key)
		result = strings.Contains(strings.ToLower(headerVal), strings.ToLower(m.Value))

	case MatchJSONPath:
		jsonResult := gjson.Get(body, m.Key)
		if m.Value == "" {
			result = jsonResult.Exists()
		} else {
			result = jsonResult.String() == m.Value
		}
	}

	if m.Negate {
		return !result
	}
	return result
}

// extract pulls a value from the response using an extractor definition
func extract(ext Extractor, body string, headers http.Header) string {
	switch ext.Type {
	case "regex":
		re, err := compileRegexCached(ext.Regex)
		if err != nil {
			return ""
		}
		matches := re.FindStringSubmatch(body)
		group := 1
		if ext.Group != nil {
			group = *ext.Group
		}
		if len(matches) > group {
			return matches[group]
		}

	case "json":
		result := gjson.Get(body, ext.Path)
		if result.Exists() {
			return result.String()
		}

	case "header":
		return headers.Get(ext.Path)
	}

	return ""
}

func compileRegexCached(pattern string) (*regexp.Regexp, error) {
	if cached, ok := compiledRegexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	if compiledRegexCacheCount.Load() >= compiledRegexCacheLimit {
		return compiled, nil
	}
	actual, loaded := compiledRegexCache.LoadOrStore(pattern, compiled)
	if !loaded {
		compiledRegexCacheCount.Add(1)
	}
	return actual.(*regexp.Regexp), nil
}

// interpolate replaces {{variable}} placeholders with values from the variables map.
// By design, variable values are injected without sanitisation. This is intentional:
// as an offensive tool, templates must be able to construct arbitrary payloads
// (e.g., path traversal, command injection strings). Template authors are trusted;
// templates should not be loaded from untrusted sources.
func interpolate(s string, vars map[string]string) string {
	if vars == nil || !strings.Contains(s, "{{") {
		return s
	}
	result := s
	for k, v := range vars {
		result = strings.ReplaceAll(result, "{{"+k+"}}", v)
	}
	return result
}

// sanitizeID converts a check name to a safe ID component
func sanitizeID(name string) string {
	name = strings.ToLower(name)
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		if r == ' ' || r == '_' {
			return '-'
		}
		return -1
	}, name)
	return strings.Trim(name, "-")
}

// shortTargetHash returns a short (8-hex) deterministic discriminator for a target,
// so per-template-check finding IDs are unique across hosts while staying stable for
// re-runs of the same check on the same target.
func shortTargetHash(target string) string {
	sum := sha256.Sum256([]byte(target))
	return hex.EncodeToString(sum[:4])
}

func (e *Engine) requestContext() context.Context {
	if e.Context != nil {
		return e.Context
	}
	return context.Background()
}
