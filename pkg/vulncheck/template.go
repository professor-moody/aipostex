package vulncheck

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/professor-moody/aipostex/pkg/report"
)

// Template represents a single vulnerability check template
type Template struct {
	ID string `yaml:"id"`
	// Transport selects the wire protocol the engine drives the template over.
	// Empty (or "http") runs the steps as raw HTTP requests. "mcp" drives them
	// through a Model Context Protocol client (initialize handshake → session →
	// tools/list / tools/call) so stateful MCP servers can be exercised — a flat
	// HTTP request can never complete the MCP handshake. See executor_mcp.go.
	Transport string            `yaml:"transport,omitempty"`
	Info      TemplateInfo      `yaml:"info"`
	Vars      map[string]string `yaml:"vars,omitempty"`
	Detect    []HTTPStep        `yaml:"detect,omitempty"`
	Checks    []Check           `yaml:"checks"`

	SourcePath string `yaml:"-"`
}

// TemplateInfo contains metadata about the vulnerability
type TemplateInfo struct {
	Name           string              `yaml:"name"`
	Type           string              `yaml:"type,omitempty"`
	Severity       string              `yaml:"severity"`
	CVSS           float64             `yaml:"cvss,omitempty"`
	Author         string              `yaml:"author"`
	Description    string              `yaml:"description"`
	References     []string            `yaml:"reference,omitempty"`
	Tags           []string            `yaml:"tags,omitempty"`
	Classification map[string][]string `yaml:"classification,omitempty"`
}

// HTTPStep represents a single HTTP request to send
type HTTPStep struct {
	Method     string            `yaml:"method"`
	ReadOnly   bool              `yaml:"read_only,omitempty"`
	Path       string            `yaml:"path"`
	Headers    map[string]string `yaml:"headers,omitempty"`
	Body       string            `yaml:"body,omitempty"`
	Matchers   []Matcher         `yaml:"matchers"`
	Extractors []Extractor       `yaml:"extractors,omitempty"`
}

// Matcher defines how to match an HTTP response
type Matcher struct {
	Type   string `yaml:"type"`
	Key    string `yaml:"key,omitempty"`
	Value  string `yaml:"value"`
	Negate bool   `yaml:"negate,omitempty"`
}

// Template type constants distinguish detection-only templates from those
// that actively exploit (send payloads, perform SSRF, read sensitive files,
// or invoke inference).
const (
	TemplateTypeDetection = "detection"
	TemplateTypeExploit   = "exploit"
)

// Transport constants select the wire protocol the engine uses to run a template.
const (
	TransportHTTP = "http"
	TransportMCP  = "mcp"
)

// Matcher types
const (
	MatchStatus          = "status"
	MatchBodyContains    = "body_contains"
	MatchBodyNotContains = "body_not_contains"
	MatchBodyRegex       = "body_regex"
	MatchHeaderContains  = "header_contains"
	MatchJSONPath        = "json_path"
)

// Extractor pulls data from responses for use in subsequent checks
type Extractor struct {
	Type  string `yaml:"type"`            // "regex", "json", "header"
	Name  string `yaml:"name"`            // Variable name
	Path  string `yaml:"path,omitempty"`  // JSON path expression
	Regex string `yaml:"regex,omitempty"` // Regex with capture group
	Group *int   `yaml:"group,omitempty"` // Regex capture group index (nil defaults to 1)
}

// Check represents a single vulnerability check within a template
type Check struct {
	Name            string            `yaml:"name"`
	Method          string            `yaml:"method"`
	ReadOnly        bool              `yaml:"read_only,omitempty"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers,omitempty"`
	Body            string            `yaml:"body,omitempty"`
	Matchers        []Matcher         `yaml:"matchers"`
	Extractors      []Extractor       `yaml:"extractors,omitempty"`
	Severity        string            `yaml:"severity"`
	Stage           string            `yaml:"stage,omitempty"`
	Landed          string            `yaml:"landed,omitempty"`
	AffectedVersion *AffectedVersion  `yaml:"affected_version,omitempty"`
	Finding         FindingTemplate   `yaml:"finding"`
}

type AffectedVersion struct {
	Variable string `yaml:"variable"`
	Range    string `yaml:"range"`
}

// FindingTemplate defines the output finding with variable interpolation
type FindingTemplate struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Remediation string `yaml:"remediation,omitempty"`
	Evidence    string `yaml:"evidence,omitempty"`
}

// LoadTemplate loads and validates a single template file
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading template %s: %w", path, err)
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parsing template %s: %w", path, err)
	}

	if err := tmpl.Validate(); err != nil {
		return nil, fmt.Errorf("validating template %s: %w", path, err)
	}
	tmpl.SourcePath = path

	return &tmpl, nil
}

func LoadTemplateFromFS(fsys fs.FS, path, sourcePath string) (*Template, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("reading template %s: %w", sourcePath, err)
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parsing template %s: %w", sourcePath, err)
	}

	if err := tmpl.Validate(); err != nil {
		return nil, fmt.Errorf("validating template %s: %w", sourcePath, err)
	}
	tmpl.SourcePath = sourcePath

	return &tmpl, nil
}

// LoadTemplatesFromDir loads all YAML templates from a directory tree
func LoadTemplatesFromDir(dir string) ([]*Template, error) {
	var templates []*Template
	var skipped []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip hidden directories (.git, .github, etc.) — they hold CI/VCS YAML,
			// not templates, and scanning them produces spurious "missing id" warnings.
			if name := info.Name(); name != "." && strings.HasPrefix(name, ".") && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		tmpl, err := LoadTemplate(path)
		if err != nil {
			// Warn + skip (one bad template must not kill the scan) but TRACK it.
			fmt.Fprintf(os.Stderr, "warning: skipping template %s: %v\n", path, err)
			skipped = append(skipped, filepath.Base(path))
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking template directory %s: %w", dir, err)
	}
	if len(skipped) > 0 {
		// Surface reduced coverage as one honest summary, not just per-file warnings that
		// scroll past — a scan that silently loads fewer templates than expected must say so.
		fmt.Fprintf(os.Stderr, "warning: %d template(s) skipped due to load errors — scan coverage reduced: %s\n",
			len(skipped), strings.Join(skipped, ", "))
	}

	return templates, nil
}

func LoadTemplatesFromFS(fsys fs.FS, dir, sourcePrefix string) ([]*Template, error) {
	var templates []*Template
	var skipped []string

	err := fs.WalkDir(fsys, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		sourcePath := path
		if sourcePrefix != "" {
			sourcePath = sourcePrefix + "/" + path
		}
		tmpl, err := LoadTemplateFromFS(fsys, path, sourcePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping template %s: %v\n", sourcePath, err)
			skipped = append(skipped, filepath.Base(sourcePath))
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking template directory %s: %w", dir, err)
	}
	if len(skipped) > 0 {
		// A shipped/embedded template that fails to load silently reduces coverage — say so
		// with one aggregate line (the enforced template count is the hard gate in CI).
		fmt.Fprintf(os.Stderr, "warning: %d template(s) skipped due to load errors — scan coverage reduced: %s\n",
			len(skipped), strings.Join(skipped, ", "))
	}

	return templates, nil
}

func LoadEmbeddedTemplates() ([]*Template, error) {
	return LoadTemplatesFromFS(embeddedTemplates, "templates", "embedded:pkg/vulncheck")
}

// Validate checks that a template has required fields and valid values
func (t *Template) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("template missing 'id'")
	}
	if t.Info.Name == "" {
		return fmt.Errorf("template %s missing 'info.name'", t.ID)
	}
	if t.Info.Severity == "" {
		return fmt.Errorf("template %s missing 'info.severity'", t.ID)
	}
	if !report.IsValidSeverity(t.Info.Severity) {
		return fmt.Errorf("template %s has invalid severity '%s'", t.ID, t.Info.Severity)
	}
	if t.Info.Type != "" && !strings.EqualFold(t.Info.Type, TemplateTypeDetection) && !strings.EqualFold(t.Info.Type, TemplateTypeExploit) {
		return fmt.Errorf("template %s has invalid type '%s' (must be detection or exploit)", t.ID, t.Info.Type)
	}
	if t.Transport != "" && !strings.EqualFold(t.Transport, TransportHTTP) && !strings.EqualFold(t.Transport, TransportMCP) {
		return fmt.Errorf("template %s has invalid transport '%s' (must be http or mcp)", t.ID, t.Transport)
	}
	if strings.TrimSpace(t.Info.Author) == "" {
		return fmt.Errorf("template %s missing 'info.author'", t.ID)
	}
	if strings.TrimSpace(t.Info.Description) == "" {
		return fmt.Errorf("template %s missing 'info.description'", t.ID)
	}
	for i, step := range t.Detect {
		if err := validateHTTPStep(fmt.Sprintf("template %s detect step %d", t.ID, i), step); err != nil {
			return err
		}
	}
	if len(t.Checks) == 0 {
		return fmt.Errorf("template %s has no checks", t.ID)
	}
	for i, check := range t.Checks {
		ctx := fmt.Sprintf("template %s check %d", t.ID, i)
		if check.Name == "" {
			return fmt.Errorf("%s missing name", ctx)
		}
		if err := validateHTTPStep(ctx, HTTPStep{
			Method:     check.Method,
			ReadOnly:   check.ReadOnly,
			Path:       check.Path,
			Headers:    check.Headers,
			Body:       check.Body,
			Matchers:   check.Matchers,
			Extractors: check.Extractors,
		}); err != nil {
			return err
		}
		if check.Severity != "" && !report.IsValidSeverity(check.Severity) {
			return fmt.Errorf("%s has invalid severity '%s'", ctx, check.Severity)
		}
		if strings.TrimSpace(check.Finding.Title) == "" {
			return fmt.Errorf("%s missing finding.title", ctx)
		}
		if strings.TrimSpace(check.Finding.Description) == "" {
			return fmt.Errorf("%s missing finding.description", ctx)
		}
		if check.AffectedVersion != nil {
			if strings.TrimSpace(check.AffectedVersion.Variable) == "" {
				return fmt.Errorf("%s affected_version missing variable", ctx)
			}
			if strings.TrimSpace(check.AffectedVersion.Range) == "" {
				return fmt.Errorf("%s affected_version missing range", ctx)
			}
			for _, part := range strings.Split(check.AffectedVersion.Range, ",") {
				if _, err := ParseVersionRange(part); err != nil {
					return fmt.Errorf("%s affected_version has invalid range %q: %w", ctx, check.AffectedVersion.Range, err)
				}
			}
		}
	}
	return nil
}

func validateHTTPStep(ctx string, step HTTPStep) error {
	if strings.TrimSpace(step.Method) == "" {
		return fmt.Errorf("%s missing method", ctx)
	}
	if strings.TrimSpace(step.Path) == "" {
		return fmt.Errorf("%s missing path", ctx)
	}
	if len(step.Matchers) == 0 {
		return fmt.Errorf("%s has no matchers", ctx)
	}
	for i, matcher := range step.Matchers {
		if err := validateMatcher(fmt.Sprintf("%s matcher %d", ctx, i), matcher); err != nil {
			return err
		}
	}
	for i, ext := range step.Extractors {
		if err := validateExtractor(fmt.Sprintf("%s extractor %d", ctx, i), ext); err != nil {
			return err
		}
	}
	return nil
}

func validateMatcher(ctx string, matcher Matcher) error {
	switch matcher.Type {
	case MatchStatus:
		if strings.TrimSpace(matcher.Value) == "" {
			return fmt.Errorf("%s missing status value", ctx)
		}
		if _, err := strconv.Atoi(matcher.Value); err != nil {
			return fmt.Errorf("%s has invalid status value %q", ctx, matcher.Value)
		}
	case MatchBodyContains, MatchBodyNotContains:
		if strings.TrimSpace(matcher.Value) == "" {
			return fmt.Errorf("%s missing value", ctx)
		}
	case MatchBodyRegex:
		if strings.TrimSpace(matcher.Value) == "" {
			return fmt.Errorf("%s missing regex", ctx)
		}
		if _, err := regexp.Compile(matcher.Value); err != nil {
			return fmt.Errorf("%s has invalid regex %q: %w", ctx, matcher.Value, err)
		}
	case MatchHeaderContains:
		if strings.TrimSpace(matcher.Key) == "" {
			return fmt.Errorf("%s missing header key", ctx)
		}
		if strings.TrimSpace(matcher.Value) == "" {
			return fmt.Errorf("%s missing header value", ctx)
		}
	case MatchJSONPath:
		if strings.TrimSpace(matcher.Key) == "" {
			return fmt.Errorf("%s missing json path key", ctx)
		}
	default:
		return fmt.Errorf("%s has unsupported matcher type %q", ctx, matcher.Type)
	}
	return nil
}

func validateExtractor(ctx string, ext Extractor) error {
	if strings.TrimSpace(ext.Name) == "" {
		return fmt.Errorf("%s missing name", ctx)
	}
	switch ext.Type {
	case "regex":
		if strings.TrimSpace(ext.Regex) == "" {
			return fmt.Errorf("%s missing regex", ctx)
		}
		if _, err := regexp.Compile(ext.Regex); err != nil {
			return fmt.Errorf("%s has invalid regex %q: %w", ctx, ext.Regex, err)
		}
	case "json", "header":
		if strings.TrimSpace(ext.Path) == "" {
			return fmt.Errorf("%s missing path", ctx)
		}
	default:
		return fmt.Errorf("%s has unsupported extractor type %q", ctx, ext.Type)
	}
	return nil
}

// IsExploit returns true when the template is classified as an exploitation
// template. Templates without an explicit type default to detection.
func (t *Template) IsExploit() bool {
	return strings.EqualFold(t.Info.Type, TemplateTypeExploit)
}

// HasTag returns true if the template has the given tag
func (t *Template) HasTag(tag string) bool {
	tag = strings.ToLower(tag)
	for _, tt := range t.Info.Tags {
		if strings.ToLower(tt) == tag {
			return true
		}
	}
	return false
}

// HasAnyTag returns true if the template has any of the given tags
func (t *Template) HasAnyTag(tags []string) bool {
	for _, tag := range tags {
		if t.HasTag(tag) {
			return true
		}
	}
	return false
}

// MaxCheckSeverity returns the highest severity across the template-level
// severity and all per-check severity overrides.
func (t *Template) MaxCheckSeverity() string {
	max := t.Info.Severity
	for _, c := range t.Checks {
		if c.Severity != "" && severityPriority(c.Severity) > severityPriority(max) {
			max = c.Severity
		}
	}
	return max
}

// MatchesSeverity returns true if the template matches any of the given
// severities: template-level severity, the max check severity, or any
// individual check's effective severity (check override or template default).
func (t *Template) MatchesSeverity(severities []string) bool {
	for _, s := range severities {
		if strings.EqualFold(t.Info.Severity, s) || strings.EqualFold(t.MaxCheckSeverity(), s) {
			return true
		}
		for _, c := range t.Checks {
			effective := c.Severity
			if effective == "" {
				effective = t.Info.Severity
			}
			if strings.EqualFold(effective, s) {
				return true
			}
		}
	}
	return false
}

func severityPriority(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info":
		return 0
	default:
		return -1
	}
}
