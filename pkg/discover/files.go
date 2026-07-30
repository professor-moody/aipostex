package discover

import (
	"context"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/professor-moody/aipostex/pkg/report"
)

// FileRule defines a pattern for discovering AI artifacts on the filesystem
type FileRule struct {
	Name            string   `yaml:"name"`
	Category        string   `yaml:"category"`
	Severity        string   `yaml:"severity"`
	Description     string   `yaml:"description,omitempty"`
	FilePatterns    []string `yaml:"file_patterns,omitempty"`    // Glob patterns for filenames
	PathPatterns    []string `yaml:"path_patterns,omitempty"`    // Glob patterns for full paths
	ContentPatterns []string `yaml:"content_patterns,omitempty"` // Regex patterns for file content
	MaxFileSize     int64    `yaml:"max_file_size,omitempty"`    // Max size to read for content matching (bytes)

	// Compiled regexes (populated at load time)
	compiledContent []*regexp.Regexp
}

// FileRuleSet is a collection of rules loaded from YAML
type FileRuleSet struct {
	Rules []FileRule `yaml:"rules"`
}

// FileScanner walks directories and matches files against rules
type FileScanner struct {
	Context             context.Context
	Rules               []FileRule
	ExcludePaths        []string
	ExcludeExtensions   []string
	ExcludeFilePatterns []string // filepath.Match globs on the base filename
	Workers             int
	MaxFileRead         int64 // Default max bytes to read for content matching
}

type ScanStats struct {
	FilesConsidered int64
	WalkErrors      int64
	ExcludedDirHits int64
	WalkErrorPaths  []string
	walkErrorMu     sync.Mutex
}

// FileMatch represents a single rule match on the filesystem
type FileMatch struct {
	Rule       FileRule
	Path       string
	MatchedOn  string // "filename", "path", "content"
	ContentHit string // The matched content (redacted if needed)
	FileSize   int64
}

// NewFileScanner creates a scanner with default settings
func NewFileScanner(workers int) *FileScanner {
	return &FileScanner{
		Context:     context.Background(),
		Workers:     workers,
		MaxFileRead: 10 * 1024 * 1024, // 10MB default
		ExcludePaths: []string{
			".git", "node_modules", "__pycache__", "venv", ".venv",
			".npm", ".yarn", "vendor", ".tox", "dist",
		},
		ExcludeExtensions: []string{
			".example", ".sample", ".template",
		},
		// Default-exclude aipostex's own artifacts so scanning a directory that holds
		// prior runs (checkpoints, report bundles, capture logs) doesn't re-ingest them
		// as findings. Matched as filepath.Match globs against the base filename.
		ExcludeFilePatterns: []string{
			"aipostex-checkpoint-*.jsonl",
			"aipostex-*-findings.jsonl",
			"all-findings.jsonl",
			"merged-engagement.json",
		},
	}
}

// LoadRules loads file discovery rules from a YAML file
func LoadRules(path string) ([]FileRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %s: %w", path, err)
	}

	var ruleSet FileRuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return nil, fmt.Errorf("parsing rules file %s: %w", path, err)
	}

	// Compile regex patterns
	for i := range ruleSet.Rules {
		rule := &ruleSet.Rules[i]
		if err := validateRule(*rule); err != nil {
			return nil, err
		}
		for _, pattern := range rule.ContentPatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("rule '%s' invalid regex '%s': %w", rule.Name, pattern, err)
			}
			rule.compiledContent = append(rule.compiledContent, re)
		}
		// Rules without content patterns use filename/path only; keep MaxFileSize 0 so
		// we do not imply a content read budget. Rules with content patterns default to 10MB.
		if rule.MaxFileSize == 0 && len(rule.ContentPatterns) > 0 {
			rule.MaxFileSize = 10 * 1024 * 1024 // Default 10MB
		}
	}

	return ruleSet.Rules, nil
}

func LoadRulesFromFS(fsys iofs.FS, path, sourcePath string) ([]FileRule, error) {
	data, err := iofs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %s: %w", sourcePath, err)
	}

	var ruleSet FileRuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return nil, fmt.Errorf("parsing rules file %s: %w", sourcePath, err)
	}

	for i := range ruleSet.Rules {
		rule := &ruleSet.Rules[i]
		if err := validateRule(*rule); err != nil {
			return nil, err
		}
		for _, pattern := range rule.ContentPatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("rule '%s' invalid regex '%s': %w", rule.Name, pattern, err)
			}
			rule.compiledContent = append(rule.compiledContent, re)
		}
		if rule.MaxFileSize == 0 && len(rule.ContentPatterns) > 0 {
			rule.MaxFileSize = 10 * 1024 * 1024
		}
	}

	return ruleSet.Rules, nil
}

func validateRule(rule FileRule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("rule missing name")
	}
	if strings.TrimSpace(rule.Category) == "" {
		return fmt.Errorf("rule '%s' missing category", rule.Name)
	}
	if !report.IsValidSeverity(rule.Severity) {
		return fmt.Errorf("rule '%s' has invalid severity '%s'", rule.Name, rule.Severity)
	}
	if len(rule.FilePatterns) == 0 && len(rule.PathPatterns) == 0 && len(rule.ContentPatterns) == 0 {
		return fmt.Errorf("rule '%s' has no file, path, or content patterns", rule.Name)
	}
	if rule.MaxFileSize < 0 {
		return fmt.Errorf("rule '%s' has negative max_file_size", rule.Name)
	}
	for _, pattern := range rule.FilePatterns {
		if !strings.Contains(pattern, "**") {
			if _, err := filepath.Match(pattern, "test"); err != nil {
				return fmt.Errorf("rule '%s' has invalid file pattern '%s': %w", rule.Name, pattern, err)
			}
		}
	}
	for _, pattern := range rule.PathPatterns {
		if !strings.Contains(pattern, "**") {
			if _, err := filepath.Match(pattern, "test"); err != nil {
				return fmt.Errorf("rule '%s' has invalid path pattern '%s': %w", rule.Name, pattern, err)
			}
		}
	}
	return nil
}

// LoadRulesFromDir loads all rule YAML files from a directory
func LoadRulesFromDir(dir string) ([]FileRule, error) {
	var allRules []FileRule

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rules, err := LoadRules(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping rules file %s: %v\n", path, err)
			return nil
		}
		allRules = append(allRules, rules...)
		return nil
	})

	return allRules, err
}

func LoadRulesDirFromFS(fsys iofs.FS, dir, sourcePrefix string) ([]FileRule, error) {
	var allRules []FileRule

	err := iofs.WalkDir(fsys, dir, func(path string, d iofs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		sourcePath := path
		if sourcePrefix != "" {
			sourcePath = sourcePrefix + "/" + path
		}
		rules, err := LoadRulesFromFS(fsys, path, sourcePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping rules file %s: %v\n", sourcePath, err)
			return nil
		}
		allRules = append(allRules, rules...)
		return nil
	})

	return allRules, err
}

func LoadEmbeddedRules() ([]FileRule, error) {
	return LoadRulesDirFromFS(embeddedRules, "rules", "embedded:pkg/discover")
}

// Scan walks the given paths and returns findings
func (fs *FileScanner) Scan(paths []string) ([]report.Finding, error) {
	findings, _, err := fs.ScanDetailed(paths)
	return findings, err
}

// canonicalizeRoots deduplicates and subsumes overlapping scan roots so that
// no path is walked more than once.
func canonicalizeRoots(paths []string) []string {
	cleaned := make([]string, 0, len(paths))
	for _, p := range paths {
		c := filepath.Clean(p)
		if c != "" {
			cleaned = append(cleaned, c)
		}
	}
	sort.Strings(cleaned)

	var result []string
	for _, p := range cleaned {
		subsumed := false
		for _, kept := range result {
			if p == kept || strings.HasPrefix(p, kept+string(filepath.Separator)) {
				subsumed = true
				break
			}
		}
		if !subsumed {
			result = append(result, p)
		}
	}
	return result
}

func (fs *FileScanner) ScanDetailed(paths []string) ([]report.Finding, *ScanStats, error) {
	paths = canonicalizeRoots(paths)
	fileChan := make(chan string, 100)
	resultChan := make(chan report.Finding, 100)
	var wg sync.WaitGroup
	stats := &ScanStats{}

	// Start workers
	for i := 0; i < fs.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				if fs.Context != nil && fs.Context.Err() != nil {
					return
				}
				matches := fs.matchFile(path)
				for _, m := range matches {
					resultChan <- m.ToFinding()
				}
			}
		}()
	}

	// Collect results
	var findings []report.Finding
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for f := range resultChan {
			findings = append(findings, f)
		}
	}()

	// Walk directories
	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, d iofs.DirEntry, err error) error {
			if fs.Context != nil && fs.Context.Err() != nil {
				return fs.Context.Err()
			}
			if err != nil {
				atomic.AddInt64(&stats.WalkErrors, 1)
				stats.walkErrorMu.Lock()
				if len(stats.WalkErrorPaths) < 100 {
					stats.WalkErrorPaths = append(stats.WalkErrorPaths, path)
				}
				stats.walkErrorMu.Unlock()
				return nil
			}
			if d.IsDir() {
				base := filepath.Base(path)
				for _, exclude := range fs.ExcludePaths {
					if base == exclude {
						atomic.AddInt64(&stats.ExcludedDirHits, 1)
						return filepath.SkipDir
					}
				}
				return nil
			}
			atomic.AddInt64(&stats.FilesConsidered, 1)
			base := filepath.Base(path)
			for _, ext := range fs.ExcludeExtensions {
				if strings.HasSuffix(strings.ToLower(base), ext) {
					return nil
				}
			}
			for _, pattern := range fs.ExcludeFilePatterns {
				if ok, _ := filepath.Match(pattern, base); ok {
					return nil
				}
			}
			fileChan <- path
			return nil
		})
		if err == context.Canceled {
			break
		}
		if err != nil {
			atomic.AddInt64(&stats.WalkErrors, 1)
			fmt.Fprintf(os.Stderr, "warning: error walking %s: %v\n", root, err)
		}
	}

	close(fileChan)
	wg.Wait()
	close(resultChan)
	collectWg.Wait()

	return findings, stats, nil
}

// matchFile checks a single file against all rules.
// When a file matches a rule on filename or path AND the rule also has content
// patterns, the content is checked first to produce richer evidence (the actual
// matched snippet). File content is read lazily and cached for the file.
func (s *FileScanner) matchFile(path string) []FileMatch {
	var matches []FileMatch
	fileName := filepath.Base(path)

	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	fileSize := info.Size()

	var cachedContent []byte
	var contentRead bool
	getContent := func() ([]byte, error) {
		if contentRead {
			return cachedContent, nil
		}
		contentRead = true
		var readErr error
		cachedContent, readErr = readFileHead(path, s.MaxFileRead)
		return cachedContent, readErr
	}

	for _, rule := range s.Rules {
		nameHit := false
		for _, pattern := range rule.FilePatterns {
			if matchGlob(pattern, fileName) {
				nameHit = true
				break
			}
		}

		pathHit := false
		if !nameHit {
			for _, pattern := range rule.PathPatterns {
				if matchGlob(pattern, path) {
					pathHit = true
					break
				}
			}
		}

		eligible := nameHit || pathHit || (len(rule.FilePatterns) == 0 && len(rule.PathPatterns) == 0)
		contentMatched := false
		contentEvaluated := false // non-empty bytes scanned with content_patterns
		maxContentFile := rule.MaxFileSize
		if maxContentFile == 0 && len(rule.compiledContent) > 0 {
			maxContentFile = 10 * 1024 * 1024 // match LoadRules default for content rules
		}
		if eligible && len(rule.compiledContent) > 0 && fileSize <= maxContentFile && fileSize > 0 {
			data, err := getContent()
			if err == nil && len(data) > 0 {
				contentEvaluated = true
				for _, re := range rule.compiledContent {
					locs := re.FindAllIndex(data, 20)
					for _, loc := range locs {
						contentMatched = true
						start := loc[0] - 80
						if start < 0 {
							start = 0
						}
						end := loc[1] + 120
						if end > len(data) {
							end = len(data)
						}
						matches = append(matches, FileMatch{
							Rule: rule, Path: path, MatchedOn: "content",
							ContentHit: string(data[start:end]), FileSize: fileSize,
						})
					}
				}
			}
		}

		if !contentMatched && (nameHit || pathHit) {
			fallbackMeta := len(rule.compiledContent) == 0 || !contentEvaluated
			if fallbackMeta {
				if nameHit {
					matches = append(matches, FileMatch{
						Rule: rule, Path: path, MatchedOn: "filename", FileSize: fileSize,
					})
				} else if pathHit {
					matches = append(matches, FileMatch{
						Rule: rule, Path: path, MatchedOn: "path", FileSize: fileSize,
					})
				}
			}
		}
	}

	return matches
}

// readFileHead reads up to maxBytes from the beginning of a file
func readFileHead(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

// ToFinding converts a FileMatch to a standard Finding
func (m FileMatch) ToFinding() report.Finding {
	evidence := fmt.Sprintf("Matched on %s", m.MatchedOn)
	if m.ContentHit != "" {
		evidence = fmt.Sprintf("Content match: ...%s...", m.ContentHit)
	}

	return report.Finding{
		ID:        fmt.Sprintf("file-%s-%s", sanitizeForID(m.Rule.Name), sanitizeForID(m.Path)),
		Timestamp: time.Now().UTC(),
		Source:    report.SourceFileDiscovery,
		Target:    m.Path,
		Title:     fmt.Sprintf("%s: %s", m.Rule.Category, m.Rule.Name),
		Severity:  m.Rule.Severity,
		Description: func() string {
			if m.Rule.Description != "" {
				return m.Rule.Description
			}
			return fmt.Sprintf("AI artifact discovered: %s (matched on %s)", m.Rule.Name, m.MatchedOn)
		}(),
		Evidence: evidence,
		Tags:     []string{m.Rule.Category},
		Metadata: map[string]interface{}{
			"file_size":  m.FileSize,
			"matched_on": m.MatchedOn,
			"rule_name":  m.Rule.Name,
		},
	}
}

// matchGlob handles both standard filepath.Match patterns and ** recursive
// globs. For patterns containing **, the ** segment matches any number of
// path components (including zero).
func matchGlob(pattern, path string) bool {
	if !strings.Contains(pattern, "**") {
		matched, _ := filepath.Match(pattern, path)
		return matched
	}
	return matchGlobSegments(splitGlobSegments(pattern), splitGlobSegments(path))
}

func splitGlobSegments(value string) []string {
	normalized := strings.Trim(filepath.ToSlash(value), "/")
	if normalized == "" {
		return nil
	}
	return strings.Split(normalized, "/")
}

func matchGlobSegments(patternSegments, pathSegments []string) bool {
	if len(patternSegments) == 0 {
		return len(pathSegments) == 0
	}
	if patternSegments[0] == "**" {
		if len(patternSegments) == 1 {
			return true
		}
		for i := 0; i <= len(pathSegments); i++ {
			if matchGlobSegments(patternSegments[1:], pathSegments[i:]) {
				return true
			}
		}
		return false
	}
	if len(pathSegments) == 0 {
		return false
	}
	matched, _ := pathpkg.Match(patternSegments[0], pathSegments[0])
	if !matched {
		return false
	}
	return matchGlobSegments(patternSegments[1:], pathSegments[1:])
}

func sanitizeForID(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, s)
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.Trim(s, "-")
}
