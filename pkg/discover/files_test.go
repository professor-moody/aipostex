package discover

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestLoadRulesAndScanPreservesRawContent(t *testing.T) {
	tmpDir := t.TempDir()

	rulesPath := filepath.Join(tmpDir, "rules.yaml")
	rulesYAML := `rules:
  - name: "OpenAI API Key"
    category: "ai-credentials"
    severity: "high"
    content_patterns:
      - 'sk-[a-zA-Z0-9]{20,}'
`
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0o600); err != nil {
		t.Fatalf("writing rules file: %v", err)
	}

	targetFile := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(targetFile, []byte("OPENAI_API_KEY=sk-abcd12345678901234567890"), 0o600); err != nil {
		t.Fatalf("writing target file: %v", err)
	}

	excludedDir := filepath.Join(tmpDir, ".git")
	if err := os.Mkdir(excludedDir, 0o755); err != nil {
		t.Fatalf("creating excluded dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(excludedDir, ".env"), []byte("OPENAI_API_KEY=sk-wxyz12345678901234567890"), 0o600); err != nil {
		t.Fatalf("writing excluded file: %v", err)
	}

	rules, err := LoadRules(rulesPath)
	if err != nil {
		t.Fatalf("LoadRules returned error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	scanner := NewFileScanner(1)
	scanner.Rules = rules
	scanner.ExcludePaths = []string{".git"}

	findings, err := scanner.Scan([]string{tmpDir})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Target != targetFile {
		t.Fatalf("unexpected target: %q", finding.Target)
	}
	if !strings.Contains(finding.Evidence, "sk-abcd12345678901234567890") {
		t.Fatalf("expected unredacted credential in evidence, got %q", finding.Evidence)
	}
}

func TestLoadRulesRejectsInvalidRuleDefinitions(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "invalid severity",
			yaml: `rules:
  - name: "Bad"
    category: "ai"
    severity: "urgent"
    file_patterns: ["*.env"]
`,
			wantErr: "invalid severity",
		},
		{
			name: "missing pattern sources",
			yaml: `rules:
  - name: "Bad"
    category: "ai"
    severity: "high"
`,
			wantErr: "has no file, path, or content patterns",
		},
		{
			name: "negative max file size",
			yaml: `rules:
  - name: "Bad"
    category: "ai"
    severity: "high"
    file_patterns: ["*.env"]
    max_file_size: -1
`,
			wantErr: "negative max_file_size",
		},
		{
			name: "invalid regex",
			yaml: `rules:
  - name: "Bad"
    category: "ai"
    severity: "high"
    content_patterns: ["("]
`,
			wantErr: "invalid regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			rulesPath := filepath.Join(tmpDir, "rules.yaml")
			if err := os.WriteFile(rulesPath, []byte(tt.yaml), 0o600); err != nil {
				t.Fatalf("writing rules file: %v", err)
			}

			_, err := LoadRules(rulesPath)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestLoadRulesFromDirSkipsBrokenFileButLoadsValidSibling(t *testing.T) {
	tmpDir := t.TempDir()

	validPath := filepath.Join(tmpDir, "valid.yaml")
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")

	validYAML := `rules:
  - name: "Valid"
    category: "ai"
    severity: "high"
    file_patterns: ["*.env"]
`
	invalidYAML := `rules:
  - name: "Invalid"
    category: "ai"
    severity: "urgent"
    file_patterns: ["*.env"]
`

	if err := os.WriteFile(validPath, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("writing valid rules file: %v", err)
	}
	if err := os.WriteFile(invalidPath, []byte(invalidYAML), 0o600); err != nil {
		t.Fatalf("writing invalid rules file: %v", err)
	}

	rules, err := LoadRulesFromDir(tmpDir)
	if err != nil {
		t.Fatalf("LoadRulesFromDir returned error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 valid rule, got %d", len(rules))
	}
	if rules[0].Name != "Valid" {
		t.Fatalf("expected valid sibling rule to load, got %q", rules[0].Name)
	}
}

func TestLoadBuiltinRulesIncludesNewHighSignalRules(t *testing.T) {
	rules, err := LoadEmbeddedRules()
	if err != nil {
		t.Fatalf("loading builtin rules: %v", err)
	}

	found := map[string]bool{
		"Fine-Tuning Dataset Manifests":    false,
		"Embedding Pipeline Configuration": false,
		"Marketplace Probe Indicators":     false,
	}
	for _, rule := range rules {
		if _, ok := found[rule.Name]; ok {
			found[rule.Name] = true
		}
	}
	for name, ok := range found {
		if !ok {
			t.Fatalf("expected builtin rule %q to be loaded", name)
		}
	}
}

func TestFileScannerStopsOnCancelledContext(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "dataset.json")
	if err := os.WriteFile(targetFile, []byte(`{"records":1}`), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	scanner := NewFileScanner(1)
	scanner.Rules = []FileRule{{
		Name:         "Dataset",
		Category:     "ai",
		Severity:     "info",
		FilePatterns: []string{"dataset.json"},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scanner.Context = ctx

	findings, _, err := scanner.ScanDetailed([]string{tmpDir})
	if err != nil {
		t.Fatalf("ScanDetailed returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings after cancellation, got %d", len(findings))
	}
}

func TestPathPatternDoubleStarGlob(t *testing.T) {
	tmpDir := t.TempDir()
	nested := filepath.Join(tmpDir, "deep", "config")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	targetFile := filepath.Join(nested, "mcp.json")
	if err := os.WriteFile(targetFile, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	nonMatchFile := filepath.Join(tmpDir, "other.txt")
	if err := os.WriteFile(nonMatchFile, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}

	scanner := NewFileScanner(1)
	scanner.Rules = []FileRule{{
		Name:         "MCP Config",
		Category:     "ai-config",
		Severity:     "medium",
		PathPatterns: []string{"**/mcp.json"},
	}}
	scanner.Context = context.Background()

	findings, _, err := scanner.ScanDetailed([]string{tmpDir})
	if err != nil {
		t.Fatalf("ScanDetailed returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected ** glob to match deep/config/mcp.json, got no findings")
	}
	matched := false
	for _, f := range findings {
		if strings.Contains(f.Target, "mcp.json") {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("expected finding for mcp.json, got %#v", findings)
	}
}

func TestMatchGlobDoubleStarDoesNotUseSubstringPrefix(t *testing.T) {
	if matchGlob("secret/**/mcp.json", "notsecret/x/mcp.json") {
		t.Fatal("expected prefix-constrained pattern not to match substring directory names")
	}
}

func TestMatchGlobDoubleStarMatchesZeroOrMoreSegments(t *testing.T) {
	for _, candidate := range []string{
		"secret/mcp.json",
		"secret/a/mcp.json",
		"secret/a/b/mcp.json",
	} {
		if !matchGlob("secret/**/mcp.json", candidate) {
			t.Fatalf("expected recursive glob to match %q", candidate)
		}
	}
}

func TestMatchGlobDatasetsNestedPaths(t *testing.T) {
	for _, path := range []string{
		"repo/data/datasets/train.csv",
		"abs/repo/data/datasets/sub/train.csv",
		"a/b/c/datasets/x/y.csv",
		"project/.cache/huggingface/datasets/foo/dataset_infos.json",
	} {
		if !matchGlob("**/datasets/**", path) {
			t.Fatalf("**/datasets/** should match %q", path)
		}
	}
	if matchGlob("**/datasets/**", "repo/data/other/train.csv") {
		t.Fatal("should not match path without datasets segment")
	}
}

func TestInvalidGlobPatternValidation(t *testing.T) {
	err := validateRule(FileRule{
		Name:         "Bad Pattern",
		Category:     "test",
		Severity:     "info",
		FilePatterns: []string{"[invalid"},
	})
	if err == nil {
		t.Fatal("expected error for invalid glob pattern, got nil")
	}
	if !strings.Contains(err.Error(), "invalid file pattern") {
		t.Fatalf("expected 'invalid file pattern' in error, got: %v", err)
	}
}

func TestFilePatternWithContentPatternsDoesNotFallbackToFilenameOnly(t *testing.T) {
	tmpDir := t.TempDir()

	targetFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(targetFile, []byte(`{"db": "postgres"}`), 0o600); err != nil {
		t.Fatalf("writing target file: %v", err)
	}

	scanner := NewFileScanner(1)
	scanner.Rules = []FileRule{{
		Name:            "OpenAI API Key",
		Category:        "ai-credentials",
		Severity:        "high",
		FilePatterns:    []string{"*.json"},
		ContentPatterns: []string{`sk-[a-zA-Z0-9]{20,}`},
	}}
	for i := range scanner.Rules {
		for _, p := range scanner.Rules[i].ContentPatterns {
			re, _ := regexp.Compile(p)
			scanner.Rules[i].compiledContent = append(scanner.Rules[i].compiledContent, re)
		}
	}
	scanner.Context = context.Background()

	findings, _, err := scanner.ScanDetailed([]string{tmpDir})
	if err != nil {
		t.Fatalf("ScanDetailed returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when content doesn't match, got %d (matched_on=%s)", len(findings), findings[0].Metadata["matched_on"])
	}
}

func TestFilePatternWithoutContentPatternsEmitsFilenameMatch(t *testing.T) {
	tmpDir := t.TempDir()

	targetFile := filepath.Join(tmpDir, "mcp.json")
	if err := os.WriteFile(targetFile, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("writing target file: %v", err)
	}

	scanner := NewFileScanner(1)
	scanner.Rules = []FileRule{{
		Name:         "MCP Config",
		Category:     "mcp-config",
		Severity:     "medium",
		FilePatterns: []string{"mcp.json"},
	}}
	scanner.Context = context.Background()

	findings, _, err := scanner.ScanDetailed([]string{tmpDir})
	if err != nil {
		t.Fatalf("ScanDetailed returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 filename-only finding, got %d", len(findings))
	}
	if findings[0].Metadata["matched_on"] != "filename" {
		t.Fatalf("expected matched_on=filename, got %v", findings[0].Metadata["matched_on"])
	}
}

func TestMatchGlobStandardPattern(t *testing.T) {
	if !matchGlob("*.json", "config.json") {
		t.Fatal("expected *.json to match config.json")
	}
	if matchGlob("*.json", "config.yaml") {
		t.Fatal("expected *.json to NOT match config.yaml")
	}
}

func TestCanonicalizeRootsDeduplicatesAndSubsumes(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "exact duplicates",
			input:  []string{"/a", "/a"},
			expect: []string{"/a"},
		},
		{
			name:   "trailing slash dedup",
			input:  []string{"/a", "/a/"},
			expect: []string{"/a"},
		},
		{
			name:   "parent subsumes child",
			input:  []string{"/a", "/a/b"},
			expect: []string{"/a"},
		},
		{
			name:   "child before parent",
			input:  []string{"/a/b", "/a"},
			expect: []string{"/a"},
		},
		{
			name:   "independent roots preserved",
			input:  []string{"/a", "/b", "/c"},
			expect: []string{"/a", "/b", "/c"},
		},
		{
			name:   "deep nesting",
			input:  []string{"/a/b/c/d", "/a/b", "/a/b/c"},
			expect: []string{"/a/b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalizeRoots(tt.input)
			if !reflect.DeepEqual(got, tt.expect) {
				t.Fatalf("canonicalizeRoots(%v) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestReadFileHeadLargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	largePath := filepath.Join(tmpDir, "large.bin")
	f, err := os.Create(largePath)
	if err != nil {
		t.Fatal(err)
	}
	written := 0
	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = byte('A' + (i % 26))
	}
	for written < 100*1024 {
		n, err := f.Write(chunk)
		if err != nil {
			t.Fatal(err)
		}
		written += n
	}
	f.Close()

	data, err := readFileHead(largePath, 1024)
	if err != nil {
		t.Fatalf("readFileHead returned error: %v", err)
	}
	if len(data) != 1024 {
		t.Fatalf("expected 1024 bytes, got %d", len(data))
	}
}

func TestReadFileHeadNonexistent(t *testing.T) {
	_, err := readFileHead("/nonexistent/path/file.txt", 1024)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadRulesFromFSWithCustomFS(t *testing.T) {
	fsys := os.DirFS(t.TempDir())
	tmpDir := t.TempDir()
	rulesYAML := `rules:
  - name: "Test Rule"
    category: "test"
    severity: "info"
    file_patterns: ["*.txt"]
`
	rulesPath := filepath.Join(tmpDir, "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	customFS := os.DirFS(tmpDir)
	rules, err := LoadRulesFromFS(customFS, "rules.yaml", "test-source")
	if err != nil {
		t.Fatalf("LoadRulesFromFS returned error: %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "Test Rule" {
		t.Fatalf("expected 1 rule named 'Test Rule', got %v", rules)
	}

	_, err = LoadRulesFromFS(fsys, "nonexistent.yaml", "missing")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadRulesFromFSInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(rulesPath, []byte("{{invalid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	customFS := os.DirFS(tmpDir)
	_, err := LoadRulesFromFS(customFS, "bad.yaml", "test-source")
	if err == nil || !strings.Contains(err.Error(), "parsing") {
		t.Fatalf("expected parsing error, got %v", err)
	}
}

func TestLoadRulesFromFSInvalidRule(t *testing.T) {
	tmpDir := t.TempDir()
	rulesYAML := `rules:
  - name: ""
    category: "test"
    severity: "info"
    file_patterns: ["*.txt"]
`
	rulesPath := filepath.Join(tmpDir, "bad-rule.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	customFS := os.DirFS(tmpDir)
	_, err := LoadRulesFromFS(customFS, "bad-rule.yaml", "test-source")
	if err == nil || !strings.Contains(err.Error(), "missing name") {
		t.Fatalf("expected 'missing name' error, got %v", err)
	}
}

func TestLoadRulesFromFSContentPatternsDefault(t *testing.T) {
	tmpDir := t.TempDir()
	rulesYAML := `rules:
  - name: "Content Rule"
    category: "test"
    severity: "high"
    content_patterns: ["api_key"]
`
	rulesPath := filepath.Join(tmpDir, "content.yaml")
	if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	customFS := os.DirFS(tmpDir)
	rules, err := LoadRulesFromFS(customFS, "content.yaml", "test-source")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].MaxFileSize != 10*1024*1024 {
		t.Fatalf("expected default MaxFileSize 10MB, got %d", rules[0].MaxFileSize)
	}
	if len(rules[0].compiledContent) != 1 {
		t.Fatalf("expected 1 compiled regex, got %d", len(rules[0].compiledContent))
	}
}

func TestValidateRuleInvalidPathPattern(t *testing.T) {
	err := validateRule(FileRule{
		Name:         "Bad Path",
		Category:     "test",
		Severity:     "info",
		PathPatterns: []string{"[invalid"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid path pattern") {
		t.Fatalf("expected 'invalid path pattern' error, got %v", err)
	}
}

func TestValidateRuleMissingCategory(t *testing.T) {
	err := validateRule(FileRule{
		Name:         "No Category",
		Category:     "",
		Severity:     "info",
		FilePatterns: []string{"*.txt"},
	})
	if err == nil || !strings.Contains(err.Error(), "missing category") {
		t.Fatalf("expected 'missing category' error, got %v", err)
	}
}

func TestFileScannerFallsBackToFilenameWhenContentPatternsCannotRun(t *testing.T) {
	tmpDir := t.TempDir()
	emptyCfg := filepath.Join(tmpDir, "config.cfg")
	if err := os.WriteFile(emptyCfg, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	re, err := regexp.Compile(`SECRET`)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewFileScanner(1)
	scanner.Rules = []FileRule{
		{
			Name:            "CfgWithSecret",
			Category:        "test",
			Severity:        "medium",
			FilePatterns:    []string{"*.cfg"},
			compiledContent: []*regexp.Regexp{re},
			MaxFileSize:     1024,
		},
	}

	matches := scanner.matchFile(emptyCfg)
	if len(matches) != 1 || matches[0].MatchedOn != "filename" {
		t.Fatalf("expected filename fallback for empty file with content_patterns, got %#v", matches)
	}

	largePath := filepath.Join(tmpDir, "big.cfg")
	f, err := os.OpenFile(largePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	scanner.Rules[0].MaxFileSize = 512
	matches = scanner.matchFile(largePath)
	if len(matches) != 1 || matches[0].MatchedOn != "filename" {
		t.Fatalf("expected filename fallback when file exceeds max_file_size, got %#v", matches)
	}
}
