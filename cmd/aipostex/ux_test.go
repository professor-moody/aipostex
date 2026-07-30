package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrintFileScanSummaryIncludesSkipCounts(t *testing.T) {
	var out strings.Builder
	printFileScanSummary(&out, fileScanSummary{
		PathsScanned:    2,
		RulesLoaded:     5,
		FilesConsidered: 12,
		ExcludedDirHits: 3,
		WalkErrors:      1,
		FindingsEmitted: 4,
	}, map[string]int{})
	rendered := out.String()
	for _, expected := range []string{
		"── Summary ",
		"2 path(s) scanned",
		"3 skipped by exclusions",
		"1 skipped by errors",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected summary to contain %q, got %q", expected, rendered)
		}
	}
}

func TestPrintTemplatesSummaryIncludesCategories(t *testing.T) {
	var out strings.Builder
	printTemplatesSummary(&out, templatesSummary{
		TemplatesLoaded:   10,
		TemplatesFiltered: 3,
		CategoryCounts: map[string]int{
			"mcp":    2,
			"ollama": 1,
		},
	})
	rendered := out.String()
	for _, expected := range []string{
		"10 template(s) loaded",
		"3 after filtering",
		"categories: mcp=2, ollama=1",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected summary to contain %q, got %q", expected, rendered)
		}
	}
}

func TestPrintExploitSummaryIncludesMutatingFlag(t *testing.T) {
	var out strings.Builder
	printExploitSummary(&out, exploitSummary{
		Module:              "ollama",
		Action:              "poison",
		ResourcesEnumerated: 1,
		FindingsEmitted:     1,
		PartialFailures:     0,
		Mutating:            true,
	}, map[string]int{"critical": 1, "high": 2})
	rendered := out.String()
	for _, expected := range []string{
		"── Summary ",
		"1 critical", // severity tally now leads the Summary block
		"2 high",
		"(total: 3)",
		"1 resource(s)",
		"1 finding(s)",
		"mutating: yes",
		"0 target(s) with follow-on guidance",
		"0 gated action(s) suggested",
	} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("expected summary to contain %q, got %q", expected, rendered)
		}
	}
}

func TestValidationErrorsAreOperatorFriendly(t *testing.T) {
	prevModel := ollamaModel
	prevPrompt := ollamaPrompt
	prevTarget := ollamaTarget
	prevVDBTarget := vdbTarget
	prevVDBType := vdbType
	defer func() {
		ollamaModel = prevModel
		ollamaPrompt = prevPrompt
		ollamaTarget = prevTarget
		vdbTarget = prevVDBTarget
		vdbType = prevVDBType
	}()

	ollamaModel = ""
	ollamaPrompt = ""
	ollamaTarget = "http://127.0.0.1:11434"
	if err := runOllamaGenerate(nil, nil); err == nil || !strings.Contains(err.Error(), "example: aipostex ollama --target http://127.0.0.1:11434 generate --model llama3 --prompt \"hello\"") {
		t.Fatalf("expected operator-friendly ollama validation error, got %v", err)
	}

	vdbTarget = "http://127.0.0.1:8000"
	vdbType = "pinecone"
	if _, _, err := newVDBClient(); err == nil || !strings.Contains(err.Error(), "valid: chromadb, milvus, pgvector, qdrant, weaviate") {
		t.Fatalf("expected provider choice error, got %v", err)
	}
}

func TestDiscoverFilesUsesCanonicalPathFlag(t *testing.T) {
	prevPaths := scanFilePaths
	prevRulesDir := scanRulesDir
	defer func() {
		scanFilePaths = prevPaths
		scanRulesDir = prevRulesDir
	}()

	withTestConfig(t, func() {
		tmpDir := t.TempDir()
		targetFile := filepath.Join(tmpDir, "dataset_info.json")
		if err := os.WriteFile(targetFile, []byte("{}"), 0o600); err != nil {
			t.Fatalf("writing target file: %v", err)
		}

		scanFilePaths = nil
		scanFilePaths = []string{tmpDir}
		scanRulesDir = ""
		cfg.Format = "jsonl"
		cfg.Verbose = false

		if err := runScanFiles(nil, nil); err != nil {
			t.Fatalf("expected canonical discover files run to succeed, got %v", err)
		}
	})
}
