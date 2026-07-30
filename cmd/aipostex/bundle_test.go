package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestRunBundleCreatesZip(t *testing.T) {
	collection := report.FindingCollection{
		EngagementID: "eng-test123",
		Findings: []report.Finding{
			{
				ID:       "vuln-001",
				Source:   report.SourceVulnCheck,
				Target:   "http://10.0.0.5:11434",
				Title:    "Ollama No Auth",
				Severity: report.SeverityCritical,
				Evidence: strings.Repeat("A", 300),
				Tags:     []string{"AML.T0025"},
			},
			{
				ID:         "vuln-002",
				Source:     report.SourceVulnCheck,
				Target:     "http://10.0.0.5:8888",
				Title:      "Jupyter No Auth",
				Severity:   report.SeverityHigh,
				Evidence:   "short evidence",
				References: []string{"https://atlas.mitre.org/techniques/AML.T0048"},
			},
		},
	}

	inputFile, err := os.CreateTemp("", "bundle-input-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(inputFile.Name())

	data, _ := json.Marshal(collection)
	if _, err := inputFile.Write(data); err != nil {
		t.Fatalf("writing input: %v", err)
	}
	inputFile.Close()

	outputFile, err := os.CreateTemp("", "bundle-output-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	bundleInput = inputFile.Name()

	withTestConfig(t, func() {
		cfg.OutputFile = outputFile.Name()

		if err := runBundle(nil, nil); err != nil {
			t.Fatalf("runBundle failed: %v", err)
		}

		reader, err := zip.OpenReader(outputFile.Name())
		if err != nil {
			t.Fatalf("opening zip: %v", err)
		}
		defer reader.Close()

		expectedFiles := map[string]bool{
			"bundle-eng-test123/report.json":           false,
			"bundle-eng-test123/report.html":           false,
			"bundle-eng-test123/evidence/vuln-001.txt": false,
			"bundle-eng-test123/README.md":             false,
		}
		var htmlContent string

		for _, f := range reader.File {
			if _, ok := expectedFiles[f.Name]; ok {
				expectedFiles[f.Name] = true
			}
			if f.Name == "bundle-eng-test123/report.html" {
				rc, err := f.Open()
				if err != nil {
					t.Fatalf("opening report.html: %v", err)
				}
				data, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Fatalf("reading report.html: %v", err)
				}
				htmlContent = string(data)
			}
		}

		for name, found := range expectedFiles {
			if !found {
				t.Errorf("expected file %s not found in zip", name)
			}
		}
		if !strings.Contains(htmlContent, "MITRE ATLAS Coverage") {
			t.Fatal("expected bundled HTML report to include MITRE ATLAS coverage")
		}
		if !strings.Contains(htmlContent, "AML.T0025") {
			t.Fatal("expected bundled HTML report to include AML.T0025")
		}
		if !strings.Contains(htmlContent, "AML.T0048") {
			t.Fatal("expected bundled HTML report to include AML.T0048")
		}
	})
}

func TestGenerateBundleReadme(t *testing.T) {
	collection := report.FindingCollection{
		EngagementID: "eng-abc",
		Findings: []report.Finding{
			{Severity: report.SeverityCritical},
			{Severity: report.SeverityHigh},
		},
	}

	readme := generateBundleReadme(collection, 1)
	if !strings.Contains(readme, "eng-abc") {
		t.Fatal("expected engagement ID in readme")
	}
	if !strings.Contains(readme, "**Critical:** 1") {
		t.Fatal("expected critical count")
	}
	if !strings.Contains(readme, "**Evidence Files:** 1") {
		t.Fatal("expected evidence file count")
	}
}

func TestSanitizeBundleName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"eng-abc", "eng-abc"},
		{"../../loot", "loot"},
		{"", "engagement"},
		{"   ", "engagement"},
		{"hello world!", "hello-world"},
		{"a/b\\c", "a-b-c"},
		{"---", "engagement"},
		{"normal_name-123", "normal_name-123"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := sanitizeBundleName(tc.input)
			if got != tc.want {
				t.Errorf("sanitizeBundleName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestAddZipFileRejectsInvalidEntryName(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := addZipFile(zw, "../etc/passwd", []byte("x"))
	_ = zw.Close()
	if err == nil {
		t.Fatal("expected error for path traversal zip entry")
	}
}

func TestSanitizeZipEntryName(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"bundle/report.json", false},
		{"bundle/evidence/vuln-001.txt", false},
		{"../../../etc/passwd", true},
		{"", true},
		{".", true},
		{"/absolute/path", true},
		{"../../sneaky/file", true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := sanitizeZipEntryName(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("sanitizeZipEntryName(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestRunBundleDefaultOutputPath(t *testing.T) {
	collection := report.FindingCollection{
		EngagementID: "auto-output-test",
		Findings: []report.Finding{
			{ID: "f1", Severity: report.SeverityInfo, Evidence: "short"},
		},
	}
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.json")
	data, _ := json.Marshal(collection)
	_ = os.WriteFile(inputPath, data, 0o600)

	prevInput := bundleInput
	wd, _ := os.Getwd()
	defer func() {
		bundleInput = prevInput
		_ = os.Chdir(wd)
	}()

	bundleInput = inputPath
	_ = os.Chdir(tmpDir)

	withTestConfig(t, func() {
		cfg.OutputFile = ""
		if err := runBundle(nil, nil); err != nil {
			t.Fatalf("runBundle with default output failed: %v", err)
		}
		expectedPath := filepath.Join(tmpDir, "bundle-auto-output-test.zip")
		if _, err := os.Stat(expectedPath); err != nil {
			t.Fatalf("expected default output zip at %s, got error: %v", expectedPath, err)
		}
	})
}

func TestRunBundleSanitizesEngagementIDForPaths(t *testing.T) {
	collection := report.FindingCollection{
		EngagementID: "../../loot",
		Findings: []report.Finding{
			{ID: "finding-1", Severity: report.SeverityInfo, Evidence: strings.Repeat("A", 250)},
		},
	}

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.json")
	data, err := json.Marshal(collection)
	if err != nil {
		t.Fatalf("marshal collection: %v", err)
	}
	if err := os.WriteFile(inputPath, data, 0o600); err != nil {
		t.Fatalf("writing input: %v", err)
	}

	prevInput := bundleInput
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() {
		bundleInput = prevInput
		_ = os.Chdir(wd)
	}()

	bundleInput = inputPath
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	withTestConfig(t, func() {
		cfg.OutputFile = ""

		if err := runBundle(nil, nil); err != nil {
			t.Fatalf("runBundle failed: %v", err)
		}

		outputPath := filepath.Join(tmpDir, "bundle-loot.zip")
		reader, err := zip.OpenReader(outputPath)
		if err != nil {
			t.Fatalf("opening sanitized zip: %v", err)
		}
		defer reader.Close()

		for _, f := range reader.File {
			if strings.Contains(f.Name, "..") || strings.Contains(f.Name, "\\") {
				t.Fatalf("expected sanitized zip entry name, got %q", f.Name)
			}
			if !strings.HasPrefix(f.Name, "bundle-loot/") {
				t.Fatalf("expected sanitized prefix, got %q", f.Name)
			}
		}
	})
}
