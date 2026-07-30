package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/exitcode"
	"github.com/professor-moody/aipostex/pkg/modelscan"
)

func TestRunModelScanRequiresPath(t *testing.T) {
	prev := modelScanPath
	defer func() { modelScanPath = prev }()

	withTestConfig(t, func() {
		modelScanPath = ""
		err := runModelScan(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "path") {
			t.Fatalf("expected missing path error, got %v", err)
		}
	})
}

func TestRunModelScanWithPickleFile(t *testing.T) {
	tmp := t.TempDir()
	modelFile := filepath.Join(tmp, "model.pkl")
	if err := os.WriteFile(modelFile, []byte("\x80\x02}q\x00(X\x01\x00\x00\x00aq\x01X\x01\x00\x00\x00bq\x02u."), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := modelScanPath
	defer func() { modelScanPath = prev }()

	withTestConfig(t, func() {
		modelScanPath = modelFile
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(tmp, "model-scan.json")

		err := runModelScan(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !strings.Contains(string(raw), "model-scan") {
			t.Fatalf("expected model-scan source, got %s", string(raw))
		}
	})
}

func TestRunModelScanDirectoryScan(t *testing.T) {
	tmp := t.TempDir()
	modelFile := filepath.Join(tmp, "checkpoint.pt")
	if err := os.WriteFile(modelFile, []byte("\x80\x02}q\x00."), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := modelScanPath
	defer func() { modelScanPath = prev }()

	withTestConfig(t, func() {
		modelScanPath = tmp
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(tmp, "dir-scan.json")

		err := runModelScan(nil, nil)
		if err != nil {
			if _, ok := err.(*exitcode.FindingsError); !ok {
				t.Fatalf("unexpected error: %v", err)
			}
		}
	})
}

func TestRunModelScanRejectsHashForDirectory(t *testing.T) {
	tmp := t.TempDir()

	prevPath := modelScanPath
	prevHash := modelScanHashCheck
	defer func() {
		modelScanPath = prevPath
		modelScanHashCheck = prevHash
	}()

	withTestConfig(t, func() {
		modelScanPath = tmp
		modelScanHashCheck = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

		err := runModelScan(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "--hash applies only") {
			t.Fatalf("expected directory hash error, got %v", err)
		}
	})
}

func TestModelScanHelpOmitsNetworkAndExploitFlags(t *testing.T) {
	for _, name := range []string{
		"callback-url",
		"force-exploit",
		"insecure",
		"proxy",
		"stealth",
		"timeout",
	} {
		if flag := modelScanCmd.Flag(name); flag != nil {
			t.Fatalf("model-scan help should not expose %q", name)
		}
	}
	for _, name := range []string{"format", "output", "path", "session", "verbose"} {
		if flag := modelScanCmd.Flag(name); flag == nil {
			t.Fatalf("model-scan help should expose %q", name)
		}
	}
}

func TestValidateHashRejectsInvalidFormat(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.bin")
	if err := os.WriteFile(f, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	risks := validateHash(f, "md5:abc")
	if len(risks) == 0 || risks[0].RiskType != "hash-format-error" {
		t.Fatalf("expected hash-format-error, got %v", risks)
	}
}

func TestValidateHashDetectsMismatch(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.bin")
	if err := os.WriteFile(f, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	risks := validateHash(f, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if len(risks) == 0 || risks[0].RiskType != "hash-mismatch" {
		t.Fatalf("expected hash-mismatch, got %v", risks)
	}
}

func TestValidateHashAcceptsMatchingSHA256(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "model.bin")
	if err := os.WriteFile(f, []byte("exact-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	hexHash, err := modelscan.HashFile(f)
	if err != nil {
		t.Fatal(err)
	}
	risks := validateHash(f, "sha256:"+hexHash)
	if len(risks) != 1 || risks[0].RiskType != "hash-verified" {
		t.Fatalf("expected hash-verified, got %v", risks)
	}
}
