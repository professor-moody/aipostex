package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/pkg/modelscan"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	modelScanPath              string
	modelScanHashCheck         string
	modelScanMaxFileSizeMB     int
	modelScanExclude           []string
	modelScanNoDefaultExcludes bool
)

var modelScanCmd = &cobra.Command{
	Use:   "model-scan",
	Short: "Scan model files for supply chain risks",
	Long: `Scan local model artifacts (.pkl, .pickle, .pt, .pth, .bin, .onnx,
.safetensors, .gguf, .pb, .h5, .keras) for deserialization and supply chain
risks.

Detects pickle/PyTorch code-execution surfaces, dangerous pickle opcodes,
ONNX external/custom-op risks, TensorFlow/Keras Python execution surfaces,
and optionally validates a single file's SHA-256 hash.`,
	Example: strings.Join([]string{
		formatCommandExample("model-scan --path /models/checkpoint.pt"),
		formatCommandExample("model-scan --path /models/"),
		formatCommandExample("model-scan --path /models/ --max-file-size-mb 0"),
		formatCommandExample("model-scan --path /models/checkpoint.pt --hash sha256:<hex>"),
	}, "\n"),
	RunE: runModelScan,
}

func init() {
	modelScanCmd.Flags().StringVar(&modelScanPath, "path", "", "File or directory to scan (required)")
	modelScanCmd.Flags().StringVar(&modelScanHashCheck, "hash", "", "Expected SHA-256 hash to validate (format: sha256:hex)")
	modelScanCmd.Flags().IntVar(&modelScanMaxFileSizeMB, "max-file-size-mb", 100, "When scanning a directory, skip files larger than this (0 = no size limit)")
	modelScanCmd.Flags().StringSliceVar(&modelScanExclude, "exclude", nil, "Extra directory base names to skip during directory scan (merged with built-in vendor paths unless --no-default-excludes)")
	modelScanCmd.Flags().BoolVar(&modelScanNoDefaultExcludes, "no-default-excludes", false, "Do not skip .git, node_modules, venv, etc.; only paths from --exclude are skipped")
}

func runModelScan(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(modelScanPath) == "" {
		return missingFlagError("path", formatCommandExample("model-scan --path /models/checkpoint.pt"))
	}

	info, err := os.Stat(modelScanPath)
	if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}
	if info.IsDir() && strings.TrimSpace(modelScanHashCheck) != "" {
		return fmt.Errorf("--hash applies only when --path is a single file; remove --hash or point --path at a file")
	}

	var risks []modelscan.Risk
	if info.IsDir() {
		infof("Scanning directory %s for model files...", modelScanPath)
		opt := modelscan.DefaultScanOptions()
		if modelScanNoDefaultExcludes {
			opt.ExcludeDirNames = make(map[string]struct{})
		}
		for _, name := range modelScanExclude {
			name = strings.TrimSpace(name)
			if name != "" {
				opt.ExcludeDirNames[name] = struct{}{}
			}
		}
		if modelScanMaxFileSizeMB == 0 {
			opt.MaxFileSize = 0
		} else if modelScanMaxFileSizeMB > 0 {
			opt.MaxFileSize = int64(modelScanMaxFileSizeMB) << 20
		}
		risks, err = modelscan.ScanDirectoryWithOptions(modelScanPath, opt)
	} else {
		infof("Scanning file %s...", modelScanPath)
		risks, err = modelscan.ScanFile(modelScanPath)
	}
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	if modelScanHashCheck != "" && !info.IsDir() {
		hashRisks := validateHash(modelScanPath, modelScanHashCheck)
		risks = append(risks, hashRisks...)
	}

	findings := make([]report.Finding, 0, len(risks))
	for _, risk := range risks {
		severity := risk.Severity
		if severity == "" {
			severity = report.SeverityInfo
		}
		finding := newExploitFinding(
			"model-scan",
			risk.File,
			fmt.Sprintf("Model supply chain risk: %s", risk.RiskType),
			severity,
			risk.Detail,
			map[string]interface{}{
				"module":    "model-scan",
				"action":    "scan",
				"mutating":  false,
				"risk_type": risk.RiskType,
				"file":      risk.File,
			},
		)
		findings = append(findings, finding)
	}

	infof("Scanned %s — %d risk(s) identified", modelScanPath, len(risks))

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "model-scan",
		Action:              "scan",
		ResourcesEnumerated: len(risks),
		Mutating:            false,
	})
}

func validateHash(path, expected string) []modelscan.Risk {
	parts := strings.SplitN(expected, ":", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return []modelscan.Risk{{
			File:     path,
			RiskType: "hash-format-error",
			Severity: "info",
			Detail:   fmt.Sprintf("Hash format not recognized (expected sha256:hex): %s", expected),
		}}
	}

	actual, err := modelscan.HashFile(path)
	if err != nil {
		return []modelscan.Risk{{
			File:     path,
			RiskType: "hash-error",
			Severity: "info",
			Detail:   fmt.Sprintf("Failed to compute hash: %v", err),
		}}
	}

	if !strings.EqualFold(actual, parts[1]) {
		return []modelscan.Risk{{
			File:     path,
			RiskType: "hash-mismatch",
			Severity: "critical",
			Detail:   fmt.Sprintf("SHA-256 hash mismatch — expected %s, got %s. Model file may have been tampered with.", parts[1], actual),
		}}
	}

	return []modelscan.Risk{{
		File:     path,
		RiskType: "hash-verified",
		Severity: "info",
		Detail:   fmt.Sprintf("SHA-256 hash matches expected value: %s", actual),
	}}
}
