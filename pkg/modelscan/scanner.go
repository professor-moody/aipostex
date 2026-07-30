package modelscan

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Risk struct {
	File     string
	RiskType string
	Severity string
	Detail   string
}

// ScanOptions configures directory walks for ScanDirectory.
type ScanOptions struct {
	// ExcludeDirNames skips directories with these base names (e.g. ".git", "node_modules").
	ExcludeDirNames map[string]struct{}
	// MaxFileSize skips files larger than this many bytes (0 = no limit).
	MaxFileSize int64
	// MaxOpcodeScanBytes caps the number of bytes scanned for dangerous pickle opcodes.
	// Defaults to 10 MiB when zero.
	MaxOpcodeScanBytes int64
}

// DefaultExcludeDirNames matches common vendor and cache trees (aligned with discover defaults).
var DefaultExcludeDirNames = []string{
	".git", "node_modules", "__pycache__", "venv", ".venv",
	".npm", ".yarn", "vendor", ".tox", "dist",
}

// DefaultScanOptions returns options with standard exclude dirs and a 100 MiB per-file cap.
func DefaultScanOptions() ScanOptions {
	ex := make(map[string]struct{}, len(DefaultExcludeDirNames))
	for _, name := range DefaultExcludeDirNames {
		ex[name] = struct{}{}
	}
	return ScanOptions{
		ExcludeDirNames: ex,
		MaxFileSize:     100 << 20,
	}
}

// pickleMagic is the two-byte pickle protocol header (\x80\x02 through \x80\x05).
var pickleMagic = []byte{0x80}

// pickleOpcodes that enable arbitrary code execution.
var dangerousOpcodes = []struct {
	Opcode byte
	Name   string
	Desc   string
}{
	{0x63, "GLOBAL", "loads arbitrary module attribute (pickle code execution)"},
	{0x69, "INST", "instantiates arbitrary class (pickle code execution)"},
	{0x52, "REDUCE", "calls arbitrary callable with args (pickle code execution)"},
	{0x81, "NEWOBJ", "creates object via cls.__new__(cls, *args) (pickle code execution)"},
	{0x92, "NEWOBJ_EX", "extended NEWOBJ with kwargs (pickle code execution)"},
	{0x83, "STACK_GLOBAL", "loads module.name from stack (pickle code execution)"},
}

// torchMagic identifies files saved with torch.save() (which uses pickle).
var torchMagic = []byte("PK") // ZIP local file header (torch.save uses ZIP format)

// hdf5Magic is the 8-byte HDF5 file signature.
var hdf5Magic = []byte{0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a}

// onnxCustomOpPatterns are byte patterns that indicate ONNX custom operator usage.
var onnxCustomOpPatterns = []struct {
	Pattern []byte
	Name    string
	Desc    string
}{
	{[]byte("PyFunc"), "PyFunc", "ONNX PyFunc op executes arbitrary Python code on model load/inference"},
	{[]byte("PyFuncStateless"), "PyFuncStateless", "ONNX stateless PyFunc op executes arbitrary Python code"},
	{[]byte("NumpyFunc"), "NumpyFunc", "ONNX NumpyFunc op executes arbitrary NumPy/Python code"},
}

// onnxExternalDataMarker is present in ONNX models that load weights from external files.
var onnxExternalDataMarker = []byte("data_location")

// tfPythonOpPatterns are byte patterns for TensorFlow Python ops that enable code execution.
var tfPythonOpPatterns = []struct {
	Pattern  []byte
	Name     string
	Severity string
}{
	{[]byte("PyFunc"), "PyFunc", "critical"},
	{[]byte("PyFuncStateless"), "PyFuncStateless", "critical"},
	{[]byte("NuFuncOp"), "NumpyFunc", "critical"},
}

// kerasLambdaClass is the Keras config JSON marker for Lambda layers.
const kerasLambdaClass = `"class_name":"Lambda"`

// ScanFile analyzes a single model file for supply chain risks.
func ScanFile(path string) ([]Risk, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}

	ext := strings.ToLower(filepath.Ext(path))
	var risks []Risk

	switch ext {
	case ".pkl", ".pickle":
		r, err := scanPickle(path)
		if err != nil {
			return nil, err
		}
		risks = append(risks, r...)
	case ".pt", ".pth":
		r, err := scanPyTorch(path)
		if err != nil {
			return nil, err
		}
		risks = append(risks, r...)
	case ".bin":
		r, err := scanBin(path)
		if err != nil {
			return nil, err
		}
		risks = append(risks, r...)
	case ".onnx":
		r, err := scanONNX(path)
		if err != nil {
			return nil, err
		}
		risks = append(risks, r...)
	case ".pb":
		r, err := scanTFProto(path)
		if err != nil {
			return nil, err
		}
		risks = append(risks, r...)
	case ".h5":
		r, err := scanHDF5(path)
		if err != nil {
			return nil, err
		}
		risks = append(risks, r...)
	case ".keras":
		r, err := scanKerasZip(path)
		if err != nil {
			return nil, err
		}
		risks = append(risks, r...)
	case ".safetensors":
		risks = append(risks, Risk{
			File:     path,
			RiskType: "model-format",
			Severity: "info",
			Detail:   "SafeTensors format — safe by design, no code execution risk",
		})
	case ".gguf":
		risks = append(risks, Risk{
			File:     path,
			RiskType: "model-format",
			Severity: "info",
			Detail:   "GGUF (llama.cpp / local LLM) weights — no Python pickle; treat like other binary weights for provenance review",
		})
	default:
		risks = append(risks, Risk{
			File:     path,
			RiskType: "unknown-format",
			Severity: "low",
			Detail:   fmt.Sprintf("Unknown model file extension %q — manual review recommended", ext),
		})
	}

	return risks, nil
}

// ScanDirectory recursively scans a directory for model files using DefaultScanOptions.
func ScanDirectory(dir string) ([]Risk, error) {
	return ScanDirectoryWithOptions(dir, DefaultScanOptions())
}

// ScanDirectoryWithOptions recursively scans a directory with explicit walk rules.
func ScanDirectoryWithOptions(dir string, opt ScanOptions) ([]Risk, error) {
	var allRisks []Risk
	modelExts := map[string]bool{
		".pkl": true, ".pickle": true, ".pt": true, ".pth": true,
		".bin": true, ".onnx": true, ".safetensors": true,
		".gguf": true, ".pb": true, ".h5": true, ".keras": true,
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if path != dir && len(opt.ExcludeDirNames) > 0 {
				if _, skip := opt.ExcludeDirNames[base]; skip {
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !modelExts[ext] {
			return nil
		}
		if opt.MaxFileSize > 0 && info.Size() > opt.MaxFileSize {
			allRisks = append(allRisks, Risk{
				File:     path,
				RiskType: "skipped-large-file",
				Severity: "info",
				Detail:   fmt.Sprintf("Skipped model-sized file (%d bytes) — larger than --max-file-size %d", info.Size(), opt.MaxFileSize),
			})
			return nil
		}
		risks, scanErr := ScanFile(path)
		if scanErr != nil {
			allRisks = append(allRisks, Risk{
				File:     path,
				RiskType: "scan-error",
				Severity: "info",
				Detail:   fmt.Sprintf("Failed to scan: %v", scanErr),
			})
			return nil
		}
		allRisks = append(allRisks, risks...)
		return nil
	})
	return allRisks, err
}

// HashFile computes SHA-256 of a file for hash validation.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func scanPickle(path string) ([]Risk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	risks := []Risk{{
		File:     path,
		RiskType: "pickle-deserialization",
		Severity: "critical",
		Detail:   "Pickle file detected — loading with pickle.load() or torch.load() enables arbitrary code execution",
	}}

	header := make([]byte, 2)
	if _, err := io.ReadFull(f, header); err != nil {
		return risks, nil
	}
	if header[0] == pickleMagic[0] {
		risks[0].Detail = fmt.Sprintf("Pickle protocol v%d detected — arbitrary code execution on deserialization", header[1])
	}

	if _, err := f.Seek(0, 0); err != nil {
		return risks, nil
	}
	opcodeRisks := scanForDangerousOpcodes(f, path)
	risks = append(risks, opcodeRisks...)

	return risks, nil
}

func scanPyTorch(path string) ([]Risk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, 2)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, nil
	}

	var risks []Risk
	if bytes.Equal(header, torchMagic) {
		risks = append(risks, Risk{
			File:     path,
			RiskType: "pytorch-pickle",
			Severity: "critical",
			Detail:   "PyTorch checkpoint (ZIP+pickle format) — default torch.load() enables arbitrary code execution. Use torch.load(weights_only=True) or convert to SafeTensors.",
		})

		fi, _ := f.Stat()
		if fi != nil {
			if zr, zerr := zip.NewReader(f, fi.Size()); zerr == nil {
				for _, entry := range zr.File {
					if strings.HasSuffix(entry.Name, ".pkl") || strings.HasSuffix(entry.Name, "/data.pkl") {
						rc, err := entry.Open()
						if err != nil {
							continue
						}
						opcodeRisks := scanForDangerousOpcodesLimit(rc, path+"!"+entry.Name, 10*1024*1024)
						_ = rc.Close()
						risks = append(risks, opcodeRisks...)
					}
				}
			} else {
				if _, serr := f.Seek(0, 0); serr == nil {
					opcodeRisks := scanForDangerousOpcodes(f, path)
					risks = append(risks, opcodeRisks...)
				}
			}
		}
	} else if header[0] == pickleMagic[0] {
		risks = append(risks, Risk{
			File:     path,
			RiskType: "pytorch-raw-pickle",
			Severity: "critical",
			Detail:   "PyTorch file appears to be raw pickle format — arbitrary code execution on load",
		})
	} else {
		risks = append(risks, Risk{
			File:     path,
			RiskType: "pytorch-unknown",
			Severity: "medium",
			Detail:   "PyTorch file with unrecognized header format — may use custom serialization",
		})
	}

	return risks, nil
}

func scanBin(path string) ([]Risk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, 8)
	n, _ := io.ReadFull(f, header)
	if n < 2 {
		return []Risk{{
			File:     path,
			RiskType: "binary-model",
			Severity: "low",
			Detail:   "Binary model file — too small to classify format",
		}}, nil
	}

	if header[0] == pickleMagic[0] {
		return []Risk{{
			File:     path,
			RiskType: "pickle-in-bin",
			Severity: "critical",
			Detail:   "Binary file contains pickle data — arbitrary code execution on deserialization",
		}}, nil
	}

	if bytes.Equal(header[:2], torchMagic) {
		return []Risk{{
			File:     path,
			RiskType: "pytorch-in-bin",
			Severity: "critical",
			Detail:   "Binary file is a PyTorch checkpoint (ZIP+pickle) — arbitrary code execution via torch.load()",
		}}, nil
	}

	return []Risk{{
		File:     path,
		RiskType: "binary-model",
		Severity: "low",
		Detail:   "Binary model file — format not recognized, manual review recommended",
	}}, nil
}

func scanForDangerousOpcodes(r io.Reader, path string) []Risk {
	return scanForDangerousOpcodesLimit(r, path, 10*1024*1024)
}

// scanONNX performs deep scanning of an ONNX model file for custom ops and external data.
func scanONNX(path string) ([]Risk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const maxScan = 64 * 1024 * 1024
	buf := make([]byte, maxScan)
	n, _ := f.Read(buf)
	buf = buf[:n]

	var risks []Risk
	for _, pat := range onnxCustomOpPatterns {
		if bytes.Contains(buf, pat.Pattern) {
			risks = append(risks, Risk{
				File:     path,
				RiskType: "onnx-custom-op",
				Severity: "high",
				Detail: fmt.Sprintf("ONNX model contains custom op %q: %s",
					pat.Name, pat.Desc),
			})
		}
	}

	if bytes.Contains(buf, onnxExternalDataMarker) {
		risks = append(risks, Risk{
			File:     path,
			RiskType: "onnx-external-data",
			Severity: "medium",
			Detail:   "ONNX model references external data files (data_location). Loading this model may trigger file access from operator-controlled paths.",
		})
	}

	if len(risks) == 0 {
		risks = append(risks, Risk{
			File:     path,
			RiskType: "model-format",
			Severity: "info",
			Detail:   "ONNX model file — no custom ops or external data references detected",
		})
	}
	return risks, nil
}

// scanTFProto scans a TensorFlow SavedModel protobuf file for Python ops.
func scanTFProto(path string) ([]Risk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const maxScan = 64 * 1024 * 1024
	buf := make([]byte, maxScan)
	n, _ := f.Read(buf)
	buf = buf[:n]

	var risks []Risk
	for _, pat := range tfPythonOpPatterns {
		if bytes.Contains(buf, pat.Pattern) {
			risks = append(risks, Risk{
				File:     path,
				RiskType: "tf-python-op",
				Severity: pat.Severity,
				Detail: fmt.Sprintf(
					"TensorFlow SavedModel contains %q op — arbitrary Python code execution on model load or inference",
					pat.Name),
			})
		}
	}

	if len(risks) == 0 {
		risks = append(risks, Risk{
			File:     path,
			RiskType: "model-format",
			Severity: "info",
			Detail:   "TensorFlow SavedModel (.pb) — protobuf graph file; no Python execution ops detected. Review for custom ops.",
		})
	}
	return risks, nil
}

// scanHDF5 scans an HDF5-based Keras model file for Lambda layer code execution.
func scanHDF5(path string) ([]Risk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Verify HDF5 magic bytes.
	header := make([]byte, 8)
	if _, err := io.ReadFull(f, header); err != nil {
		return []Risk{{
			File:     path,
			RiskType: "model-format",
			Severity: "info",
			Detail:   "Keras HDF5 file too small to verify magic — manual review recommended",
		}}, nil
	}
	if !bytes.Equal(header, hdf5Magic) {
		return []Risk{{
			File:     path,
			RiskType: "model-format-unknown",
			Severity: "low",
			Detail:   ".h5 file does not have HDF5 magic bytes — format may be corrupted or non-Keras",
		}}, nil
	}

	// Scan file body for Lambda layer markers embedded in JSON config strings.
	const maxScan = 64 * 1024 * 1024
	buf := make([]byte, maxScan)
	n, _ := f.Read(buf)
	buf = buf[:n]

	if bytes.Contains(buf, []byte(kerasLambdaClass)) {
		return []Risk{{
			File:     path,
			RiskType: "keras-lambda-layer",
			Severity: "high",
			Detail:   "Keras HDF5 model contains a Lambda layer (\"class_name\":\"Lambda\"). Lambda layers serialize and deserialize Python source code, enabling arbitrary code execution on model load.",
		}}, nil
	}

	return []Risk{{
		File:     path,
		RiskType: "model-format",
		Severity: "info",
		Detail:   "Keras HDF5 model — no Lambda layers detected",
	}}, nil
}

// scanKerasZip scans a Keras 3.x .keras zip archive for Lambda layers in config.json.
func scanKerasZip(path string) ([]Risk, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		// Fallback: treat it like HDF5.
		return scanHDF5(path)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name != "config.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var cfg map[string]interface{}
		parseErr := json.NewDecoder(rc)
		_ = parseErr.Decode(&cfg)
		rc.Close()

		// Re-open and scan raw bytes for Lambda marker.
		rc2, err := f.Open()
		if err != nil {
			continue
		}
		rawBuf, _ := io.ReadAll(io.LimitReader(rc2, 4*1024*1024))
		rc2.Close()

		if bytes.Contains(rawBuf, []byte(kerasLambdaClass)) {
			return []Risk{{
				File:     path,
				RiskType: "keras-lambda-layer",
				Severity: "high",
				Detail:   "Keras 3.x .keras archive contains a Lambda layer in config.json. Lambda layers serialize Python source code and enable arbitrary code execution on model load.",
			}}, nil
		}
	}

	return []Risk{{
		File:     path,
		RiskType: "model-format",
		Severity: "info",
		Detail:   "Keras 3.x .keras archive — no Lambda layers detected in config.json",
	}}, nil
}

func scanForDangerousOpcodesLimit(r io.Reader, path string, maxScan int64) []Risk {
	var risks []Risk
	if maxScan <= 0 {
		maxScan = 10 * 1024 * 1024
	}
	scanner := bufio.NewReader(r)

	buf := make([]byte, maxScan)
	n, _ := scanner.Read(buf)
	buf = buf[:n]

	for _, op := range dangerousOpcodes {
		// Raw pickle opcodes are single bytes (often >0x7f). Do not use ContainsRune,
		// which searches for UTF-8 encoding of the rune, not the byte value.
		if bytes.IndexByte(buf, op.Opcode) >= 0 {
			risks = append(risks, Risk{
				File:     path,
				RiskType: fmt.Sprintf("pickle-opcode-%s", strings.ToLower(op.Name)),
				Severity: "critical",
				Detail:   fmt.Sprintf("Dangerous pickle opcode %s (0x%02x) found: %s", op.Name, op.Opcode, op.Desc),
			})
		}
	}
	return risks
}
