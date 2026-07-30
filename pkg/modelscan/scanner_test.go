package modelscan

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFile_Pickle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.pkl")
	// Pickle v2 header + GLOBAL opcode
	if err := os.WriteFile(path, []byte{0x80, 0x02, 0x63}, 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) == 0 {
		t.Fatal("expected risks for pickle file")
	}
	foundPickle := false
	for _, r := range risks {
		if r.RiskType == "pickle-deserialization" {
			foundPickle = true
			if r.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", r.Severity)
			}
		}
	}
	if !foundPickle {
		t.Error("expected pickle-deserialization risk")
	}
}

func TestScanFile_PyTorch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.pt")
	// PK (ZIP header) followed by data
	if err := os.WriteFile(path, []byte("PK\x03\x04\x00\x00\x00\x00"), 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	foundPyTorch := false
	for _, r := range risks {
		if r.RiskType == "pytorch-pickle" {
			foundPyTorch = true
		}
	}
	if !foundPyTorch {
		t.Error("expected pytorch-pickle risk")
	}
}

func TestScanFile_ONNX(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.onnx")
	if err := os.WriteFile(path, []byte("onnx-data"), 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk for ONNX, got %d", len(risks))
	}
	if risks[0].Severity != "info" {
		t.Errorf("expected info severity for ONNX, got %s", risks[0].Severity)
	}
}

func TestScanFile_SafeTensors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.safetensors")
	if err := os.WriteFile(path, []byte("safetensors-data"), 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 || risks[0].Severity != "info" {
		t.Errorf("expected 1 info risk for SafeTensors, got %v", risks)
	}
}

func TestScanDirectory(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "safe.safetensors"), []byte("safe"), 0644)
	os.WriteFile(filepath.Join(dir, "dangerous.pkl"), []byte{0x80, 0x02}, 0644)
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("text"), 0644)

	risks, err := ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) < 2 {
		t.Fatalf("expected at least 2 risks (pkl + safetensors), got %d", len(risks))
	}
}

func TestScanDirectoryWithOptions_SkipsExcludedDirs(t *testing.T) {
	dir := t.TempDir()
	nodeDir := filepath.Join(dir, "node_modules", "pkg")
	if err := os.MkdirAll(nodeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "bad.pkl"), []byte{0x80, 0x02}, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.safetensors"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanDirectoryWithOptions(dir, DefaultScanOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range risks {
		if strings.Contains(r.File, "node_modules") {
			t.Fatalf("expected node_modules skipped, found risk on %s", r.File)
		}
	}
	found := false
	for _, r := range risks {
		if strings.HasSuffix(r.File, "good.safetensors") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected scan of good.safetensors, got %#v", risks)
	}
}

func TestScanDirectoryWithOptions_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "huge.pkl")
	if err := os.WriteFile(p, []byte{0x80, 0x02}, 0644); err != nil {
		t.Fatal(err)
	}
	opt := ScanOptions{MaxFileSize: 1, ExcludeDirNames: map[string]struct{}{}}
	risks, err := ScanDirectoryWithOptions(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 || risks[0].RiskType != "skipped-large-file" {
		t.Fatalf("expected skipped-large-file, got %#v", risks)
	}
}

func TestScanDirectoryWithOptions_LargeNonModelIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dataset.mp4"), make([]byte, 4096), 0644); err != nil {
		t.Fatal(err)
	}
	opt := ScanOptions{MaxFileSize: 1024, ExcludeDirNames: map[string]struct{}{}}
	risks, err := ScanDirectoryWithOptions(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range risks {
		if r.RiskType == "skipped-large-file" {
			t.Fatalf("non-model file should not emit skipped-large-file, got %#v", r)
		}
	}
}

func TestScanFile_PickleHighByteOpcode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evil.pkl")
	// v4 header + NEWOBJ (0x81) — must be detected as raw byte, not UTF-8 rune search.
	if err := os.WriteFile(path, []byte{0x80, 0x04, 0x81, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}
	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range risks {
		if r.RiskType == "pickle-opcode-newobj" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected pickle-opcode-newobj in risks, got %#v", risks)
	}
}

func TestScanFile_GGUF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.gguf")
	if err := os.WriteFile(path, []byte("GGUF"), 0644); err != nil {
		t.Fatal(err)
	}
	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 || risks[0].RiskType != "model-format" {
		t.Fatalf("expected gguf model-format info, got %#v", risks)
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars", len(hash))
	}
}

func TestScanFile_BinWithPickle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.bin")
	if err := os.WriteFile(path, []byte{0x80, 0x04, 0x63, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	foundPickle := false
	for _, r := range risks {
		if r.RiskType == "pickle-in-bin" {
			foundPickle = true
		}
	}
	if !foundPickle {
		t.Error("expected pickle-in-bin risk for .bin with pickle header")
	}
}

func TestScanFile_Directory(t *testing.T) {
	dir := t.TempDir()
	_, err := ScanFile(dir)
	if err == nil {
		t.Error("expected error for directory input")
	}
}

func TestScanFile_PyTorchRawPickle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.pt")
	if err := os.WriteFile(path, []byte{0x80, 0x04, 0x63, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range risks {
		if r.RiskType == "pytorch-raw-pickle" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected pytorch-raw-pickle risk, got %#v", risks)
	}
}

func TestScanFile_PyTorchUnknownHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.pth")
	if err := os.WriteFile(path, []byte{0xFF, 0xFE, 0x00, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range risks {
		if r.RiskType == "pytorch-unknown" {
			found = true
			if r.Severity != "medium" {
				t.Errorf("expected medium severity, got %s", r.Severity)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected pytorch-unknown risk, got %#v", risks)
	}
}

func TestScanFile_BinWithPyTorchZIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.bin")
	if err := os.WriteFile(path, []byte("PK\x03\x04\x00\x00"), 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range risks {
		if r.RiskType == "pytorch-in-bin" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected pytorch-in-bin risk, got %#v", risks)
	}
}

func TestScanFile_BinTooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.bin")
	if err := os.WriteFile(path, []byte{0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 || risks[0].RiskType != "binary-model" {
		t.Fatalf("expected binary-model risk for tiny file, got %#v", risks)
	}
	if !strings.Contains(risks[0].Detail, "too small") {
		t.Fatalf("expected 'too small' in detail, got %q", risks[0].Detail)
	}
}

func TestScanFile_BinUnrecognized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, []byte{0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49}, 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 || risks[0].RiskType != "binary-model" {
		t.Fatalf("expected binary-model risk, got %#v", risks)
	}
	if !strings.Contains(risks[0].Detail, "not recognized") {
		t.Fatalf("expected 'not recognized' in detail, got %q", risks[0].Detail)
	}
}

func TestScanFile_UnknownExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.custom")
	if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 || risks[0].RiskType != "unknown-format" {
		t.Fatalf("expected unknown-format risk, got %#v", risks)
	}
}

func TestScanFile_PyTorchValidZIPWithPickleEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.pt")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("archive/data.pkl")
	if err != nil {
		t.Fatal(err)
	}
	// pickle v4 header + REDUCE opcode (0x52) + GLOBAL opcode (0x63)
	w.Write([]byte{0x80, 0x04, 0x52, 0x63, 0x00})
	zw.Close()

	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	foundCheckpoint := false
	foundOpcode := false
	for _, r := range risks {
		if r.RiskType == "pytorch-pickle" {
			foundCheckpoint = true
		}
		if strings.HasPrefix(r.RiskType, "pickle-opcode-") {
			foundOpcode = true
		}
	}
	if !foundCheckpoint {
		t.Error("expected pytorch-pickle risk for valid ZIP")
	}
	if !foundOpcode {
		t.Errorf("expected dangerous opcode detection inside ZIP pkl entry, got %#v", risks)
	}
}

func TestScanFile_PickleWithMultipleOpcodes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.pkl")
	// pickle v2 header + GLOBAL(0x63) + REDUCE(0x52) + INST(0x69)
	if err := os.WriteFile(path, []byte{0x80, 0x02, 0x63, 0x52, 0x69, 0x00}, 0644); err != nil {
		t.Fatal(err)
	}

	risks, err := ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opcodeTypes := make(map[string]bool)
	for _, r := range risks {
		if strings.HasPrefix(r.RiskType, "pickle-opcode-") {
			opcodeTypes[r.RiskType] = true
		}
	}
	for _, expected := range []string{"pickle-opcode-global", "pickle-opcode-reduce", "pickle-opcode-inst"} {
		if !opcodeTypes[expected] {
			t.Errorf("expected %s in risks, got %v", expected, opcodeTypes)
		}
	}
}

func TestScanFile_Nonexistent(t *testing.T) {
	_, err := ScanFile("/nonexistent/model.pkl")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
