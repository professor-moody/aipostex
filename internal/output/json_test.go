package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestJSONWriterPopulatesCollectionMetadata(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "findings.json")
	writer, err := NewJSONWriter(outputPath)
	if err != nil {
		t.Fatalf("NewJSONWriter returned error: %v", err)
	}

	finding := report.Finding{
		ID:          "finding-1",
		Timestamp:   time.Now().UTC(),
		Source:      report.SourceVulnCheck,
		Target:      "http://127.0.0.1:3000",
		Title:       "Example",
		Severity:    report.SeverityHigh,
		Description: "Example finding",
	}
	if err := writer.WriteFinding(finding); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.WriteFooter(nil); err != nil {
		t.Fatalf("WriteFooter returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	var collection report.FindingCollection
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if collection.EngagementID == "" {
		t.Fatal("expected engagement_id to be populated")
	}
	if collection.StartTime.IsZero() {
		t.Fatal("expected start_time to be populated")
	}
}

func TestJSONAndJSONLPreserveWorkflowAndEvidenceMetadata(t *testing.T) {
	outputDir := t.TempDir()
	jsonPath := filepath.Join(outputDir, "findings.json")
	jsonlPath := filepath.Join(outputDir, "findings.jsonl")

	finding := report.Finding{
		ID:          "finding-2",
		Timestamp:   time.Now().UTC(),
		Source:      report.SourceOpenAICompat,
		Target:      "http://127.0.0.1:8000",
		Title:       "Model exposed",
		Severity:    report.SeverityInfo,
		Description: "Example finding",
		Metadata: map[string]interface{}{
			"workflow": map[string]interface{}{
				"stage": "enum",
				"recommendations": []map[string]interface{}{
					{
						"command": "aipostex openai-compat --target http://127.0.0.1:8000 validate-inference --model llama3",
						"gated":   false,
					},
				},
			},
			"evidence": map[string]interface{}{
				"kind":          "model-response",
				"preview":       "trimmed preview",
				"raw_preserved": true,
			},
		},
	}

	jsonWriter, err := NewJSONWriter(jsonPath)
	if err != nil {
		t.Fatalf("NewJSONWriter returned error: %v", err)
	}
	if err := jsonWriter.WriteFinding(finding); err != nil {
		t.Fatalf("JSON WriteFinding returned error: %v", err)
	}
	if err := jsonWriter.WriteFooter(nil); err != nil {
		t.Fatalf("JSON WriteFooter returned error: %v", err)
	}
	if err := jsonWriter.Close(); err != nil {
		t.Fatalf("JSON Close returned error: %v", err)
	}

	jsonlWriter, err := NewJSONLWriter(jsonlPath)
	if err != nil {
		t.Fatalf("NewJSONLWriter returned error: %v", err)
	}
	if err := jsonlWriter.WriteFinding(finding); err != nil {
		t.Fatalf("JSONL WriteFinding returned error: %v", err)
	}
	if err := jsonlWriter.Close(); err != nil {
		t.Fatalf("JSONL Close returned error: %v", err)
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("reading json output: %v", err)
	}
	var collection report.FindingCollection
	if err := json.Unmarshal(jsonData, &collection); err != nil {
		t.Fatalf("unmarshal json output: %v", err)
	}
	if len(collection.Findings) != 1 {
		t.Fatalf("expected one JSON finding, got %d", len(collection.Findings))
	}
	if _, ok := collection.Findings[0].Metadata["workflow"]; !ok {
		t.Fatalf("expected workflow metadata in JSON output, got %#v", collection.Findings[0].Metadata)
	}
	if _, ok := collection.Findings[0].Metadata["evidence"]; !ok {
		t.Fatalf("expected evidence metadata in JSON output, got %#v", collection.Findings[0].Metadata)
	}

	jsonlData, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("reading jsonl output: %v", err)
	}
	var jsonlFinding report.Finding
	if err := json.Unmarshal(jsonlData[:len(jsonlData)-1], &jsonlFinding); err != nil {
		t.Fatalf("unmarshal jsonl output: %v", err)
	}
	if _, ok := jsonlFinding.Metadata["workflow"]; !ok {
		t.Fatalf("expected workflow metadata in JSONL output, got %#v", jsonlFinding.Metadata)
	}
	if _, ok := jsonlFinding.Metadata["evidence"]; !ok {
		t.Fatalf("expected evidence metadata in JSONL output, got %#v", jsonlFinding.Metadata)
	}
}

func TestJSONLWriterNoOpHeaderAndFooter(t *testing.T) {
	path := t.TempDir() + "/noop.jsonl"
	jw, err := NewJSONLWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := jw.WriteHeader(); err != nil {
		t.Fatalf("WriteHeader should be no-op, got %v", err)
	}
	if err := jw.WriteFooter(map[string]int{"high": 1}); err != nil {
		t.Fatalf("WriteFooter should be no-op, got %v", err)
	}
	_ = jw.Close()
}

func TestJSONWriterWriteHeaderIdempotent(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "idempotent.json")
	writer, err := NewJSONWriter(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(); err != nil {
		t.Fatalf("first WriteHeader: %v", err)
	}
	if err := writer.WriteHeader(); err != nil {
		t.Fatalf("second WriteHeader should be no-op: %v", err)
	}
	if err := writer.WriteFooter(nil); err != nil {
		t.Fatalf("WriteFooter: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, _ := os.ReadFile(outputPath)
	var collection report.FindingCollection
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestJSONWriterWriteFooterIdempotent(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "footer-idem.json")
	writer, err := NewJSONWriter(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteFooter(nil); err != nil {
		t.Fatalf("first WriteFooter: %v", err)
	}
	if err := writer.WriteFooter(nil); err != nil {
		t.Fatalf("second WriteFooter should be no-op: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestJSONWriterMultipleFindings(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "multi.json")
	writer, err := NewJSONWriter(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := writer.WriteFinding(report.Finding{
			ID:       fmt.Sprintf("f-%d", i),
			Source:   report.SourceVulnCheck,
			Target:   "http://10.0.0.1:8080",
			Title:    fmt.Sprintf("Finding %d", i),
			Severity: report.SeverityHigh,
		}); err != nil {
			t.Fatalf("WriteFinding %d: %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, _ := os.ReadFile(outputPath)
	var collection report.FindingCollection
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(collection.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(collection.Findings))
	}
}

func TestJSONWriterWriteFooterAutoStartsHeader(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "auto-header.json")
	writer, err := NewJSONWriter(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteFooter(nil); err != nil {
		t.Fatalf("WriteFooter without prior WriteHeader: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, _ := os.ReadFile(outputPath)
	var collection report.FindingCollection
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !collection.EndTime.After(time.Time{}) {
		t.Fatal("expected end_time to be populated")
	}
}

func TestJSONWriterCloseFinalizesWhenFooterNotCalled(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "findings-close.json")
	writer, err := NewJSONWriter(outputPath)
	if err != nil {
		t.Fatalf("NewJSONWriter returned error: %v", err)
	}

	if err := writer.WriteFinding(report.Finding{
		ID:          "finding-close",
		Timestamp:   time.Now().UTC(),
		Source:      report.SourceVulnCheck,
		Target:      "http://127.0.0.1:3000",
		Title:       "Close finalization",
		Severity:    report.SeverityLow,
		Description: "Footer should auto-write on close",
	}); err != nil {
		t.Fatalf("WriteFinding returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	var collection report.FindingCollection
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(collection.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(collection.Findings))
	}
	if collection.EndTime.IsZero() {
		t.Fatal("expected end_time to be populated")
	}
}
