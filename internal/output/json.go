package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/professor-moody/aipostex/pkg/report"
)

// JSONWriter writes findings as a JSON array
type JSONWriter struct {
	w              io.WriteCloser
	collectionMeta report.FindingCollection
	started        bool
	firstFinding   bool
	footerWritten  bool
}

func NewJSONWriter(path string) (*JSONWriter, error) {
	var w io.WriteCloser
	if path == "" || path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("creating output file: %w", err)
		}
		w = f
	}
	meta := report.NewCollection()
	meta.Findings = nil
	return &JSONWriter{
		w:              w,
		collectionMeta: *meta,
		firstFinding:   true,
	}, nil
}

func (jw *JSONWriter) WriteHeader() error {
	if jw.started {
		return nil
	}
	meta, err := json.Marshal(struct {
		EngagementID string    `json:"engagement_id"`
		StartTime    time.Time `json:"start_time"`
	}{
		EngagementID: jw.collectionMeta.EngagementID,
		StartTime:    jw.collectionMeta.StartTime,
	})
	if err != nil {
		return fmt.Errorf("marshaling output header: %w", err)
	}
	if len(meta) == 0 || meta[len(meta)-1] != '}' {
		return fmt.Errorf("invalid output header encoding")
	}
	if _, err := jw.w.Write(meta[:len(meta)-1]); err != nil {
		return fmt.Errorf("writing output header: %w", err)
	}
	if _, err := jw.w.Write([]byte(`,"findings":[`)); err != nil {
		return fmt.Errorf("writing output header: %w", err)
	}
	jw.started = true
	return nil
}

func (jw *JSONWriter) WriteFinding(f report.Finding) error {
	if !jw.started {
		if err := jw.WriteHeader(); err != nil {
			return err
		}
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshaling finding: %w", err)
	}
	if !jw.firstFinding {
		if _, err := jw.w.Write([]byte(",")); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if _, err := jw.w.Write(data); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	jw.firstFinding = false
	return nil
}

func (jw *JSONWriter) WriteFooter(stats map[string]int) error {
	_ = stats
	if jw.footerWritten {
		return nil
	}
	if !jw.started {
		if err := jw.WriteHeader(); err != nil {
			return err
		}
	}
	endMeta, err := json.Marshal(struct {
		EndTime time.Time `json:"end_time"`
	}{
		EndTime: time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("marshaling output footer: %w", err)
	}
	if len(endMeta) == 0 || endMeta[0] != '{' || endMeta[len(endMeta)-1] != '}' {
		return fmt.Errorf("invalid output footer encoding")
	}
	if _, err := jw.w.Write([]byte("],")); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if _, err := jw.w.Write(endMeta[1:]); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	if _, err := jw.w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	jw.footerWritten = true
	return nil
}

func (jw *JSONWriter) Close() error {
	if !jw.footerWritten {
		if err := jw.WriteFooter(nil); err != nil {
			return err
		}
	}
	if jw.w != os.Stdout {
		return jw.w.Close()
	}
	return nil
}

// JSONLWriter writes findings as newline-delimited JSON (one per line, streaming)
type JSONLWriter struct {
	w io.WriteCloser
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	var w io.WriteCloser
	if path == "" || path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("creating output file: %w", err)
		}
		w = f
	}
	return &JSONLWriter{w: w}, nil
}

func (jw *JSONLWriter) WriteHeader() error                 { return nil }
func (jw *JSONLWriter) WriteFooter(_ map[string]int) error { return nil }

func (jw *JSONLWriter) WriteFinding(f report.Finding) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(jw.w, "%s\n", data)
	return err
}

func (jw *JSONLWriter) Close() error {
	if jw.w != os.Stdout {
		return jw.w.Close()
	}
	return nil
}
