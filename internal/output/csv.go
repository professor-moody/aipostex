package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/professor-moody/aipostex/pkg/report"
)

var csvColumns = []string{
	"id", "timestamp", "source", "template_id", "target", "title",
	"severity", "cvss", "description", "evidence", "remediation",
	"tags", "references", "landed", "stage", "action",
}

// CSVWriter writes findings as CSV rows.
type CSVWriter struct {
	w      io.WriteCloser
	csv    *csv.Writer
	header bool
}

func NewCSVWriter(path string) (*CSVWriter, error) {
	var w io.WriteCloser
	if path == "" || path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("creating csv output file: %w", err)
		}
		w = f
	}
	return &CSVWriter{w: w, csv: csv.NewWriter(w)}, nil
}

func (cw *CSVWriter) WriteHeader() error {
	if cw.header {
		return nil
	}
	cw.header = true
	return cw.csv.Write(csvColumns)
}

func (cw *CSVWriter) WriteFinding(f report.Finding) error {
	if !cw.header {
		if err := cw.WriteHeader(); err != nil {
			return err
		}
	}
	ts := ""
	if !f.Timestamp.IsZero() {
		ts = f.Timestamp.Format("2006-01-02T15:04:05Z")
	}
	landed := csvMetaString(f.Metadata, "landed")
	stage := csvMetaString(f.Metadata, "stage")
	action := csvMetaString(f.Metadata, "action")
	row := []string{
		f.ID,
		ts,
		f.Source,
		f.TemplateID,
		f.Target,
		f.Title,
		f.Severity,
		fmt.Sprintf("%.1f", f.CVSS),
		f.Description,
		f.Evidence,
		f.Remediation,
		strings.Join(f.Tags, "; "),
		strings.Join(f.References, "; "),
		landed,
		stage,
		action,
	}
	return cw.csv.Write(row)
}

func (cw *CSVWriter) WriteFooter(_ map[string]int) error {
	cw.csv.Flush()
	return cw.csv.Error()
}

func (cw *CSVWriter) Close() error {
	cw.csv.Flush()
	if cw.w != os.Stdout {
		return cw.w.Close()
	}
	return nil
}

func csvMetaString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
