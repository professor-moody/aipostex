package output

import (
	"bytes"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

// The "see + save" tee must deliver every finding to all underlying writers.
func TestMultiWriterFansOut(t *testing.T) {
	var a, b bytes.Buffer
	m := NewMultiWriter(NewConsoleWriterTo(&a, false), NewConsoleWriterTo(&b, false))
	if err := m.WriteHeader(); err != nil {
		t.Fatal(err)
	}
	f := report.Finding{ID: "f1", Title: "canary finding", Severity: "high", Target: "http://x:1"}
	if err := m.WriteFinding(f); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteFooter(map[string]int{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(a.Bytes(), []byte("canary finding")) {
		t.Errorf("writer A missing the finding: %q", a.String())
	}
	if !bytes.Contains(b.Bytes(), []byte("canary finding")) {
		t.Errorf("writer B missing the finding: %q", b.String())
	}
}

// nil writers are skipped, not panicked on.
func TestMultiWriterSkipsNil(t *testing.T) {
	var a bytes.Buffer
	m := NewMultiWriter(nil, NewConsoleWriterTo(&a, false), nil)
	if err := m.WriteFinding(report.Finding{ID: "f1", Title: "x", Severity: "low", Target: "t"}); err != nil {
		t.Fatal(err)
	}
	if a.Len() == 0 {
		t.Fatal("expected output from the non-nil writer")
	}
}

type recordingWriter struct {
	gotNextSteps bool
	gotSuppress  bool
}

func (r *recordingWriter) WriteHeader() error                        { return nil }
func (r *recordingWriter) WriteFinding(report.Finding) error         { return nil }
func (r *recordingWriter) WriteFooter(map[string]int) error          { return nil }
func (r *recordingWriter) Close() error                              { return nil }
func (r *recordingWriter) SetHostNextSteps(map[string]HostNextSteps) { r.gotNextSteps = true }
func (r *recordingWriter) SetSuppressNextActions(bool)               { r.gotSuppress = true }

// Regression for AIP34-MULTIWRITER-NEXT-STEPS: a top-level type-assert for SetHostNextSteps /
// SetSuppressNextActions must reach the child writers (so a grouped console teed under `-o`
// keeps its inline "-> next:" guidance).
func TestMultiWriterForwardsOptionalInterfaces(t *testing.T) {
	rec := &recordingWriter{}
	var buf bytes.Buffer
	m := NewMultiWriter(NewConsoleWriterTo(&buf, false), rec)

	setter, ok := interface{}(m).(interface {
		SetHostNextSteps(map[string]HostNextSteps)
	})
	if !ok {
		t.Fatal("MultiWriter must implement SetHostNextSteps for the workflow type-assert")
	}
	setter.SetHostNextSteps(map[string]HostNextSteps{"h": {}})
	if !rec.gotNextSteps {
		t.Error("SetHostNextSteps was not forwarded to the child writer")
	}

	m.SetSuppressNextActions(true)
	if !rec.gotSuppress {
		t.Error("SetSuppressNextActions was not forwarded to the child writer")
	}
}
