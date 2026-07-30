package output

import "github.com/professor-moody/aipostex/pkg/report"

// MultiWriter fans out every Writer call to several underlying writers. It backs
// "see and save": render the human console view to stderr AND write a structured
// artifact to a file in the same run. Header/Finding/Footer/Close are delivered to
// ALL writers; the first error from each phase is returned, but every writer still
// receives the call (so the file is always flushed even if the console errors).
type MultiWriter struct {
	writers []Writer
}

// NewMultiWriter returns a Writer that fans out to all non-nil writers.
func NewMultiWriter(writers ...Writer) *MultiWriter {
	ws := make([]Writer, 0, len(writers))
	for _, w := range writers {
		if w != nil {
			ws = append(ws, w)
		}
	}
	return &MultiWriter{writers: ws}
}

func (m *MultiWriter) WriteHeader() error {
	var firstErr error
	for _, w := range m.writers {
		if err := w.WriteHeader(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiWriter) WriteFinding(f report.Finding) error {
	var firstErr error
	for _, w := range m.writers {
		if err := w.WriteFinding(f); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiWriter) WriteFooter(stats map[string]int) error {
	var firstErr error
	for _, w := range m.writers {
		if err := w.WriteFooter(stats); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiWriter) Close() error {
	var firstErr error
	for _, w := range m.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// SetHostNextSteps forwards the per-host "start here" commands to any child writer that
// supports the optional interface — without this the grouped console inside a see-and-save
// tee (`-o`) would lose the inline "-> next:" guidance that plain console mode shows.
func (m *MultiWriter) SetHostNextSteps(next map[string]HostNextSteps) {
	for _, w := range m.writers {
		if setter, ok := w.(interface {
			SetHostNextSteps(map[string]HostNextSteps)
		}); ok {
			setter.SetHostNextSteps(next)
		}
	}
}

// SetSuppressNextActions forwards the suppress flag to any child writer that supports it.
func (m *MultiWriter) SetSuppressNextActions(suppress bool) {
	for _, w := range m.writers {
		if setter, ok := w.(interface{ SetSuppressNextActions(bool) }); ok {
			setter.SetSuppressNextActions(suppress)
		}
	}
}
