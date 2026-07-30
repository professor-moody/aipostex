package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunTemplatesListsLoadedTemplates(t *testing.T) {
	prevErr := stderrWriter
	defer func() { stderrWriter = prevErr }()
	var stderr bytes.Buffer
	stderrWriter = &stderr

	withTestConfig(t, func() {
		err := runTemplates(nil, nil)
		if err != nil {
			t.Fatalf("runTemplates returned error: %v", err)
		}
		rendered := stderr.String()
		if !strings.Contains(rendered, "template(s) loaded") {
			t.Fatalf("expected template summary in stderr, got %q", rendered)
		}
	})
}

func TestRunTemplatesLintBuiltins(t *testing.T) {
	withTestConfig(t, func() {
		if err := runTemplatesLint(nil, nil); err != nil {
			t.Fatalf("runTemplatesLint returned error: %v", err)
		}
	})
}
