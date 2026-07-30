package main

import (
	"os"
	"testing"

	"github.com/professor-moody/aipostex/internal/output"
)

// TestMain pins a deterministic, wide framing width for the cmd-package tests so the
// framed summary/next-actions/hint printers render their single-line form regardless of
// the runner's terminal size ($COLUMNS). Tests that assert wrapping set a narrow width
// locally and restore this default with a defer.
func TestMain(m *testing.M) {
	output.SetConsoleWidth(400)
	os.Exit(m.Run())
}
