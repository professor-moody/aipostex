package exitcode

import (
	"errors"
	"fmt"
	"testing"
)

func TestCodeNilReturnsOK(t *testing.T) {
	if got := Code(nil); got != OK {
		t.Fatalf("Code(nil) = %d, want %d", got, OK)
	}
}

func TestCodeDirectFindingsError(t *testing.T) {
	err := &FindingsError{Count: 5}
	if got := Code(err); got != Findings {
		t.Fatalf("Code(FindingsError) = %d, want %d", got, Findings)
	}
}

func TestCodeWrappedFindingsError(t *testing.T) {
	inner := &FindingsError{Count: 3}
	wrapped := fmt.Errorf("scan complete: %w", inner)
	if got := Code(wrapped); got != Findings {
		t.Fatalf("Code(wrapped FindingsError) = %d, want %d", got, Findings)
	}
}

func TestCodeDirectPartialError(t *testing.T) {
	err := &PartialError{Succeeded: 2, Failed: 1, Cause: errors.New("timeout")}
	if got := Code(err); got != PartialFailure {
		t.Fatalf("Code(PartialError) = %d, want %d", got, PartialFailure)
	}
}

func TestCodeWrappedPartialError(t *testing.T) {
	inner := &PartialError{Succeeded: 4, Failed: 2, Cause: errors.New("timeout")}
	wrapped := fmt.Errorf("module run: %w", inner)
	if got := Code(wrapped); got != PartialFailure {
		t.Fatalf("Code(wrapped PartialError) = %d, want %d", got, PartialFailure)
	}
}

func TestFindingsPartialErrorMessage(t *testing.T) {
	inner := errors.New("dns error")
	e := &FindingsPartialError{FindingsCount: 3, Succeeded: 5, Failed: 2, Cause: inner}
	msg := e.Error()
	if msg == "" {
		t.Fatal("expected non-empty error message")
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap should return the cause")
	}
}

func TestCodeFindingsPartialError(t *testing.T) {
	err := &FindingsPartialError{FindingsCount: 2, Succeeded: 3, Failed: 1, Cause: errors.New("x")}
	if got := Code(err); got != FindingsPartial {
		t.Fatalf("Code(FindingsPartialError) = %d, want %d", got, FindingsPartial)
	}
}

func TestPartialErrorMessage(t *testing.T) {
	inner := errors.New("timeout")
	e := &PartialError{Succeeded: 2, Failed: 1, Cause: inner}
	msg := e.Error()
	if msg == "" {
		t.Fatal("expected non-empty error message")
	}
	if e.Unwrap() != inner {
		t.Error("Unwrap should return the cause")
	}
}

func TestCodeGenericError(t *testing.T) {
	err := errors.New("something went wrong")
	if got := Code(err); got != Error {
		t.Fatalf("Code(generic) = %d, want %d", got, Error)
	}
}
