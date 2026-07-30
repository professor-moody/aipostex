package exitcode

import (
	"errors"
	"fmt"
)

const (
	OK              = 0
	Error           = 1
	Findings        = 2
	PartialFailure  = 3
	FindingsPartial = 4
)

// FindingsError indicates the scan completed and produced findings.
type FindingsError struct {
	Count int
}

func (e *FindingsError) Error() string {
	return fmt.Sprintf("%d finding(s) discovered", e.Count)
}

// PartialError indicates some modules or templates failed while others succeeded.
type PartialError struct {
	Succeeded int
	Failed    int
	Cause     error
}

func (e *PartialError) Error() string {
	return fmt.Sprintf("partial failure: %d succeeded, %d failed: %v", e.Succeeded, e.Failed, e.Cause)
}

func (e *PartialError) Unwrap() error {
	return e.Cause
}

// FindingsPartialError indicates findings were discovered but some targets
// also had failures, so coverage is incomplete.
type FindingsPartialError struct {
	FindingsCount int
	Succeeded     int
	Failed        int
	Cause         error
}

func (e *FindingsPartialError) Error() string {
	return fmt.Sprintf("%d finding(s) discovered with incomplete coverage: %d succeeded, %d failed: %v",
		e.FindingsCount, e.Succeeded, e.Failed, e.Cause)
}

func (e *FindingsPartialError) Unwrap() error {
	return e.Cause
}

// Code maps an error to the appropriate exit code.
// Uses errors.As so wrapped errors are matched correctly.
func Code(err error) int {
	if err == nil {
		return OK
	}
	var fpe *FindingsPartialError
	if errors.As(err, &fpe) {
		return FindingsPartial
	}
	var fe *FindingsError
	if errors.As(err, &fe) {
		return Findings
	}
	var pe *PartialError
	if errors.As(err, &pe) {
		return PartialFailure
	}
	return Error
}
