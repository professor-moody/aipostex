package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/professor-moody/aipostex/pkg/exploit/common"
)

// A definitive "not this service type" response (404/405/501) to a type-specific probe is
// soft (reachable, wrong identity) — but a real signal (auth, 5xx from the correct service,
// transport failure) must still count as a hard failure.
func TestIsNotApplicableEnumError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"404 not found", &common.HTTPError{StatusCode: 404}, true},
		{"405 method not allowed", &common.HTTPError{StatusCode: 405}, true},
		{"501 not implemented", &common.HTTPError{StatusCode: 501}, true},
		{"wrapped 404 (as enumerators return it)", fmt.Errorf("listing models: %w", &common.HTTPError{StatusCode: 404}), true},
		{"401 auth is a real signal, not N/A", &common.HTTPError{StatusCode: 401}, false},
		{"403 forbidden is a real signal", &common.HTTPError{StatusCode: 403}, false},
		{"500 from the correct service is a real failure", &common.HTTPError{StatusCode: 500}, false},
		{"transport error is not N/A", errors.New("dial tcp: connection refused"), false},
		{"nil is not N/A", nil, false},
	}
	for _, c := range cases {
		if got := isNotApplicableEnumError(c.err); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
