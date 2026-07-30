// Package httptestutil provides small HTTP helpers for unit tests (mock transports, JSON/text responses).
package httptestutil

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// RoundTripFunc implements http.RoundTripper for tests.
type RoundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// JSON builds a JSON response body by marshaling v.
func JSON(status int, v any) *http.Response {
	body, err := json.Marshal(v)
	if err != nil {
		body = []byte("{}")
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// JSONString uses raw JSON in body (already valid JSON text).
func JSONString(status int, jsonBody string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(jsonBody)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// Text builds a plain-text response.
func Text(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
	}
}
