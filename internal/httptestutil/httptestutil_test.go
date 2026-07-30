package httptestutil

import (
	"net/http"
	"testing"
)

func TestRoundTripFunc(t *testing.T) {
	var rt RoundTripFunc = func(req *http.Request) (*http.Response, error) {
		return Text(http.StatusTeapot, "x"), nil
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestJSON(t *testing.T) {
	r := JSON(http.StatusOK, map[string]any{"ok": true})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatal(r.StatusCode)
	}
}

func TestJSONString(t *testing.T) {
	r := JSONString(http.StatusCreated, `{"id":"abc"}`)
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", r.StatusCode)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	body := make([]byte, 128)
	n, _ := r.Body.Read(body)
	if string(body[:n]) != `{"id":"abc"}` {
		t.Fatalf("unexpected body: %q", string(body[:n]))
	}
}

func TestText(t *testing.T) {
	r := Text(http.StatusNotFound, "not found")
	defer r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", r.StatusCode)
	}
	if ct := r.Header.Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("expected text/plain, got %q", ct)
	}
}

func TestJSONNon200Status(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"400 bad request", http.StatusBadRequest},
		{"500 internal error", http.StatusInternalServerError},
		{"201 created", http.StatusCreated},
		{"204 no content", http.StatusNoContent},
		{"403 forbidden", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := JSON(tc.status, map[string]string{"error": "test"})
			defer r.Body.Close()
			if r.StatusCode != tc.status {
				t.Fatalf("expected %d, got %d", tc.status, r.StatusCode)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("expected application/json, got %q", ct)
			}
		})
	}
}

func TestJSONMarshalError(t *testing.T) {
	r := JSON(http.StatusOK, make(chan int))
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", r.StatusCode)
	}
	body := make([]byte, 128)
	n, _ := r.Body.Read(body)
	if string(body[:n]) != "{}" {
		t.Fatalf("expected fallback '{}' for unmarshalable input, got %q", string(body[:n]))
	}
}
