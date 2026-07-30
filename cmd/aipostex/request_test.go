package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestIsFullRequestURL(t *testing.T) {
	cases := map[string]bool{
		"http://x/y":    true,
		"https://x":     true,
		"HTTP://X":      true,
		"/api/jobs/":    false,
		"api/jobs":      false,
		"":              false,
		"ftp://x":       false,
		"  https://a  ": true,
	}
	for in, want := range cases {
		if got := isFullRequestURL(in); got != want {
			t.Errorf("isFullRequestURL(%q)=%v, want %v", in, got, want)
		}
	}
}

func TestBuildRequestURL(t *testing.T) {
	tests := []struct {
		name, target, path, want string
		wantErr                  bool
	}{
		{name: "full url passthrough ignores target", target: "http://ignored", path: "https://real/api", want: "https://real/api"},
		{name: "join adds leading slash", target: "http://h:5000", path: "api/x", want: "http://h:5000/api/x"},
		{name: "join keeps leading slash", target: "http://h:5000", path: "/api/x", want: "http://h:5000/api/x"},
		{name: "normalizes bare host target", target: "h:5000", path: "/v1/models", want: "http://h:5000/v1/models"},
		{name: "trims trailing slash on target", target: "http://h:5000/", path: "/a", want: "http://h:5000/a"},
		{name: "empty path is base", target: "http://h:5000", path: "", want: "http://h:5000"},
		{name: "missing target and relative path errors", target: "", path: "/a", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildRequestURL(tc.target, tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("buildRequestURL(%q,%q)=%q, want %q", tc.target, tc.path, got, tc.want)
			}
		})
	}
}

func TestClassifyConsoleRequest(t *testing.T) {
	// A safe method (GET) on 2xx is an honest read; a state-changing method (POST/DELETE) on 2xx
	// is an accepted mutation (impact/influenced), never a read; non-2xx is only reachability.
	stage, landed, sev := classifyConsoleRequest("GET", 200)
	if stage != "access" || landed != "read-confirmed" || sev != report.SeverityInfo {
		t.Errorf("GET 200 => %q/%q/%q, want access/read-confirmed/Info", stage, landed, sev)
	}
	stage, landed, sev = classifyConsoleRequest("HEAD", 204)
	if stage != "access" || landed != "read-confirmed" || sev != report.SeverityInfo {
		t.Errorf("HEAD 204 => %q/%q/%q, want access/read-confirmed/Info", stage, landed, sev)
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		stage, landed, sev = classifyConsoleRequest(m, 200)
		if stage != "impact" || landed != "influenced" || sev != report.SeverityHigh {
			t.Errorf("%s 200 => %q/%q/%q, want impact/influenced/High", m, stage, landed, sev)
		}
		if !requestMethodMutates(m) {
			t.Errorf("%s should be classified as mutating", m)
		}
	}
	if requestMethodMutates("GET") {
		t.Error("GET must not be classified as mutating")
	}
	for _, code := range []int{301, 401, 403, 404, 500} {
		stage, landed, _ = classifyConsoleRequest("GET", code)
		if stage != "recon" || landed != "reachable" {
			t.Errorf("GET %d => %q/%q, want recon/reachable", code, stage, landed)
		}
	}
}

func TestResolveRequestBody(t *testing.T) {
	defer func() { requestBody, requestBodyFile, requestContentType = "", "", "" }()

	// literal
	requestBody, requestBodyFile, requestContentType = `{"a":1}`, "", "application/xml"
	body, ct, err := resolveRequestBody()
	if err != nil || string(body) != `{"a":1}` || ct != "application/xml" {
		t.Fatalf("literal: body=%q ct=%q err=%v", body, ct, err)
	}

	// file wins over literal
	dir := t.TempDir()
	fp := filepath.Join(dir, "body.json")
	if err := os.WriteFile(fp, []byte(`{"from":"file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	requestBody, requestBodyFile, requestContentType = "ignored", fp, ""
	body, ct, err = resolveRequestBody()
	if err != nil || string(body) != `{"from":"file"}` || ct != "" {
		t.Fatalf("file: body=%q ct=%q err=%v", body, ct, err)
	}

	// missing file errors
	requestBody, requestBodyFile, requestContentType = "", filepath.Join(dir, "nope.json"), ""
	if _, _, err := resolveRequestBody(); err == nil {
		t.Fatal("expected error for missing body file")
	}

	// no body
	requestBody, requestBodyFile, requestContentType = "", "", ""
	body, _, err = resolveRequestBody()
	if err != nil || len(body) != 0 {
		t.Fatalf("empty: body=%q err=%v", body, err)
	}
}

func TestBearerHeaderResolver(t *testing.T) {
	// key present, no explicit Authorization -> Bearer added
	resolve := bearerHeaderResolver(func() []string { return nil }, func() string { return "sk-abc" })
	h, err := resolve()
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Get("Authorization"); got != "Bearer sk-abc" {
		t.Errorf("Authorization=%q, want Bearer sk-abc", got)
	}

	// explicit Authorization header is not overridden by the key
	resolve = bearerHeaderResolver(func() []string { return []string{"Authorization: Basic xyz"} }, func() string { return "sk-abc" })
	h, err = resolve()
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Get("Authorization"); got != "Basic xyz" {
		t.Errorf("Authorization=%q, want Basic xyz (explicit header wins)", got)
	}

	// no key -> no Authorization (unauthenticated)
	resolve = bearerHeaderResolver(func() []string { return nil }, func() string { return "" })
	h, err = resolve()
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Get("Authorization"); got != "" {
		t.Errorf("Authorization=%q, want empty for unauthenticated", got)
	}
}

func TestModuleRequestVerbsRegistered(t *testing.T) {
	// Every HTTP demo module exposes a `request` verb after registration.
	want := map[string]bool{
		"mlflow": true, "ray": true, "ollama": true, "openai-compat": true,
		"litellm": true, "vectordb": true, "huggingface": true,
	}
	modules := map[string]bool{}
	for name := range want {
		modules[name] = false
	}
	for _, c := range rootCmd.Commands() {
		if !want[c.Name()] {
			continue
		}
		for _, sub := range c.Commands() {
			if sub.Name() == "request" {
				modules[c.Name()] = true
			}
		}
	}
	for name := range want {
		if !modules[name] {
			t.Errorf("module %q is missing its `request` verb", name)
		}
	}
	// and the top-level primitive exists
	found := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "request" {
			found = true
		}
	}
	if !found {
		t.Error("top-level `request` command is not registered")
	}
}
