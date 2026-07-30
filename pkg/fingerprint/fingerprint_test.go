package fingerprint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"time"

	"github.com/professor-moody/aipostex/pkg/stringutil"
)

func TestExpandCIDRReturnsUsableHosts(t *testing.T) {
	hosts, err := ExpandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("ExpandCIDR returned error: %v", err)
	}

	expected := []string{"192.168.1.1", "192.168.1.2"}
	if len(hosts) != len(expected) {
		t.Fatalf("expected %d hosts, got %d", len(expected), len(hosts))
	}
	for i := range expected {
		if hosts[i] != expected[i] {
			t.Fatalf("expected host %q at index %d, got %q", expected[i], i, hosts[i])
		}
	}
}

func TestBuiltinProbesIncludeCoreServices(t *testing.T) {
	probes := BuiltinProbes()
	required := map[string]bool{
		"ollama":            false,
		"chromadb":          false,
		"mcp-sse":           false,
		"mcp-inspector":     false,
		"openai-compatible": false,
	}

	for _, probe := range probes {
		if _, ok := required[probe.Name]; ok {
			required[probe.Name] = true
		}
	}

	for name, found := range required {
		if !found {
			t.Fatalf("expected builtin probe %q to exist", name)
		}
	}
}

func TestNewScannerUsesConfigurableDialTimeoutPath(t *testing.T) {
	scanner := NewScanner(time.Second, 1)
	if scanner.DialContext != nil {
		t.Fatal("expected default scanner to use DialTimeout-driven dialer path")
	}
	if scanner.DialTimeout != time.Second {
		t.Fatalf("expected default dial timeout 1s, got %s", scanner.DialTimeout)
	}
}

func TestTopTCPPortsHasNoDuplicates(t *testing.T) {
	seen := make(map[int]struct{})
	for _, port := range TopTCPPorts() {
		if _, ok := seen[port]; ok {
			t.Fatalf("found duplicate top TCP port %d", port)
		}
		seen[port] = struct{}{}
	}
}

func TestTopTCPPortsAllInValidRange(t *testing.T) {
	for _, port := range TopTCPPorts() {
		if port < 1 || port > 65535 {
			t.Fatalf("top TCP port %d out of range", port)
		}
	}
}

func TestBuiltinInspectorProbesIncludeAPIPaths(t *testing.T) {
	probes := BuiltinProbes()
	for _, probe := range probes {
		if probe.Name != "mcp-inspector" {
			continue
		}
		foundServers := false
		foundTools := false
		for _, httpProbe := range probe.Probes {
			if httpProbe.Path == "/api/servers" {
				foundServers = true
			}
			if httpProbe.Path == "/api/tools" {
				foundTools = true
			}
		}
		if !foundServers || !foundTools {
			t.Fatalf("expected inspector probes to include API paths, got %#v", probe.Probes)
		}
		return
	}
	t.Fatal("expected mcp-inspector probe to exist")
}

func TestBuiltinMCPProbeIncludesStreamableHTTP(t *testing.T) {
	probes := BuiltinProbes()
	for _, probe := range probes {
		if probe.Name != "mcp-sse" {
			continue
		}
		foundMCP := false
		for _, httpProbe := range probe.Probes {
			if httpProbe.Path == "/mcp" && httpProbe.Method == "POST" {
				foundMCP = true
				// The official SDK rejects initialize without the event-stream Accept.
				if accept := httpProbe.Headers["Accept"]; accept == "" || !strings.Contains(accept, "text/event-stream") {
					t.Fatalf("/mcp probe must send a text/event-stream Accept header, got %q", accept)
				}
			}
		}
		if !foundMCP {
			t.Fatalf("expected an mcp-sse probe against the modern /mcp endpoint, got %#v", probe.Probes)
		}
		return
	}
	t.Fatal("expected mcp-sse probe to exist")
}

func TestBoundedPreviewNormalizesNewlines(t *testing.T) {
	value := stringutil.BoundedPreview("line1\nline2\r\nline3", 100)
	if value != "line1 line2 line3" {
		t.Fatalf("unexpected preview value: %q", value)
	}
}

func TestExpandCIDRIsStableAcrossCalls(t *testing.T) {
	first, err := ExpandCIDR("10.0.0.0/30")
	if err != nil {
		t.Fatalf("ExpandCIDR first call returned error: %v", err)
	}
	second, err := ExpandCIDR("10.0.0.0/30")
	if err != nil {
		t.Fatalf("ExpandCIDR second call returned error: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("expected equal host counts, got %d and %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("expected stable CIDR expansion, got %q and %q at index %d", first[i], second[i], i)
		}
	}
}

func TestScannerFallsBackToHTTPS(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "ollama",
			DefaultPort: 443,
			Probes: []HTTPProbe{
				{Path: "/api/tags", MatchStatus: 200, MatchBody: "models", Specificity: 90},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Scheme == "http" {
				return nil, errors.New("tls: first record does not look like a TLS handshake")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"models":[]}`)),
			}, nil
		}),
	}

	observation := scanner.ScanHost("127.0.0.1", 443)
	if len(observation.Results) == 0 || !strings.HasPrefix(observation.Results[0].URL, "https://") {
		t.Fatalf("expected HTTPS fallback result, got %#v", observation)
	}
}

func TestEstimateCIDRSizeRejectsLargeIPv6(t *testing.T) {
	for _, cidr := range []string{"::/64", "::/0", "fe80::/48", "2001:db8::/32"} {
		n, err := EstimateCIDRSize(cidr)
		if err == nil {
			t.Fatalf("EstimateCIDRSize(%q) should return error for large IPv6, got %d", cidr, n)
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("expected 'too large' error for %q, got: %v", cidr, err)
		}
	}
}

func TestEstimateCIDRSizeAcceptsSmallIPv6(t *testing.T) {
	n, err := EstimateCIDRSize("fe80::/126")
	if err != nil {
		t.Fatalf("EstimateCIDRSize(fe80::/126) returned error: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 usable hosts for /126, got %d", n)
	}
}

func TestRequestPlanKey(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		body    string
	}{
		{"simple GET", "GET", "/api/tags", nil, ""},
		{"POST with body", "POST", "/v2/vectordb/collections/list", map[string]string{"Content-Type": "application/json"}, "{}"},
		{"method normalization", "get", "/path", nil, ""},
		{"multiple headers sorted", "GET", "/path", map[string]string{"X-Beta": "b", "X-Alpha": "a"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := requestPlanKey(tc.method, tc.path, tc.headers, tc.body)
			if key == "" {
				t.Fatal("expected non-empty key")
			}
			key2 := requestPlanKey(tc.method, tc.path, tc.headers, tc.body)
			if key != key2 {
				t.Fatal("expected deterministic key")
			}
		})
	}

	k1 := requestPlanKey("GET", "/a", nil, "")
	k2 := requestPlanKey("POST", "/a", nil, "")
	if k1 == k2 {
		t.Fatal("different methods should produce different keys")
	}

	k3 := requestPlanKey("GET", "/a", map[string]string{"X-A": "1", "X-B": "2"}, "")
	k4 := requestPlanKey("GET", "/a", map[string]string{"X-B": "2", "X-A": "1"}, "")
	if k3 != k4 {
		t.Fatal("header order should not affect key")
	}
}

func TestClassifyMatchScenarios(t *testing.T) {
	tests := []struct {
		name      string
		match     *serviceMatch
		port      int
		wantKind  string
		wantConf  string
		wantAmbig string
	}{
		{"strong hit", &serviceMatch{strongHits: 1, defaultPort: 8080}, 8080, MatchKindConfirmed, "high", ""},
		{"two supporting default port", &serviceMatch{supportHits: 2, defaultPort: 8080}, 8080, MatchKindConfirmed, "high", ""},
		{"two supporting non-default", &serviceMatch{supportHits: 2, defaultPort: 9090}, 8080, MatchKindConfirmed, "medium", ""},
		{"one supporting default port", &serviceMatch{supportHits: 1, defaultPort: 8080}, 8080, MatchKindSuspected, "medium", "supporting_match_only"},
		{"one supporting non-default", &serviceMatch{supportHits: 1, defaultPort: 9090}, 8080, MatchKindSuspected, "medium", "non_default_port_without_strong_corroboration"},
		{"generic default port", &serviceMatch{genericHits: 1, defaultPort: 8080}, 8080, MatchKindSuspected, "low", "generic_match_only"},
		{"generic non-default", &serviceMatch{genericHits: 1, defaultPort: 9090}, 8080, MatchKindSuspected, "low", "generic_match_on_non_default_port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &Result{}
			classifyMatch(result, tc.match, tc.port)
			if result.MatchKind != tc.wantKind {
				t.Errorf("MatchKind = %q, want %q", result.MatchKind, tc.wantKind)
			}
			if result.Confidence != tc.wantConf {
				t.Errorf("Confidence = %q, want %q", result.Confidence, tc.wantConf)
			}
			if tc.wantAmbig != "" && result.Ambiguity != tc.wantAmbig {
				t.Errorf("Ambiguity = %q, want %q", result.Ambiguity, tc.wantAmbig)
			}
		})
	}
}

func TestClassifyMatchNilInputs(t *testing.T) {
	classifyMatch(nil, &serviceMatch{strongHits: 1}, 8080)
	classifyMatch(&Result{}, nil, 8080)
}

func TestBuildObservationEdgeCases(t *testing.T) {
	obs := buildObservation("host", 8080, "", nil, nil, "", "", false)
	if obs.FingerprintStatus != "unidentified" {
		t.Fatalf("expected unidentified for empty services, got %q", obs.FingerprintStatus)
	}
	if obs.URL != "http://host:8080" {
		t.Fatalf("expected default URL, got %q", obs.URL)
	}

	obsTimeout := buildObservation("host", 8080, "http://host:8080", nil, nil, "", "", true)
	if !obsTimeout.TimedOut || !obsTimeout.Incomplete {
		t.Fatal("expected TimedOut and Incomplete flags set")
	}
}

func TestBuildObservationBannerFallback(t *testing.T) {
	obs := buildObservation("host", 9090, "http://host:9090", nil, nil, "nginx/1.18", "welcome", false)
	if len(obs.Results) != 1 {
		t.Fatalf("expected banner fallback result, got %d results", len(obs.Results))
	}
	if obs.Results[0].MatchKind != MatchKindBanner {
		t.Fatalf("expected banner match kind, got %q", obs.Results[0].MatchKind)
	}
	if obs.FingerprintStatus != MatchKindBanner {
		t.Fatalf("expected banner fingerprint status, got %q", obs.FingerprintStatus)
	}
}

func TestBuildObservationCandidateServices(t *testing.T) {
	obs := buildObservation("host", 8080, "http://host:8080", map[string]*serviceMatch{
		"above": {specificity: 50, strongHits: 1, defaultPort: 8080, probes: []string{"/"}},
		"below": {specificity: 10, defaultPort: 8080, probes: []string{"/low"}},
	}, []string{"/"}, "", "", false)
	if len(obs.Results) != 1 || obs.Results[0].Service != "above" {
		t.Fatalf("expected only above-threshold result, got %#v", obs.Results)
	}
	if len(obs.CandidateServices) != 1 || obs.CandidateServices[0] != "below" {
		t.Fatalf("expected 'below' as candidate, got %v", obs.CandidateServices)
	}
	if obs.FingerprintStatus != MatchKindConfirmed {
		t.Fatalf("expected confirmed status, got %q", obs.FingerprintStatus)
	}
}

func TestObservationFingerprintStatusEdgeCases(t *testing.T) {
	if s := observationFingerprintStatus(nil, nil); s != "unidentified" {
		t.Fatalf("expected unidentified, got %q", s)
	}
	if s := observationFingerprintStatus(nil, []string{"svc"}); s != "candidate" {
		t.Fatalf("expected candidate, got %q", s)
	}
	if s := observationFingerprintStatus([]Result{{MatchKind: MatchKindSuspected}}, nil); s != MatchKindSuspected {
		t.Fatalf("expected suspected, got %q", s)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestCIDRGuardConsistency(t *testing.T) {
	// /11 has 21 host bits (> maxCIDRHostBits=20), rejected by both
	_, err := EstimateCIDRSize("10.0.0.0/11")
	if err == nil {
		t.Fatal("EstimateCIDRSize should reject /11")
	}
	_, err = ExpandCIDR("10.0.0.0/11")
	if err == nil {
		t.Fatal("ExpandCIDR should reject /11")
	}

	// /20 has 12 host bits, accepted by both
	n, err := EstimateCIDRSize("10.0.0.0/20")
	if err != nil {
		t.Fatalf("EstimateCIDRSize rejected /20: %v", err)
	}
	hosts, err := ExpandCIDR("10.0.0.0/20")
	if err != nil {
		t.Fatalf("ExpandCIDR rejected /20: %v", err)
	}
	if n != len(hosts) {
		t.Fatalf("EstimateCIDRSize=%d but ExpandCIDR returned %d hosts", n, len(hosts))
	}

	// /30 has 2 host bits, accepted by both
	n30, err := EstimateCIDRSize("10.0.0.0/30")
	if err != nil {
		t.Fatalf("EstimateCIDRSize rejected /30: %v", err)
	}
	hosts30, err := ExpandCIDR("10.0.0.0/30")
	if err != nil {
		t.Fatalf("ExpandCIDR rejected /30: %v", err)
	}
	if n30 != len(hosts30) {
		t.Fatalf("EstimateCIDRSize=%d but ExpandCIDR returned %d hosts for /30", n30, len(hosts30))
	}
}

func TestScanRangeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = ctx
	scanner.Probes = []ServiceProbe{
		{
			Name:        "test-svc",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{Path: "/", MatchStatus: 200, MatchBody: "hello", Specificity: 90},
			},
		},
	}

	done := make(chan struct{})
	var results []PortObservation
	go func() {
		results = scanner.ScanRange([]string{"192.168.1.1", "192.168.1.2"}, []int{8080, 9090})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ScanRange did not return promptly on cancelled context")
	}

	if len(results) != 0 {
		t.Fatalf("expected no results on cancelled context, got %d", len(results))
	}
}

func TestMultiServicePerPort(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "service-alpha",
			DefaultPort: 9090,
			Probes: []HTTPProbe{
				{Path: "/alpha", MatchStatus: 200, MatchBody: "alpha-match", Specificity: 80},
			},
		},
		{
			Name:        "service-beta",
			DefaultPort: 9090,
			Probes: []HTTPProbe{
				{Path: "/beta", MatchStatus: 200, MatchBody: "beta-match", Specificity: 70},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("alpha-match beta-match")),
			}, nil
		}),
	}

	observation := scanner.ScanHost("127.0.0.1", 9090)
	results := observation.Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d: %#v", len(results), observation)
	}
	found := map[string]bool{}
	for _, r := range results {
		found[r.Service] = true
	}
	if !found["service-alpha"] || !found["service-beta"] {
		t.Fatalf("expected both services, got %v", found)
	}
}

func TestNegativeMatching(t *testing.T) {
	probe := HTTPProbe{
		MatchStatus:  200,
		MatchBody:    "welcome",
		MatchBodyNot: "forbidden",
		Specificity:  80,
	}

	if matchProbe(probe, 200, "welcome forbidden zone", http.Header{}) {
		t.Fatal("probe should not match when body contains MatchBodyNot string")
	}

	if !matchProbe(probe, 200, "welcome to the site", http.Header{}) {
		t.Fatal("probe should match when body does not contain MatchBodyNot string")
	}
}

// Ray's dashboard /api/version returns a bare "version" key too, so the ollama probe must
// exclude it via MatchBodyNot:"ray_version" — without suppressing a real Ollama (which never
// returns "ray_version"). Mirrors the ollama /api/version probe in fingerprint.go.
func TestOllamaVersionProbeExcludesRayDashboard(t *testing.T) {
	probe := HTTPProbe{MatchStatus: 200, MatchBody: `"version"`, MatchBodyNot: "ray_version"}
	rayBody := `{"version": "4", "ray_version": "2.54.1", "ray_commit": "abc", "session_name": "s"}`
	ollamaBody := `{"version":"0.1.32"}`
	if matchProbe(probe, 200, rayBody, http.Header{}) {
		t.Error("ollama /api/version probe must NOT match the Ray dashboard (it carries ray_version)")
	}
	if !matchProbe(probe, 200, ollamaBody, http.Header{}) {
		t.Error("ollama /api/version probe must still match a real Ollama version response")
	}
}

func TestHeaderMatching(t *testing.T) {
	probe := HTTPProbe{
		MatchStatus: 200,
		MatchHeader: map[string]string{"X-Engine": "ai-service"},
		Specificity: 80,
	}

	matchHeaders := http.Header{}
	matchHeaders.Set("X-Engine", "ai-service")
	if !matchProbe(probe, 200, "", matchHeaders) {
		t.Fatal("probe should match when response header matches")
	}

	noMatchHeaders := http.Header{}
	noMatchHeaders.Set("X-Engine", "other-service")
	if matchProbe(probe, 200, "", noMatchHeaders) {
		t.Fatal("probe should not match when response header differs")
	}
}

func TestProxyDetection(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{Name: "svc-a", DefaultPort: 7000, Probes: []HTTPProbe{
			{Path: "/a", MatchStatus: 200, MatchBody: "ok", Specificity: 60},
		}},
		{Name: "svc-b", DefaultPort: 7000, Probes: []HTTPProbe{
			{Path: "/b", MatchStatus: 200, MatchBody: "ok", Specificity: 60},
		}},
		{Name: "svc-c", DefaultPort: 7000, Probes: []HTTPProbe{
			{Path: "/c", MatchStatus: 200, MatchBody: "ok", Specificity: 60},
		}},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}

	observation := scanner.ScanHost("127.0.0.1", 7000)
	results := observation.Results
	if len(results) < 3 {
		t.Fatalf("expected at least 3 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.ProxyLikely {
			t.Fatalf("expected ProxyLikely=true for %q, got false", r.Service)
		}
	}
}

func TestChromaDBProbeRequiresHeartbeatBody(t *testing.T) {
	probes := BuiltinProbes()
	var chromaProbes []HTTPProbe
	for _, sp := range probes {
		if sp.Name == "chromadb" {
			chromaProbes = sp.Probes
			break
		}
	}
	if len(chromaProbes) == 0 {
		t.Fatal("expected chromadb probes")
	}
	for _, p := range chromaProbes {
		if p.MatchBody == "" {
			t.Fatalf("chromadb probe %s has no MatchBody — will false-positive on any 200 response", p.Path)
		}
	}

	h := make(http.Header)
	if matchProbe(chromaProbes[0], 200, `{"status":"ok"}`, h) {
		t.Fatal("chromadb probe should not match a generic 200 response")
	}
	if !matchProbe(chromaProbes[0], 200, `{"nanosecond heartbeat":1234567890}`, h) {
		t.Fatal("chromadb probe should match real heartbeat response")
	}
}

func TestServerHeaderCaptured(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "test-svc",
			DefaultPort: 9090,
			Probes: []HTTPProbe{
				{Path: "/test", MatchStatus: 200, MatchBody: "found", Specificity: 80},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			h := make(http.Header)
			h.Set("Server", "uvicorn")
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     h,
				Body:       io.NopCloser(strings.NewReader("found it")),
			}, nil
		}),
	}

	observation := scanner.ScanHost("127.0.0.1", 9090)
	results := observation.Results
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ServerHeader != "uvicorn" {
		t.Fatalf("expected ServerHeader='uvicorn', got %q", results[0].ServerHeader)
	}
}

func TestScanProgressCallback(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "test-svc",
			DefaultPort: 9090,
			Probes: []HTTPProbe{
				{Path: "/", MatchStatus: 200, MatchBody: "ok", Specificity: 80},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}

	var events []ScanProgressEvent
	scanner.OnProgress = func(ev ScanProgressEvent) {
		events = append(events, ev)
	}

	results := scanner.ScanRange([]string{"127.0.0.1"}, []int{9090})
	if len(results) == 0 {
		t.Fatal("expected results")
	}

	foundTypes := make(map[string]bool)
	for _, ev := range events {
		foundTypes[ev.Type] = true
	}
	for _, eventType := range []string{"tcp_open", "fingerprinting", "matched", "done"} {
		if !foundTypes[eventType] {
			t.Fatalf("expected %s event, got types: %v", eventType, foundTypes)
		}
	}
}

func TestClosedPortEmitsNoProgressEvents(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	var events []ScanProgressEvent
	scanner.OnProgress = func(ev ScanProgressEvent) {
		events = append(events, ev)
	}

	results := scanner.ScanRange([]string{"127.0.0.1"}, []int{9090})
	if len(results) != 0 {
		t.Fatalf("expected no results for closed port, got %#v", results)
	}
	for _, ev := range events {
		if ev.Type == "tcp_open" || ev.Type == "fingerprinting" || ev.Type == "matched" || ev.Type == "timed_out" {
			t.Fatalf("expected no open/fingerprint events for closed port, got %#v", events)
		}
	}
}

func TestOpenPortWithoutFingerprintStillReturnsObservation(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "test-svc",
			DefaultPort: 9090,
			Probes: []HTTPProbe{
				{Path: "/health", MatchStatus: 200, MatchBody: "ok", Specificity: 80},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("not found")),
			}, nil
		}),
	}

	observation := scanner.ScanHost("127.0.0.1", 9090)
	if observation.Port != 9090 || observation.PortState != "open" {
		t.Fatalf("expected open port observation, got %#v", observation)
	}
	if observation.FingerprintStatus != "unidentified" {
		t.Fatalf("expected unidentified status, got %#v", observation)
	}
	if len(observation.Results) != 0 {
		t.Fatalf("expected no surviving identities, got %#v", observation.Results)
	}
}

func TestFingerprintTimeoutEmitsTimedOutAndPreservesMatches(t *testing.T) {
	scanner := NewScannerWithClient(nil, 25*time.Millisecond, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "test-svc",
			DefaultPort: 9090,
			Probes: []HTTPProbe{
				{Path: "/fast", MatchStatus: 200, MatchBody: "ok", Specificity: 80},
				{Path: "/slow", MatchStatus: 200, MatchBody: "slow", Specificity: 70},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/fast":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("ok")),
				}, nil
			case "/slow":
				<-req.Context().Done()
				return nil, req.Context().Err()
			default:
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("not found")),
				}, nil
			}
		}),
		Timeout: 25 * time.Millisecond,
	}

	var events []ScanProgressEvent
	scanner.OnProgress = func(ev ScanProgressEvent) {
		events = append(events, ev)
	}

	results := scanner.ScanRange([]string{"127.0.0.1"}, []int{9090})
	if len(results) != 1 || len(results[0].Results) != 1 || results[0].Results[0].Service != "test-svc" {
		t.Fatalf("expected preserved match before timeout, got %#v", results)
	}

	foundMatch := false
	foundTimeout := false
	for _, ev := range events {
		if ev.Type == "matched" && ev.Service == "test-svc" {
			foundMatch = true
		}
		if ev.Type == "timed_out" {
			foundTimeout = true
			if ev.Budget != 25*time.Millisecond {
				t.Fatalf("expected timeout budget 25ms, got %s", ev.Budget)
			}
		}
	}
	if !foundMatch || !foundTimeout {
		t.Fatalf("expected matched and timed_out events, got %#v", events)
	}
}

func TestScanHostDeduplicatesSharedProbeRequests(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "svc-a",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{Path: "/shared", MatchStatus: 200, MatchBody: "hello", Specificity: 80},
			},
		},
		{
			Name:        "svc-b",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{Path: "/shared", MatchStatus: 200, MatchBody: "hello", Specificity: 70},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}

	requests := 0
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("hello")),
			}, nil
		}),
	}

	observation := scanner.ScanHost("127.0.0.1", 8080)
	if requests != 1 {
		t.Fatalf("expected shared probe to be requested once, got %d", requests)
	}
	if len(observation.Results) != 2 {
		t.Fatalf("expected both services from one shared request, got %#v", observation)
	}
}

func TestScanHostSkipsHTTPProbesForClearNonHTTPPorts(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}

	requests := 0
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("unexpected")),
			}, nil
		}),
	}

	observation := scanner.ScanHost("10.0.0.5", 5432)
	if requests != 0 {
		t.Fatalf("expected no HTTP probes against PostgreSQL port, got %d", requests)
	}
	if len(observation.Results) != 1 || observation.Results[0].Service != "postgresql" {
		t.Fatalf("expected PostgreSQL port heuristic observation, got %#v", observation)
	}
	if observation.FingerprintStatus != MatchKindPortHeuristic {
		t.Fatalf("expected port heuristic status, got %q", observation.FingerprintStatus)
	}
}

func TestMlflowProbeRequiresBodyMatch(t *testing.T) {
	probes := BuiltinProbes()
	var mlflowProbes []HTTPProbe
	for _, sp := range probes {
		if sp.Name == "mlflow" {
			mlflowProbes = sp.Probes
			break
		}
	}
	if len(mlflowProbes) == 0 {
		t.Fatal("expected mlflow probes")
	}
	for _, p := range mlflowProbes {
		if p.MatchBody == "" {
			t.Fatalf("mlflow probe %s has no MatchBody — will false-positive on any 200 response", p.Path)
		}
	}

	h := make(http.Header)
	registeredModelsProbe := mlflowProbes[1]
	if matchProbe(registeredModelsProbe, 200, `{"status":"ok"}`, h) {
		t.Fatal("mlflow registered-models probe should not match a generic 200 response")
	}
	if !matchProbe(registeredModelsProbe, 200, `{"registered_models":[]}`, h) {
		t.Fatal("mlflow registered-models probe should match response containing registered_models")
	}
}

func TestJupyterProbeRequiresSpecificBody(t *testing.T) {
	probes := BuiltinProbes()
	var jupyterProbes []HTTPProbe
	for _, sp := range probes {
		if sp.Name == "jupyter" {
			jupyterProbes = sp.Probes
			break
		}
	}
	if len(jupyterProbes) == 0 {
		t.Fatal("expected jupyter probes")
	}

	h := make(http.Header)
	apiProbe := jupyterProbes[0]
	if matchProbe(apiProbe, 200, `{"version":"1.0"}`, h) {
		t.Fatal("jupyter /api probe should not match a generic version response")
	}
	if !matchProbe(apiProbe, 200, `{"jupyter_server":{"version":"2.0"}}`, h) {
		t.Fatal("jupyter /api probe should match response containing jupyter_server")
	}
}

func TestQdrantProbeRequiresResultField(t *testing.T) {
	probes := BuiltinProbes()
	var qdrantProbes []HTTPProbe
	for _, sp := range probes {
		if sp.Name == "qdrant" {
			qdrantProbes = sp.Probes
			break
		}
	}
	if len(qdrantProbes) == 0 {
		t.Fatal("expected qdrant probes")
	}

	collectionsProbe := qdrantProbes[0]
	hPlain := make(http.Header)
	if matchProbe(collectionsProbe, 200, `{"collections":[]}`, hPlain) {
		t.Fatal("qdrant /collections probe should not match without JSON content-type header")
	}

	hJSON := make(http.Header)
	hJSON.Set("Content-Type", "application/json")
	if matchProbe(collectionsProbe, 200, `{"items":[]}`, hJSON) {
		t.Fatal("qdrant /collections probe should not match without result field in body")
	}
	if !matchProbe(collectionsProbe, 200, `{"result":{"collections":[]}}`, hJSON) {
		t.Fatal("qdrant /collections probe should match response with result field and JSON header")
	}
}

func TestVersionExtraction(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "versioned-svc",
			DefaultPort: 5000,
			Probes: []HTTPProbe{
				{
					Path:         "/version",
					MatchStatus:  200,
					MatchBody:    "version",
					VersionRegex: `"version"\s*:\s*"([^"]+)"`,
					Specificity:  80,
				},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"version": "3.14.159"}`)),
			}, nil
		}),
	}

	observation := scanner.ScanHost("127.0.0.1", 5000)
	results := observation.Results
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Version != "3.14.159" {
		t.Fatalf("expected version '3.14.159', got %q", results[0].Version)
	}
}

func TestPortAffinityOrdering(t *testing.T) {
	var probeOrder []string
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "generic-svc",
			DefaultPort: 9999,
			Probes: []HTTPProbe{
				{Path: "/generic", MatchStatus: 200, MatchBody: "ok", Specificity: 60},
			},
		},
		{
			Name:        "port-matched-svc",
			DefaultPort: 4000,
			Probes: []HTTPProbe{
				{Path: "/matched", MatchStatus: 200, MatchBody: "ok", Specificity: 90},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			probeOrder = append(probeOrder, req.URL.Path)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}

	observation := scanner.ScanHost("127.0.0.1", 4000)
	results := observation.Results
	if len(probeOrder) == 0 {
		t.Fatal("expected at least one probe to run")
	}
	if probeOrder[0] != "/matched" {
		t.Fatalf("expected port-matched probe to run first, got %q", probeOrder[0])
	}
	if len(results) != 1 || results[0].Service != "port-matched-svc" {
		t.Fatalf("expected only port-matched-svc (early termination skips non-port-matched probes), got %#v", results)
	}
	if len(probeOrder) != 1 {
		t.Fatalf("expected early termination to skip non-port-matched probe, got probes: %v", probeOrder)
	}
}

func TestShortCircuit100(t *testing.T) {
	scanner := NewScanner(2*time.Second, 1)
	scanner.Context = context.Background()
	scanner.Probes = []ServiceProbe{
		{
			Name:        "definite-svc",
			DefaultPort: 6000,
			Probes: []HTTPProbe{
				{Path: "/definite", MatchStatus: 200, MatchBody: "found", Specificity: 100},
			},
		},
		{
			Name:        "other-svc",
			DefaultPort: 7777,
			Probes: []HTTPProbe{
				{Path: "/other", MatchStatus: 200, MatchBody: "found", Specificity: 70},
			},
		},
	}
	scanner.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}
	scanner.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("found it")),
			}, nil
		}),
	}

	observation := scanner.ScanHost("127.0.0.1", 6000)
	results := observation.Results
	if len(results) != 1 {
		t.Fatalf("expected early termination to keep only port-matched strong hit, got %d: %#v", len(results), observation)
	}
	if results[0].Service != "definite-svc" {
		t.Fatalf("expected 'definite-svc', got %q", results[0].Service)
	}
}

func TestBuildResultsClassifiesStrongMatchAsConfirmed(t *testing.T) {
	results := buildResults("127.0.0.1", 11434, "http://127.0.0.1:11434", map[string]*serviceMatch{
		"ollama": {
			specificity: 90,
			defaultPort: 11434,
			probes:      []string{"/api/tags"},
			strongHits:  1,
		},
	})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].MatchKind != MatchKindConfirmed {
		t.Fatalf("expected confirmed match, got %#v", results[0])
	}
	if results[0].Confidence != "high" {
		t.Fatalf("expected high confidence, got %#v", results[0])
	}
}

func TestBuildResultsClassifiesGenericOnlyMatchAsSuspected(t *testing.T) {
	results := buildResults("127.0.0.1", 8000, "http://127.0.0.1:8000", map[string]*serviceMatch{
		"openai-compatible": {
			specificity: 35,
			defaultPort: 8000,
			probes:      []string{"/v1/models"},
			genericHits: 1,
		},
	})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].MatchKind != MatchKindSuspected {
		t.Fatalf("expected suspected match, got %#v", results[0])
	}
	if results[0].Ambiguity != "generic_match_only" {
		t.Fatalf("expected generic_match_only ambiguity, got %#v", results[0])
	}
}

func TestBuildResultsMarksWeakOverlapAsAmbiguous(t *testing.T) {
	results := buildResults("127.0.0.1", 8501, "http://127.0.0.1:8501", map[string]*serviceMatch{
		"hf-tgi": {
			specificity: 30,
			defaultPort: 3000,
			probes:      []string{"/health"},
			genericHits: 1,
		},
		"hf-tei": {
			specificity: 30,
			defaultPort: 8080,
			probes:      []string{"/health"},
			genericHits: 1,
		},
	})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, result := range results {
		if result.MatchKind != MatchKindAmbiguous {
			t.Fatalf("expected ambiguous match, got %#v", result)
		}
		if result.Ambiguity != "no_strong_winner" {
			t.Fatalf("expected no_strong_winner ambiguity, got %#v", result)
		}
	}
}

func TestBuildResultsMarksProxyLikelyWhenManyServicesOverlap(t *testing.T) {
	results := buildResults("127.0.0.1", 8000, "http://127.0.0.1:8000", map[string]*serviceMatch{
		"svc-a": {specificity: 40, defaultPort: 8000, probes: []string{"/a"}, genericHits: 1},
		"svc-b": {specificity: 40, defaultPort: 8000, probes: []string{"/b"}, genericHits: 1},
		"svc-c": {specificity: 40, defaultPort: 8000, probes: []string{"/c"}, genericHits: 1},
	})
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for _, result := range results {
		if !result.ProxyLikely {
			t.Fatalf("expected proxy likely result, got %#v", result)
		}
		if result.Ambiguity != "proxy_likely" {
			t.Fatalf("expected proxy_likely ambiguity, got %#v", result)
		}
	}
}

func TestBuildResultsAllowsConfirmedNonDefaultPortWithCorroboration(t *testing.T) {
	results := buildResults("127.0.0.1", 1234, "http://127.0.0.1:1234", map[string]*serviceMatch{
		"ollama": {
			specificity: 95,
			defaultPort: 11434,
			probes:      []string{"/api/tags", "/api/version"},
			supportHits: 2,
		},
	})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].MatchKind != MatchKindConfirmed {
		t.Fatalf("expected confirmed corroborated non-default match, got %#v", results[0])
	}
	if results[0].Confidence != "medium" {
		t.Fatalf("expected medium confidence on corroborated non-default match, got %#v", results[0])
	}
}

func TestRequestPriority(t *testing.T) {
	tests := []struct {
		name        string
		portMatched bool
		strength    ProbeStrength
		want        int
	}{
		{"strong port-matched", true, ProbeStrengthStrong, 0},
		{"supporting port-matched", true, ProbeStrengthSupporting, 1},
		{"strong non-port", false, ProbeStrengthStrong, 2},
		{"generic port-matched", true, ProbeStrengthGeneric, 3},
		{"supporting non-port", false, ProbeStrengthSupporting, 4},
		{"generic non-port", false, ProbeStrengthGeneric, 5},
		{"empty defaults to strong port-matched", true, "", 0},
		{"empty defaults to strong non-port", false, "", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := requestPriority(tc.portMatched, tc.strength)
			if got != tc.want {
				t.Errorf("requestPriority(%v, %q) = %d, want %d", tc.portMatched, tc.strength, got, tc.want)
			}
		})
	}
}

func TestRecordMatch(t *testing.T) {
	m := &serviceMatch{defaultPort: 8080}

	m.recordMatch(HTTPProbe{Strength: ProbeStrengthStrong}, 8080)
	if m.strongHits != 1 {
		t.Fatalf("expected 1 strong hit, got %d", m.strongHits)
	}

	m.recordMatch(HTTPProbe{Strength: ProbeStrengthSupporting}, 8080)
	if m.supportHits != 1 {
		t.Fatalf("expected 1 support hit, got %d", m.supportHits)
	}

	m.recordMatch(HTTPProbe{Strength: ProbeStrengthGeneric}, 8080)
	if m.genericHits != 1 {
		t.Fatalf("expected 1 generic hit, got %d", m.genericHits)
	}

	m.recordMatch(HTTPProbe{Strength: ""}, 9090)
	if m.strongHits != 2 {
		t.Fatalf("expected empty strength to count as strong, got %d", m.strongHits)
	}
	if m.defaultPort != 9090 {
		t.Fatalf("expected default port updated to 9090, got %d", m.defaultPort)
	}
}

func TestMatchKindRank(t *testing.T) {
	tests := []struct {
		kind string
		want int
	}{
		{MatchKindConfirmed, 0},
		{MatchKindSuspected, 1},
		{MatchKindAmbiguous, 2},
		{MatchKindBanner, 3},
		{"unknown", 3},
		{"", 3},
		{"  confirmed  ", 0},
	}
	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			got := matchKindRank(tc.kind)
			if got != tc.want {
				t.Errorf("matchKindRank(%q) = %d, want %d", tc.kind, got, tc.want)
			}
		})
	}
}

func TestEstimateCIDRSizeSingleHost(t *testing.T) {
	n, err := EstimateCIDRSize("10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 for single host, got %d", n)
	}
}

func TestEstimateCIDRSizeInvalidCIDR(t *testing.T) {
	_, err := EstimateCIDRSize("not-a-cidr/24")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestEstimateCIDRSize32(t *testing.T) {
	n, err := EstimateCIDRSize("10.0.0.1/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 for /32, got %d", n)
	}
}

func TestEstimateCIDRSize24(t *testing.T) {
	n, err := EstimateCIDRSize("10.0.0.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 254 {
		t.Fatalf("expected 254 for /24, got %d", n)
	}
}

func TestIsTLSProbeErrorURLError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"tls in message", fmt.Errorf("tls: something wrong"), true},
		{"server gave http", fmt.Errorf("server gave HTTP response to HTTPS client"), true},
		{"malformed", fmt.Errorf("malformed HTTP response"), true},
		{"generic", fmt.Errorf("connection refused"), false},
		{"timeout", fmt.Errorf("i/o timeout"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTLSProbeError(tc.err); got != tc.want {
				t.Errorf("isTLSProbeError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsTLSProbeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil wrapped tls msg", fmt.Errorf("tls handshake failed"), true},
		{"server gave http", fmt.Errorf("server gave HTTP response to HTTPS client"), true},
		{"malformed http", fmt.Errorf("malformed HTTP response"), true},
		{"generic error", fmt.Errorf("connection refused"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTLSProbeError(tc.err); got != tc.want {
				t.Errorf("isTLSProbeError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsTLSProbeErrorWithURLError(t *testing.T) {
	tlsRecordErr := &net.OpError{
		Op:  "read",
		Err: fmt.Errorf("tls: first record does not look like a TLS handshake"),
	}
	urlErr := &url.Error{
		Op:  "Get",
		URL: "https://localhost:8080",
		Err: tlsRecordErr,
	}
	if !isTLSProbeError(urlErr) {
		t.Error("expected url.Error wrapping TLS-like message to be detected")
	}
}

func TestEstimateCIDRSizeIPv6Small(t *testing.T) {
	n, err := EstimateCIDRSize("::1/128")
	if err != nil {
		t.Fatalf("unexpected error for /128: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 for /128, got %d", n)
	}
}

func TestExpandCIDRSingleHost(t *testing.T) {
	hosts, err := ExpandCIDR("10.0.0.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "10.0.0.5" {
		t.Fatalf("expected [10.0.0.5], got %v", hosts)
	}
}

func TestExpandCIDRInvalid(t *testing.T) {
	_, err := ExpandCIDR("not-a-cidr/24")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestExpandCIDRTooLarge(t *testing.T) {
	_, err := ExpandCIDR("10.0.0.0/11")
	if err == nil {
		t.Fatal("expected error for too-large CIDR")
	}
}

func TestIsTimeoutError(t *testing.T) {
	if isTimeoutError(nil) {
		t.Error("nil should not be timeout")
	}
	if !isTimeoutError(context.DeadlineExceeded) {
		t.Error("DeadlineExceeded should be timeout")
	}
	if isTimeoutError(errors.New("generic")) {
		t.Error("generic error should not be timeout")
	}
}

func TestNormalizedProbeStrengthAll(t *testing.T) {
	tests := []struct {
		input ProbeStrength
		want  ProbeStrength
	}{
		{ProbeStrengthStrong, ProbeStrengthStrong},
		{ProbeStrengthSupporting, ProbeStrengthSupporting},
		{ProbeStrengthGeneric, ProbeStrengthGeneric},
		{"", ProbeStrengthStrong},
		{"unknown", ProbeStrengthStrong},
	}
	for _, tc := range tests {
		got := normalizedProbeStrength(tc.input)
		if got != tc.want {
			t.Errorf("normalizedProbeStrength(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestRequestContextNilContext(t *testing.T) {
	scanner := &Scanner{Context: nil}
	ctx := scanner.requestContext()
	if ctx == nil {
		t.Fatal("expected non-nil context when scanner.Context is nil")
	}
}

func TestDialContextNilDialer(t *testing.T) {
	scanner := &Scanner{
		DialContext: nil,
		DialTimeout: 50 * time.Millisecond,
		Context:     context.Background(),
	}
	_, err := scanner.dialContext("127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error connecting to port 1 with default dialer")
	}
}

func TestDialContextCustomDialer(t *testing.T) {
	scanner := &Scanner{
		Context: context.Background(),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("custom-dialer-error")
		},
	}
	_, err := scanner.dialContext("127.0.0.1:8080")
	if err == nil {
		t.Fatal("expected error from custom dialer")
	}
	if !strings.Contains(err.Error(), "custom-dialer-error") {
		t.Fatalf("expected custom dialer error, got: %v", err)
	}
}

func TestDialContextDefaultTimeout(t *testing.T) {
	scanner := &Scanner{
		DialContext: nil,
		DialTimeout: 0,
		Context:     context.Background(),
	}
	_, err := scanner.dialContext("127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error from default dialer with zero timeout")
	}
}

func TestBuildObservationMultipleResultsServerHeader(t *testing.T) {
	services := map[string]*serviceMatch{
		"svc-a": {specificity: 80, strongHits: 1, defaultPort: 8080, probes: []string{"/a"}, serverHeader: "custom-server"},
	}
	obs := buildObservation("host", 8080, "http://host:8080", services, []string{"/a"}, "", "", false)
	if obs.ServerHeader != "custom-server" {
		t.Fatalf("expected server header from result, got %q", obs.ServerHeader)
	}
}

func TestBuildObservationDetailsFromResult(t *testing.T) {
	services := map[string]*serviceMatch{
		"svc-a": {specificity: 80, strongHits: 1, defaultPort: 8080, probes: []string{"/a"}, details: "detail-from-result"},
	}
	obs := buildObservation("host", 8080, "http://host:8080", services, []string{"/a"}, "", "", false)
	if obs.Details != "detail-from-result" {
		t.Fatalf("expected details from result, got %q", obs.Details)
	}
}

func TestBuildObservationPortHeuristic(t *testing.T) {
	// Port 5432 with no HTTP matches should produce a postgresql port-heuristic result.
	obs := buildObservation("host", 5432, "http://host:5432", nil, nil, "", "", false)
	if len(obs.Results) != 1 {
		t.Fatalf("expected 1 result for port 5432, got %d", len(obs.Results))
	}
	if obs.Results[0].Service != "postgresql" {
		t.Fatalf("expected service 'postgresql', got %q", obs.Results[0].Service)
	}
	if obs.Results[0].MatchKind != MatchKindPortHeuristic {
		t.Fatalf("expected MatchKind %q, got %q", MatchKindPortHeuristic, obs.Results[0].MatchKind)
	}
	if obs.FingerprintStatus != MatchKindPortHeuristic {
		t.Fatalf("expected FingerprintStatus %q, got %q", MatchKindPortHeuristic, obs.FingerprintStatus)
	}

	// Non-heuristic port should NOT produce a port-heuristic result.
	obs2 := buildObservation("host", 8080, "http://host:8080", nil, nil, "", "", false)
	if len(obs2.Results) != 0 {
		t.Fatalf("expected 0 results for non-heuristic port 8080, got %d", len(obs2.Results))
	}
}

func TestPrefersHTTPS(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{443, true},
		{8443, true},
		{9443, true},
		{80, false},
		{8080, false},
	}
	for _, tc := range tests {
		if got := prefersHTTPS(tc.port); got != tc.want {
			t.Errorf("prefersHTTPS(%d) = %v, want %v", tc.port, got, tc.want)
		}
	}
}

func TestSchemesForPortHonorsExplicitHTTPSPreference(t *testing.T) {
	scanner := &Scanner{PreferHTTPSPorts: map[int]bool{8000: true}}
	got := scanner.schemesForPort(8000)
	if len(got) != 2 || got[0] != "https" || got[1] != "http" {
		t.Fatalf("expected explicit HTTPS preference for port 8000, got %v", got)
	}

	got = scanner.schemesForPort(8080)
	if len(got) != 1 || got[0] != "http" {
		t.Fatalf("expected default HTTP-only probing for port 8080, got %v", got)
	}
}

func TestRequestPlanKeyDifferentBodies(t *testing.T) {
	k1 := requestPlanKey("POST", "/path", nil, "body1")
	k2 := requestPlanKey("POST", "/path", nil, "body2")
	if k1 == k2 {
		t.Fatal("different bodies should produce different keys")
	}
}

func TestRequestPlanKeyDifferentPaths(t *testing.T) {
	k1 := requestPlanKey("GET", "/a", nil, "")
	k2 := requestPlanKey("GET", "/b", nil, "")
	if k1 == k2 {
		t.Fatal("different paths should produce different keys")
	}
}

func TestBuildRequestPlansDeduplicates(t *testing.T) {
	probes := []ServiceProbe{
		{Name: "svc-a", DefaultPort: 8080, Probes: []HTTPProbe{
			{Path: "/shared", MatchStatus: 200, MatchBody: "a", Specificity: 80},
		}},
		{Name: "svc-b", DefaultPort: 8080, Probes: []HTTPProbe{
			{Path: "/shared", MatchStatus: 200, MatchBody: "b", Specificity: 70},
		}},
	}
	plans := buildRequestPlans(probes, 8080)
	if len(plans) != 1 {
		t.Fatalf("expected 1 deduplicated plan, got %d", len(plans))
	}
	if len(plans[0].expectations) != 2 {
		t.Fatalf("expected 2 expectations in single plan, got %d", len(plans[0].expectations))
	}
}

func TestParseServerBanner(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"nginx/1.18.0", "nginx"},
		{"Apache/2.4.41 (Ubuntu)", "apache"},
		{"Python/3.11 aiohttp/3.9.5", "aiohttp"},
		{"Jetty(9.2.11.v20150529)", "jetty"},
		{"SMA/11.4", "sma"},
		{"Gordian Embedded", "gordian embedded"},
		{"", ""},
		{"uvicorn", "uvicorn"},
		{"Oracle XML DB/Oracle9i Enterprise Edition Release 9", "oracle xml db"},
	}
	for _, tt := range tests {
		got := parseServerBanner(tt.header)
		if got != tt.want {
			t.Errorf("parseServerBanner(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func kubeAPIServerProbe(t *testing.T) ServiceProbe {
	t.Helper()
	for _, p := range BuiltinProbes() {
		if p.Name == "kube-apiserver" {
			return p
		}
	}
	t.Fatal("kube-apiserver probe not registered in BuiltinProbes()")
	return ServiceProbe{}
}

func TestKubeAPIServerProbeRegistered(t *testing.T) {
	p := kubeAPIServerProbe(t)
	if p.DefaultPort != 6443 {
		t.Errorf("kube-apiserver DefaultPort = %d, want 6443", p.DefaultPort)
	}
	if !prefersHTTPS(6443) {
		t.Error("prefersHTTPS(6443) should be true for the apiserver")
	}
}

func TestKubeAPIServerProbeMatching(t *testing.T) {
	p := kubeAPIServerProbe(t)
	h := make(http.Header)

	var versionStrong, version401, apiOpen HTTPProbe
	for _, pr := range p.Probes {
		switch {
		case pr.Path == "/version" && pr.MatchStatus == 200:
			versionStrong = pr
		case pr.Path == "/version" && pr.MatchStatus == 401:
			version401 = pr
		case pr.Path == "/api":
			apiOpen = pr
		}
	}

	// Open cluster: anonymous /version returns gitVersion -> strong match.
	openBody := `{"major":"1","minor":"31","gitVersion":"v1.31.5+k3s1","platform":"linux/arm64"}`
	if !matchProbe(versionStrong, 200, openBody, h) {
		t.Error("expected /version 200 probe to match an open apiserver body")
	}
	if versionStrong.Strength == ProbeStrengthSupporting || versionStrong.Strength == ProbeStrengthGeneric {
		t.Error("the /version 200 probe should be a strong (confirming) probe")
	}
	// Secure cluster: anonymous reads rejected with a Status object -> still identifies.
	secureBody := `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`
	if !matchProbe(version401, 401, secureBody, h) {
		t.Error("expected /version 401 probe to match a default-secure apiserver")
	}
	// /api discovery on an open cluster.
	if !matchProbe(apiOpen, 200, `{"kind":"APIVersions","versions":["v1"]}`, h) {
		t.Error("expected /api probe to match APIVersions discovery body")
	}
	// Negative: an unrelated 200 JSON must not match the apiserver probes.
	if matchProbe(versionStrong, 200, `{"status":"ok","service":"grafana"}`, h) {
		t.Error("apiserver /version probe must not match unrelated JSON")
	}
}
