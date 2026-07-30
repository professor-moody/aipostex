package runtimehttp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/internal/httptestutil"
)

func TestNewTransportRejectsUnsupportedProxyScheme(t *testing.T) {
	_, err := NewTransport(Options{Timeout: time.Second, ProxyURL: "ftp://127.0.0.1:2121"})
	if err == nil || !strings.Contains(err.Error(), "unsupported proxy scheme") {
		t.Fatalf("expected unsupported proxy scheme error, got %v", err)
	}
}

func TestNewTransportHonorsInsecureTLS(t *testing.T) {
	transport, err := NewTransport(Options{Timeout: time.Second, Insecure: true})
	if err != nil {
		t.Fatalf("NewTransport returned error: %v", err)
	}
	base, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", transport)
	}
	if base.TLSClientConfig == nil || !base.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected insecure TLS config, got %#v", base.TLSClientConfig)
	}
}

func TestStealthRoundTripperAddsUserAgent(t *testing.T) {
	prevMin := stealthDelayMin
	prevMax := stealthDelayMax
	stealthDelayMin = 0
	stealthDelayMax = 0
	defer func() {
		stealthDelayMin = prevMin
		stealthDelayMax = prevMax
	}()

	var seenUserAgent string
	rt := &stealthRoundTripper{
		base: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			seenUserAgent = req.Header.Get("User-Agent")
			r := httptestutil.Text(http.StatusOK, "ok")
			r.TLS = &tls.ConnectionState{}
			return r, nil
		}),
	}

	req, err := http.NewRequest(http.MethodGet, "https://unit.test", nil)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	defer resp.Body.Close()
	if seenUserAgent == "" {
		t.Fatal("expected stealth transport to inject a User-Agent")
	}
}

func TestBridgeDialContextClosesLateConnectionAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	closed := atomic.Bool{}
	_, err := bridgeDialContext(ctx, func(network, addr string) (net.Conn, error) {
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			buf := make([]byte, 1)
			if _, readErr := server.Read(buf); readErr != nil {
				closed.Store(true)
			}
		}()
		time.Sleep(15 * time.Millisecond)
		return client, nil
	}, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected cancellation error")
	}

	deadline := time.Now().Add(250 * time.Millisecond)
	for !closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !closed.Load() {
		t.Fatal("expected late-arriving connection to be closed")
	}
}

func TestLimitRedirects(t *testing.T) {
	check := LimitRedirects(2)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err := check(req, []*http.Request{}); err != nil {
		t.Error("0 redirects should be allowed")
	}
	if err := check(req, []*http.Request{req}); err != nil {
		t.Error("1 redirect should be allowed")
	}
	if err := check(req, []*http.Request{req, req}); err != http.ErrUseLastResponse {
		t.Errorf("2 redirects should return ErrUseLastResponse, got %v", err)
	}
	if err := check(req, []*http.Request{req, req, req}); err != http.ErrUseLastResponse {
		t.Errorf("3 redirects should return ErrUseLastResponse, got %v", err)
	}
}

func TestNewClientReturnsConfiguredHTTPClient(t *testing.T) {
	client, err := NewClient(Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil http.Client")
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Error("expected CheckRedirect to be set")
	}
	if client.Transport == nil {
		t.Error("expected Transport to be set")
	}
}

func TestNewClientRejectsInvalidProxy(t *testing.T) {
	_, err := NewClient(Options{Timeout: time.Second, ProxyURL: "ftp://127.0.0.1:2121"})
	if err == nil || !strings.Contains(err.Error(), "unsupported proxy scheme") {
		t.Fatalf("expected unsupported proxy scheme error, got %v", err)
	}
}

func TestNewTransportDefaultTimeout(t *testing.T) {
	transport, err := NewTransport(Options{Timeout: 0})
	if err != nil {
		t.Fatalf("NewTransport returned error: %v", err)
	}
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestNewTransportHTTPProxy(t *testing.T) {
	transport, err := NewTransport(Options{Timeout: time.Second, ProxyURL: "http://127.0.0.1:8888"})
	if err != nil {
		t.Fatalf("NewTransport with HTTP proxy returned error: %v", err)
	}
	base, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", transport)
	}
	if base.Proxy == nil {
		t.Fatal("expected proxy function to be set")
	}
}

func TestNewTransportHTTPSProxy(t *testing.T) {
	transport, err := NewTransport(Options{Timeout: time.Second, ProxyURL: "https://proxy.example.com:443"})
	if err != nil {
		t.Fatalf("NewTransport with HTTPS proxy returned error: %v", err)
	}
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestNewTransportInvalidProxyURL(t *testing.T) {
	_, err := NewTransport(Options{Timeout: time.Second, ProxyURL: "://bad"})
	if err == nil {
		t.Fatal("expected error for invalid proxy URL")
	}
	if !strings.Contains(err.Error(), "parsing proxy URL") {
		t.Fatalf("expected parsing error, got %v", err)
	}
}

func TestNewTransportStealthMode(t *testing.T) {
	transport, err := NewTransport(Options{Timeout: time.Second, Stealth: true})
	if err != nil {
		t.Fatalf("NewTransport with stealth returned error: %v", err)
	}
	if _, ok := transport.(*stealthRoundTripper); !ok {
		t.Fatalf("expected *stealthRoundTripper, got %T", transport)
	}
}

func TestNewTransportSocks5Proxy(t *testing.T) {
	_, err := NewTransport(Options{Timeout: time.Second, ProxyURL: "socks5://127.0.0.1:1080"})
	if err != nil {
		t.Fatalf("NewTransport with SOCKS5 proxy returned error: %v", err)
	}
}

func TestStealthRoundTripperPreservesExistingUserAgent(t *testing.T) {
	prevMin := stealthDelayMin
	prevMax := stealthDelayMax
	stealthDelayMin = 0
	stealthDelayMax = 0
	defer func() {
		stealthDelayMin = prevMin
		stealthDelayMax = prevMax
	}()

	var seenUA string
	rt := &stealthRoundTripper{
		base: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			seenUA = req.Header.Get("User-Agent")
			return httptestutil.Text(http.StatusOK, "ok"), nil
		}),
	}

	req, _ := http.NewRequest(http.MethodGet, "http://test.local", nil)
	req.Header.Set("User-Agent", "CustomAgent/1.0")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if seenUA != "CustomAgent/1.0" {
		t.Fatalf("expected custom UA preserved, got %q", seenUA)
	}
}

func TestStealthRoundTripperCancelledContext(t *testing.T) {
	prevMin := stealthDelayMin
	prevMax := stealthDelayMax
	stealthDelayMin = 5 * time.Second
	stealthDelayMax = 5 * time.Second
	defer func() {
		stealthDelayMin = prevMin
		stealthDelayMax = prevMax
	}()

	rt := &stealthRoundTripper{
		base: httptestutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return httptestutil.Text(http.StatusOK, "ok"), nil
		}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://test.local", nil)
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestNewTransportUsesConfiguredDialTimeout(t *testing.T) {
	transport, err := NewTransport(Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("NewTransport returned error: %v", err)
	}
	base, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", transport)
	}
	if base.DialContext == nil {
		t.Fatal("expected DialContext to be configured")
	}
}

func TestNextDelayBounds(t *testing.T) {
	prevMin := stealthDelayMin
	prevMax := stealthDelayMax
	stealthDelayMin = 100 * time.Millisecond
	stealthDelayMax = 200 * time.Millisecond
	defer func() {
		stealthDelayMin = prevMin
		stealthDelayMax = prevMax
	}()

	rt := &stealthRoundTripper{}
	for i := 0; i < 100; i++ {
		d := rt.nextDelay()
		if d < 100*time.Millisecond || d > 200*time.Millisecond {
			t.Fatalf("delay %v out of bounds [100ms, 200ms]", d)
		}
	}
}

func TestNextDelayMinEqualMax(t *testing.T) {
	prevMin := stealthDelayMin
	prevMax := stealthDelayMax
	stealthDelayMin = 50 * time.Millisecond
	stealthDelayMax = 50 * time.Millisecond
	defer func() {
		stealthDelayMin = prevMin
		stealthDelayMax = prevMax
	}()

	rt := &stealthRoundTripper{}
	d := rt.nextDelay()
	if d != 50*time.Millisecond {
		t.Fatalf("expected exact 50ms when min==max, got %v", d)
	}
}

func TestNextDelayMaxLessThanMin(t *testing.T) {
	prevMin := stealthDelayMin
	prevMax := stealthDelayMax
	stealthDelayMin = 200 * time.Millisecond
	stealthDelayMax = 100 * time.Millisecond
	defer func() {
		stealthDelayMin = prevMin
		stealthDelayMax = prevMax
	}()

	rt := &stealthRoundTripper{}
	d := rt.nextDelay()
	if d != 200*time.Millisecond {
		t.Fatalf("expected min when max<min, got %v", d)
	}
}

func TestRandomSeedReturnsValue(t *testing.T) {
	seen := make(map[int64]bool)
	for i := 0; i < 10; i++ {
		s := randomSeed()
		seen[s] = true
	}
	if len(seen) < 5 {
		t.Fatalf("expected diverse seeds, got only %d unique values", len(seen))
	}
}

func TestNewWebsocketDialerBasic(t *testing.T) {
	d, err := NewWebsocketDialer(Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.HandshakeTimeout != 3*time.Second {
		t.Fatalf("expected 3s timeout, got %v", d.HandshakeTimeout)
	}
}

func TestNewWebsocketDialerHTTPProxy(t *testing.T) {
	d, err := NewWebsocketDialer(Options{Timeout: time.Second, ProxyURL: "http://127.0.0.1:8888"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Proxy == nil {
		t.Fatal("expected proxy to be set")
	}
}

func TestNewWebsocketDialerUnsupportedScheme(t *testing.T) {
	_, err := NewWebsocketDialer(Options{Timeout: time.Second, ProxyURL: "ftp://127.0.0.1:2121"})
	if err == nil || !strings.Contains(err.Error(), "unsupported proxy scheme") {
		t.Fatalf("expected unsupported proxy error, got %v", err)
	}
}

func TestNewWebsocketDialerInvalidURL(t *testing.T) {
	_, err := NewWebsocketDialer(Options{Timeout: time.Second, ProxyURL: "://bad"})
	if err == nil || !strings.Contains(err.Error(), "parsing proxy URL") {
		t.Fatalf("expected parsing error, got %v", err)
	}
}

func TestNewWebsocketDialerSocks5(t *testing.T) {
	d, err := NewWebsocketDialer(Options{Timeout: time.Second, ProxyURL: "socks5://127.0.0.1:1080"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.NetDialContext == nil {
		t.Fatal("expected NetDialContext to be configured for SOCKS5")
	}
}
