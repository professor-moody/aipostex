// Package runtimehttp configures shared HTTP transports for the CLI and exploit clients:
// timeouts, TLS, optional proxy, stealth delays, and User-Agent rotation.
package runtimehttp

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

type Options struct {
	Timeout  time.Duration
	ProxyURL string
	Insecure bool
	Stealth  bool
}

var defaultUserAgents = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 OPR/121.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
}

var (
	stealthDelayMin = time.Second
	stealthDelayMax = 5 * time.Second
)

type stealthRoundTripper struct {
	base http.RoundTripper
	rng  *rand.Rand
	mu   sync.Mutex
}

// LimitRedirects returns a CheckRedirect function that stops after max redirects.
func LimitRedirects(max int) func(*http.Request, []*http.Request) error {
	return func(_ *http.Request, via []*http.Request) error {
		if len(via) >= max {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

func NewClient(opts Options) (*http.Client, error) {
	transport, err := NewTransport(opts)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:       opts.Timeout,
		Transport:     transport,
		CheckRedirect: LimitRedirects(3),
	}, nil
}

func NewTransport(opts Options) (http.RoundTripper, error) {
	dialTimeout := opts.Timeout
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure, //nolint:gosec
		},
	}

	if opts.ProxyURL != "" {
		parsed, err := url.Parse(opts.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("parsing proxy URL: %w", err)
		}
		switch parsed.Scheme {
		case "http", "https":
			base.Proxy = http.ProxyURL(parsed)
		case "socks5":
			dialer, err := proxy.FromURL(parsed, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("configuring SOCKS5 proxy: %w", err)
			}
			if ctxDialer, ok := dialer.(proxy.ContextDialer); ok {
				base.DialContext = ctxDialer.DialContext
			} else {
				base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return bridgeDialContext(ctx, dialer.Dial, network, addr)
				}
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q (valid: http, https, socks5)", parsed.Scheme)
		}
	}

	if !opts.Stealth {
		return base, nil
	}

	return &stealthRoundTripper{
		base: base,
		rng:  rand.New(rand.NewSource(randomSeed())), //nolint:gosec // jitter does not need cryptographic randomness
	}, nil
}

func NewWebsocketDialer(opts Options) (*websocket.Dialer, error) {
	dialer := &websocket.Dialer{
		HandshakeTimeout: opts.Timeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure, //nolint:gosec
		},
	}
	if opts.ProxyURL == "" {
		return dialer, nil
	}

	parsed, err := url.Parse(opts.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy URL: %w", err)
	}
	switch parsed.Scheme {
	case "http", "https":
		dialer.Proxy = http.ProxyURL(parsed)
	case "socks5":
		proxyDialer, err := proxy.FromURL(parsed, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("configuring SOCKS5 proxy: %w", err)
		}
		if ctxDialer, ok := proxyDialer.(proxy.ContextDialer); ok {
			dialer.NetDialContext = ctxDialer.DialContext
		} else {
			fmt.Fprintln(os.Stderr, "warning: SOCKS5 websocket proxy dialer does not support context-aware dialing; using cancellation bridge")
			dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return bridgeDialContext(ctx, proxyDialer.Dial, network, addr)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (valid: http, https, socks5)", parsed.Scheme)
	}

	return dialer, nil
}

func (s *stealthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if clone.Header.Get("User-Agent") == "" {
		clone.Header.Set("User-Agent", s.nextUserAgent())
	}

	delay := s.nextDelay()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-clone.Context().Done():
		return nil, clone.Context().Err()
	case <-timer.C:
	}

	return s.base.RoundTrip(clone)
}

func (s *stealthRoundTripper) nextUserAgent() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureRNG()
	return defaultUserAgents[s.rng.Intn(len(defaultUserAgents))]
}

func (s *stealthRoundTripper) nextDelay() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureRNG()
	if stealthDelayMax <= stealthDelayMin {
		return stealthDelayMin
	}
	span := stealthDelayMax - stealthDelayMin
	return stealthDelayMin + time.Duration(s.rng.Int63n(int64(span)+1))
}

func (s *stealthRoundTripper) ensureRNG() {
	if s.rng == nil {
		s.rng = rand.New(rand.NewSource(randomSeed())) //nolint:gosec // jitter does not need cryptographic randomness
	}
}

type dialResult struct {
	conn net.Conn
	err  error
}

func bridgeDialContext(ctx context.Context, dial func(network, addr string) (net.Conn, error), network, addr string) (net.Conn, error) {
	ch := make(chan dialResult, 1)
	go func() {
		conn, dialErr := dial(network, addr)
		ch <- dialResult{conn: conn, err: dialErr}
	}()
	select {
	case <-ctx.Done():
		go func() {
			res := <-ch
			if res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case res := <-ch:
		return res.conn, res.err
	}
}

func randomSeed() int64 {
	var seed int64
	if err := binary.Read(crand.Reader, binary.BigEndian, &seed); err == nil {
		return seed
	}
	return time.Now().UnixNano()
}
