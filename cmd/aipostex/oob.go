package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/professor-moody/aipostex/pkg/listener"
)

// oobConfirmWait bounds how long we wait for an out-of-band callback after a
// probe registers an attacker-controlled URL with the target.
var oobConfirmWait = 12 * time.Second

// confirmOOBCallback stands up an in-process HTTP listener on callbackURL's port,
// appends a per-run unguessable nonce to the callback path, and passes the
// nonce-augmented URL to run (which should register it with the target). It waits
// up to wait for the target to dereference that exact URL and returns the FIRST
// inbound request whose path carries the nonce (nil if none arrived). run's error
// is returned even when no callback is seen, so the caller can still report
// honestly.
//
// The nonce is what makes a confirmation defensible: only a callback WE provoked
// (carrying the unguessable token) counts, so an unrelated inbound hit — a port
// scan, a health probe, a stray webhook — cannot be mislabeled as proof. This is
// the out-of-band confirmation primitive for the A2A card-spoof / push-hijack
// verbs: an "accepted" JSON-RPC reply only proves the instruction was processed,
// whereas a real nonce-matched hit proves the agent actually dereferenced the
// attacker URL (fetch-and-trust) or delivered to the attacker webhook (push
// hijack), upgrading the proof from "influenced" to "exploited".
//
// NOTE: keep the listen/poll machinery in sync with confirmTorchServeSSRF in
// torchserve.go — they are deliberate siblings (that one threads a RegisterResult
// and does not nonce-scope its path). The listener is plaintext HTTP, so an
// https callback URL whose target completes a TLS handshake cannot be confirmed.
func confirmOOBCallback(ctx context.Context, callbackURL string, wait time.Duration, run func(registerURL string) error) (*listener.CallbackEvent, error) {
	base := strings.TrimSpace(callbackURL)
	u, perr := url.Parse(base)
	if perr != nil || u.Host == "" {
		return nil, run(base)
	}
	if s := strings.ToLower(u.Scheme); s != "http" && s != "https" {
		return nil, run(base)
	}
	port := callbackPort(u)

	// Per-run correlation token appended to the callback path.
	nonce := oobNonce()
	u.Path = strings.TrimRight(u.Path, "/") + "/" + nonce
	registerURL := u.String()

	var (
		mu  sync.Mutex
		hit *listener.CallbackEvent
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		// Only count an inbound request that carries our per-run nonce.
		if hit == nil && strings.Contains(r.URL.Path, nonce) {
			hdrs := make(map[string]string, len(r.Header))
			for k := range r.Header {
				hdrs[k] = r.Header.Get(k)
			}
			hit = &listener.CallbackEvent{
				Timestamp:  time.Now().UTC(),
				Protocol:   "http",
				RemoteAddr: r.RemoteAddr,
				Headers:    hdrs,
				Body:       fmt.Sprintf("%s %s", r.Method, r.URL.RequestURI()),
			}
		}
		mu.Unlock()
		// Answer with a minimal agent-card-shaped body so a fetch-and-trust agent
		// gets a plausible 200 rather than an error.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"aipostex-oob","skills":[]}`))
	})
	ln, lerr := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if lerr != nil {
		// Port unavailable; run the probe without confirmation.
		return nil, run(registerURL)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	firstHit := func() *listener.CallbackEvent {
		mu.Lock()
		defer mu.Unlock()
		return hit
	}

	runErr := run(registerURL)

	deadline := time.Now().Add(wait)
	for {
		if h := firstHit(); h != nil {
			return h, runErr
		}
		if time.Now().After(deadline) {
			return nil, runErr
		}
		select {
		case <-ctx.Done():
			return firstHit(), runErr
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// oobNonce returns a per-run, unguessable correlation token for the callback path.
func oobNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("aipostex-%d", time.Now().UnixNano())
	}
	return "aipostex-" + hex.EncodeToString(b)
}

// cmdInjectMathProof returns a shell fragment whose printed marker only appears when
// a REAL shell EVALUATES the arithmetic expansion. A reflected/echoed payload prints
// the literal `$((a*b))`, never the product — so a returned marker is nonce-confirmed
// command execution, upgrading cmd-inject from a heuristic marker match (influenced)
// to execution-confirmed. Operands are per-run random so the product can't be guessed.
func cmdInjectMathProof() (fragment, marker string) {
	b := make([]byte, 2)
	a1, a2 := 3607, 2909
	if _, err := rand.Read(b); err == nil {
		a1 = 2003 + int(b[0])*7
		a2 = 2003 + int(b[1])*7
	}
	marker = fmt.Sprintf("aipx%ddone", a1*a2)
	fragment = fmt.Sprintf("echo aipx$((%d*%d))done", a1, a2)
	return fragment, marker
}

// oobEvidence appends a confirmed out-of-band callback (with its source address)
// to a probe's raw response.
func oobEvidence(raw string, hit *listener.CallbackEvent) string {
	if hit == nil {
		return raw
	}
	line := fmt.Sprintf("[OOB callback confirmed] %s from %s at %s",
		hit.Body, hit.RemoteAddr, hit.Timestamp.Format(time.RFC3339))
	if strings.TrimSpace(raw) == "" {
		return line
	}
	return raw + "\n\n" + line
}
