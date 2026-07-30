package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/listener"
)

func oobFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("oobFreePort: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// A run func that dereferences the registered (nonce-augmented) URL must produce
// a recorded hit, and the registered URL must carry the per-run nonce.
func TestConfirmOOBCallbackRecordsHit(t *testing.T) {
	port := oobFreePort(t)
	cbURL := fmt.Sprintf("http://127.0.0.1:%d/aipostex-probe", port)

	var gotRegisterURL string
	hit, err := confirmOOBCallback(context.Background(), cbURL, 5*time.Second, func(registerURL string) error {
		gotRegisterURL = registerURL
		resp, gerr := http.Get(registerURL) //nolint:noctx
		if gerr != nil {
			return gerr
		}
		resp.Body.Close()
		return nil
	})
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a recorded callback hit")
	}
	if !strings.Contains(gotRegisterURL, "/aipostex-probe/aipostex-") {
		t.Errorf("register URL should carry the base path + nonce, got %q", gotRegisterURL)
	}
	if !strings.Contains(hit.Body, "GET") || !strings.Contains(hit.Body, "/aipostex-probe/") {
		t.Errorf("unexpected hit body: %q", hit.Body)
	}
}

// An inbound request WITHOUT the per-run nonce (an unrelated hit) must NOT be
// counted as confirmation — the correlation token is what makes a hit defensible.
func TestConfirmOOBCallbackIgnoresUncorrelatedHit(t *testing.T) {
	port := oobFreePort(t)
	cbURL := fmt.Sprintf("http://127.0.0.1:%d/card", port)

	hit, err := confirmOOBCallback(context.Background(), cbURL, 700*time.Millisecond, func(registerURL string) error {
		// Hit a DIFFERENT path with no nonce, simulating a scanner / health probe.
		resp, gerr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/unrelated", port)) //nolint:noctx
		if gerr == nil {
			resp.Body.Close()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if hit != nil {
		t.Errorf("uncorrelated hit must not be counted as confirmation, got %+v", hit)
	}
}

// No dereference => no hit, but run still executes and its error surfaces.
func TestConfirmOOBCallbackNoHit(t *testing.T) {
	port := oobFreePort(t)
	cbURL := fmt.Sprintf("http://127.0.0.1:%d/never", port)

	ran := false
	hit, err := confirmOOBCallback(context.Background(), cbURL, 500*time.Millisecond, func(registerURL string) error {
		ran = true
		return nil
	})
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if !ran {
		t.Error("run was not invoked")
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}

// A non-http(s) callback URL can't be listened on; run still executes with the
// verbatim (un-nonced) URL.
func TestConfirmOOBCallbackBadURLStillRuns(t *testing.T) {
	var gotURL string
	hit, err := confirmOOBCallback(context.Background(), "tcp://127.0.0.1:9", time.Second, func(registerURL string) error {
		gotURL = registerURL
		return nil
	})
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if gotURL != "tcp://127.0.0.1:9" {
		t.Errorf("non-http URL should be passed verbatim, got %q", gotURL)
	}
	if hit != nil {
		t.Errorf("expected no hit for non-http URL, got %+v", hit)
	}
}

func TestOOBEvidence(t *testing.T) {
	if got := oobEvidence("raw-body", nil); got != "raw-body" {
		t.Errorf("nil hit should return raw, got %q", got)
	}
	hit := &listener.CallbackEvent{Body: "GET /probe", RemoteAddr: "127.0.0.1:5555", Timestamp: time.Now().UTC()}
	got := oobEvidence("raw-body", hit)
	if !strings.Contains(got, "raw-body") || !strings.Contains(got, "OOB callback confirmed") {
		t.Errorf("expected raw + confirmation line, got %q", got)
	}
}
