package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/pkg/exploit/torchserve"
)

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// A real TorchServe model fetch is an HTTP GET that waits for a response. The
// listener must record the hit on request receipt (not after EOF) and reply, so
// http.Get returns. This is the realistic SSRF path the raw-TCP version missed.
func TestConfirmTorchServeSSRF_Hit(t *testing.T) {
	port := freeTCPPort(t)
	cb := fmt.Sprintf("http://127.0.0.1:%d/x.mar", port)
	old := torchserveSSRFWait
	torchserveSSRFWait = 3 * time.Second
	defer func() { torchserveSSRFWait = old }()

	res, hit, err := confirmTorchServeSSRF(context.Background(), cb, func() (torchserve.RegisterResult, error) {
		// Simulate the TorchServe host fetching the attacker-supplied model URL
		// the way a real HTTP client does: GET and wait for the response.
		resp, derr := http.Get(cb)
		if derr == nil {
			_ = resp.Body.Close()
		}
		return torchserve.RegisterResult{StatusCode: 200, Success: true}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected an out-of-band SSRF hit, got none")
	}
	if !res.Success {
		t.Fatal("expected registration success")
	}
}

// SSRF can fire (server fetches the callback) before registration is rejected as
// an invalid .mar. A hit must still confirm the SSRF even though registerFn errored.
func TestConfirmTorchServeSSRF_HitDespiteRegistrationError(t *testing.T) {
	port := freeTCPPort(t)
	cb := fmt.Sprintf("http://127.0.0.1:%d/x.mar", port)
	old := torchserveSSRFWait
	torchserveSSRFWait = 3 * time.Second
	defer func() { torchserveSSRFWait = old }()

	res, hit, err := confirmTorchServeSSRF(context.Background(), cb, func() (torchserve.RegisterResult, error) {
		resp, derr := http.Get(cb) // SSRF fetch fires...
		if derr == nil {
			_ = resp.Body.Close()
		}
		// ...then registration is rejected (callback URL is not a valid .mar).
		return torchserve.RegisterResult{StatusCode: 400}, fmt.Errorf("invalid model archive")
	})
	if err != nil {
		t.Fatalf("a captured callback must override the registration error, got: %v", err)
	}
	if hit == nil {
		t.Fatal("expected the SSRF hit to be reported despite the registration error")
	}
	_ = res
}

// With no callback received, the SSRF stays unconfirmed (nil hit, no error) —
// the caller keeps the submission-accepted/High label.
func TestConfirmTorchServeSSRF_NoHit(t *testing.T) {
	port := freeTCPPort(t)
	cb := fmt.Sprintf("http://127.0.0.1:%d/x.mar", port)
	old := torchserveSSRFWait
	torchserveSSRFWait = 400 * time.Millisecond
	defer func() { torchserveSSRFWait = old }()

	res, hit, err := confirmTorchServeSSRF(context.Background(), cb, func() (torchserve.RegisterResult, error) {
		return torchserve.RegisterResult{StatusCode: 200, Success: true}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Fatalf("expected no OOB hit, got %+v", hit)
	}
	if !res.Success {
		t.Fatal("expected registration success")
	}
}

// Registration error AND no callback → the registration error is surfaced.
func TestConfirmTorchServeSSRF_RegistrationErrorNoHit(t *testing.T) {
	port := freeTCPPort(t)
	cb := fmt.Sprintf("http://127.0.0.1:%d/x.mar", port)
	old := torchserveSSRFWait
	torchserveSSRFWait = 400 * time.Millisecond
	defer func() { torchserveSSRFWait = old }()

	_, hit, err := confirmTorchServeSSRF(context.Background(), cb, func() (torchserve.RegisterResult, error) {
		return torchserve.RegisterResult{StatusCode: 400}, fmt.Errorf("invalid model archive")
	})
	if err == nil {
		t.Fatal("expected the registration error to surface when no callback arrived")
	}
	if hit != nil {
		t.Fatalf("expected no hit, got %+v", hit)
	}
}

func TestCallbackPortDefaults(t *testing.T) {
	cases := map[string]int{
		"http://h:9000/x":  9000,
		"http://h/x":       80,
		"https://h/x":      443,
		"http://1.2.3.4:1": 1,
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if got := callbackPort(u); got != want {
			t.Errorf("callbackPort(%q) = %d, want %d", raw, got, want)
		}
	}
}
