// Package listener provides webhook, TCP, and DNS canary listener
// infrastructure for receiving callbacks from exploit modules.
package listener

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Type enumerates supported listener protocols.
const (
	TypeWebhook = "webhook"
	TypeTCP     = "tcp"
	TypeDNS     = "dns"
)

// CallbackEvent represents a single received callback regardless of protocol.
type CallbackEvent struct {
	Timestamp  time.Time         `json:"timestamp"`
	Protocol   string            `json:"protocol"`
	RemoteAddr string            `json:"remote_addr"`
	Module     string            `json:"module,omitempty"`
	Action     string            `json:"action,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	RawSize    int               `json:"raw_size"`
}

// Listener is the common interface for all listener types.
type Listener interface {
	Start(ctx context.Context) error
	Addr() string
	Events() []CallbackEvent
}

// --------------- Webhook listener ---------------

// WebhookConfig configures a webhook HTTP listener.
type WebhookConfig struct {
	Addr     string
	Port     int
	Path     string
	CertFile string
	KeyFile  string
}

func (c *WebhookConfig) defaults() {
	if c.Addr == "" {
		c.Addr = "0.0.0.0"
	}
	if c.Port == 0 {
		c.Port = 8443
	}
	if c.Path == "" {
		c.Path = "/webhook"
	}
}

// WebhookListener accepts incoming HTTP POST callbacks.
type WebhookListener struct {
	cfg     WebhookConfig
	mu      sync.Mutex
	events  []CallbackEvent
	ln      net.Listener
	addr    string
	onEvent func(CallbackEvent)
}

// NewWebhookListener creates a webhook listener with the given config.
func NewWebhookListener(cfg WebhookConfig) *WebhookListener {
	cfg.defaults()
	return &WebhookListener{cfg: cfg}
}

// SetOnEvent registers a callback invoked for each received event.
func (w *WebhookListener) SetOnEvent(fn func(CallbackEvent)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onEvent = fn
}

func (w *WebhookListener) Addr() string { return w.addr }

func (w *WebhookListener) Events() []CallbackEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]CallbackEvent, len(w.events))
	copy(out, w.events)
	return out
}

func (w *WebhookListener) record(evt CallbackEvent) {
	w.mu.Lock()
	w.events = append(w.events, evt)
	fn := w.onEvent
	w.mu.Unlock()
	if fn != nil {
		fn(evt)
	}
}

const webhookBodyLimit = 1 << 20

func (w *WebhookListener) Start(ctx context.Context) error {
	listenAddr := fmt.Sprintf("%s:%d", w.cfg.Addr, w.cfg.Port)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("webhook listen %s: %w", listenAddr, err)
	}
	w.ln = ln
	w.addr = ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc(w.cfg.Path, func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, webhookBodyLimit))
		hdrs := make(map[string]string, len(r.Header))
		for k := range r.Header {
			hdrs[k] = r.Header.Get(k)
		}
		evt := CallbackEvent{
			Timestamp:  time.Now().UTC(),
			Protocol:   TypeWebhook,
			RemoteAddr: r.RemoteAddr,
			Headers:    hdrs,
			Body:       string(body),
			RawSize:    len(body),
		}
		var parsed map[string]interface{}
		if json.Unmarshal(body, &parsed) == nil {
			if m, ok := parsed["module"].(string); ok {
				evt.Module = m
			}
			if a, ok := parsed["action"].(string); ok {
				evt.Action = a
			}
		}
		w.record(evt)
		rw.WriteHeader(http.StatusOK)
		fmt.Fprintln(rw, `{"status":"received"}`)
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if w.cfg.CertFile != "" && w.cfg.KeyFile != "" {
		return srv.ServeTLS(ln, w.cfg.CertFile, w.cfg.KeyFile)
	}
	err = srv.Serve(ln)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// --------------- TCP listener ---------------

// TCPConfig configures a raw TCP listener for reverse shells.
type TCPConfig struct {
	Addr        string
	Port        int
	Interactive bool
	MaxRead     int64
}

func (c *TCPConfig) defaults() {
	if c.Addr == "" {
		c.Addr = "0.0.0.0"
	}
	if c.Port == 0 {
		c.Port = 4444
	}
	if c.MaxRead == 0 {
		c.MaxRead = 64 * 1024
	}
}

// TCPListener accepts raw TCP connections and logs data.
type TCPListener struct {
	cfg     TCPConfig
	mu      sync.Mutex
	events  []CallbackEvent
	ln      net.Listener
	addr    string
	onEvent func(CallbackEvent)
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// NewTCPListener creates a TCP listener with the given config.
func NewTCPListener(cfg TCPConfig) *TCPListener {
	cfg.defaults()
	return &TCPListener{cfg: cfg}
}

// SetOnEvent registers a callback invoked for each received event.
func (t *TCPListener) SetOnEvent(fn func(CallbackEvent)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onEvent = fn
}

func (t *TCPListener) Addr() string { return t.addr }

func (t *TCPListener) Events() []CallbackEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]CallbackEvent, len(t.events))
	copy(out, t.events)
	return out
}

func (t *TCPListener) record(evt CallbackEvent) {
	t.mu.Lock()
	t.events = append(t.events, evt)
	fn := t.onEvent
	t.mu.Unlock()
	if fn != nil {
		fn(evt)
	}
}

func (t *TCPListener) Start(ctx context.Context) error {
	listenAddr := fmt.Sprintf("%s:%d", t.cfg.Addr, t.cfg.Port)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("tcp listen %s: %w", listenAddr, err)
	}
	t.ln = ln
	t.addr = ln.Addr().String()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("tcp accept: %w", err)
		}
		go t.handleConn(ctx, conn)
	}
}

func (t *TCPListener) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	evt := CallbackEvent{
		Timestamp:  time.Now().UTC(),
		Protocol:   TypeTCP,
		RemoteAddr: remote,
	}
	if t.cfg.Interactive && t.Stdin != nil && t.Stdout != nil {
		done := make(chan struct{}, 2)
		go func() {
			io.Copy(t.Stdout, conn) //nolint:errcheck
			done <- struct{}{}
		}()
		go func() {
			io.Copy(conn, t.Stdin) //nolint:errcheck
			done <- struct{}{}
		}()
		select {
		case <-done:
		case <-ctx.Done():
		}
		evt.Body = "(interactive session)"
		evt.RawSize = -1
	} else {
		buf, _ := io.ReadAll(io.LimitReader(conn, t.cfg.MaxRead))
		evt.Body = string(buf)
		evt.RawSize = len(buf)
	}
	t.record(evt)
}

// --------------- DNS canary listener ---------------

// DNSConfig configures a minimal UDP DNS canary listener.
type DNSConfig struct {
	Addr      string
	Port      int
	RespondIP net.IP
}

func (c *DNSConfig) defaults() {
	if c.Addr == "" {
		c.Addr = "0.0.0.0"
	}
	if c.Port == 0 {
		c.Port = 5353
	}
	if c.RespondIP == nil {
		c.RespondIP = net.IPv4(127, 0, 0, 1)
	}
}

// DNSListener is a minimal UDP DNS server that logs all queries and
// responds with a fixed A record.
type DNSListener struct {
	cfg     DNSConfig
	mu      sync.Mutex
	events  []CallbackEvent
	conn    *net.UDPConn
	addr    string
	onEvent func(CallbackEvent)
}

// NewDNSListener creates a DNS canary listener with the given config.
func NewDNSListener(cfg DNSConfig) *DNSListener {
	cfg.defaults()
	return &DNSListener{cfg: cfg}
}

// SetOnEvent registers a callback invoked for each received event.
func (d *DNSListener) SetOnEvent(fn func(CallbackEvent)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onEvent = fn
}

func (d *DNSListener) Addr() string { return d.addr }

func (d *DNSListener) Events() []CallbackEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]CallbackEvent, len(d.events))
	copy(out, d.events)
	return out
}

func (d *DNSListener) record(evt CallbackEvent) {
	d.mu.Lock()
	d.events = append(d.events, evt)
	fn := d.onEvent
	d.mu.Unlock()
	if fn != nil {
		fn(evt)
	}
}

func (d *DNSListener) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", d.cfg.Addr, d.cfg.Port))
	if err != nil {
		return fmt.Errorf("dns resolve addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dns listen %s: %w", addr, err)
	}
	d.conn = conn
	d.addr = conn.LocalAddr().String()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 512)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("dns read: %w", err)
		}
		if n < 12 {
			continue
		}
		qname := extractDNSQName(buf[12:n])
		evt := CallbackEvent{
			Timestamp:  time.Now().UTC(),
			Protocol:   TypeDNS,
			RemoteAddr: remote.String(),
			Body:       qname,
			RawSize:    n,
		}
		d.record(evt)
		resp := buildDNSResponse(buf[:n], d.cfg.RespondIP)
		conn.WriteToUDP(resp, remote) //nolint:errcheck
	}
}

// extractDNSQName parses a query name from the question section of a DNS packet
// starting after the 12-byte header.
func extractDNSQName(data []byte) string {
	var parts []string
	i := 0
	for i < len(data) {
		length := int(data[i])
		if length == 0 {
			break
		}
		i++
		if i+length > len(data) {
			break
		}
		parts = append(parts, string(data[i:i+length]))
		i += length
	}
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "." + p
	}
	return out
}

// buildDNSResponse constructs a minimal DNS A-record response.
func buildDNSResponse(query []byte, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, len(query)+16)
	copy(resp, query)
	resp[2] = 0x81
	resp[3] = 0x80
	resp[6] = 0x00
	resp[7] = 0x01
	offset := len(query)
	resp[offset] = 0xc0
	resp[offset+1] = 0x0c
	resp[offset+2] = 0x00
	resp[offset+3] = 0x01
	resp[offset+4] = 0x00
	resp[offset+5] = 0x01
	resp[offset+6] = 0x00
	resp[offset+7] = 0x00
	resp[offset+8] = 0x00
	resp[offset+9] = 0x3c
	resp[offset+10] = 0x00
	resp[offset+11] = 0x04
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1).To4()
	}
	copy(resp[offset+12:offset+16], ip4)
	return resp[:offset+16]
}
