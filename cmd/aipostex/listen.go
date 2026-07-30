package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/pkg/listener"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	listenAddr      string
	listenPort      int
	listenCertFile  string
	listenKeyFile   string
	listenPath      string
	listenRespondIP string
	listenMaxRead   int64
)

var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Start a callback listener (webhook, TCP, or DNS canary)",
	Long: `Run a local listener to capture callbacks from exploit modules.
Use with --callback-url on service modules to receive proof callbacks,
reverse shell connections, or DNS canary lookups.

All listeners require --force-exploit.`,
	Example: strings.Join([]string{
		formatCommandExample("listen webhook --port 8443 --force-exploit"),
		formatCommandExample("listen tcp --port 4444 --force-exploit"),
		formatCommandExample("listen dns --port 5353 --respond-ip 10.0.0.1 --force-exploit"),
	}, "\n"),
}

var listenWebhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Start an HTTP webhook listener for POST callbacks",
	Long: `Start an HTTP listener that accepts POST requests and logs the body,
headers, and remote address of each callback as a finding.
Supports optional TLS via --tls-cert and --tls-key.

Runs until interrupted (Ctrl-C).`,
	Example: formatCommandExample("listen webhook --port 8443 --force-exploit"),
	RunE:    runListenWebhook,
}

var listenTCPCmd = &cobra.Command{
	Use:   "tcp",
	Short: "Start a raw TCP listener for reverse shells",
	Long: `Start a raw TCP socket listener. Each incoming connection is logged
as a finding with the remote address and first bytes received.

Runs until interrupted (Ctrl-C).`,
	Example: formatCommandExample("listen tcp --port 4444 --force-exploit"),
	RunE:    runListenTCP,
}

var listenDNSCmd = &cobra.Command{
	Use:   "dns",
	Short: "Start a DNS canary listener for lookup callbacks",
	Long: `Start a minimal UDP DNS server that responds to all queries with a
configurable IP and logs each lookup as a finding. Use this with DNS
canary domains to confirm outbound DNS resolution from exploit targets.

Default port is 5353 (does not require root). Use --port 53 with
elevated privileges for real DNS interception.

Runs until interrupted (Ctrl-C).`,
	Example: formatCommandExample("listen dns --port 5353 --respond-ip 10.0.0.1 --force-exploit"),
	RunE:    runListenDNS,
}

func init() {
	listenCmd.PersistentFlags().StringVar(&listenAddr, "addr", "0.0.0.0", "Bind address")
	listenCmd.PersistentFlags().IntVar(&listenPort, "port", 0, "Bind port (default: 8443 webhook, 4444 tcp, 5353 dns)")

	listenWebhookCmd.Flags().StringVar(&listenCertFile, "tls-cert", "", "TLS certificate file for HTTPS")
	listenWebhookCmd.Flags().StringVar(&listenKeyFile, "tls-key", "", "TLS private key file for HTTPS")
	listenWebhookCmd.Flags().StringVar(&listenPath, "path", "/webhook", "HTTP path to listen on")

	listenDNSCmd.Flags().StringVar(&listenRespondIP, "respond-ip", "127.0.0.1", "IP address to include in DNS A responses")

	listenTCPCmd.Flags().Int64Var(&listenMaxRead, "max-read", 64*1024, "Max bytes to capture per TCP connection")

	listenCmd.AddCommand(listenWebhookCmd, listenTCPCmd, listenDNSCmd)
}

func runListenWebhook(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("listen webhook"); err != nil {
		return err
	}
	port := listenPort
	if port == 0 {
		port = 8443
	}
	wl := listener.NewWebhookListener(listener.WebhookConfig{
		Addr:     listenAddr,
		Port:     port,
		Path:     listenPath,
		CertFile: listenCertFile,
		KeyFile:  listenKeyFile,
	})
	wl.SetOnEvent(listenerOnEvent("webhook"))
	proto := "http"
	if listenCertFile != "" {
		proto = "https"
	}
	infof("Webhook listener starting on %s://%s:%d%s (Ctrl-C to stop)", proto, listenAddr, port, listenPath)
	return wl.Start(cmd.Context())
}

func runListenTCP(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("listen tcp"); err != nil {
		return err
	}
	port := listenPort
	if port == 0 {
		port = 4444
	}
	tl := listener.NewTCPListener(listener.TCPConfig{
		Addr:    listenAddr,
		Port:    port,
		MaxRead: listenMaxRead,
	})
	tl.SetOnEvent(listenerOnEvent("tcp"))
	tl.Stdin = os.Stdin
	tl.Stdout = os.Stdout
	tl.Stderr = os.Stderr
	infof("TCP listener starting on %s:%d (Ctrl-C to stop)", listenAddr, port)
	return tl.Start(cmd.Context())
}

func runListenDNS(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("listen dns"); err != nil {
		return err
	}
	port := listenPort
	if port == 0 {
		port = 5353
	}
	ip := net.ParseIP(listenRespondIP)
	if ip == nil {
		return fmt.Errorf("invalid --respond-ip %q", listenRespondIP)
	}
	dl := listener.NewDNSListener(listener.DNSConfig{
		Addr:      listenAddr,
		Port:      port,
		RespondIP: ip,
	})
	dl.SetOnEvent(listenerOnEvent("dns"))
	infof("DNS canary listener starting on %s:%d (respond-ip=%s, Ctrl-C to stop)", listenAddr, port, listenRespondIP)
	return dl.Start(cmd.Context())
}

// listenerOnEvent returns a callback that logs each event to stderr and writes
// a structured finding to the configured output.
func listenerOnEvent(protocol string) func(listener.CallbackEvent) {
	return func(evt listener.CallbackEvent) {
		bodyPreview := evt.Body
		if len(bodyPreview) > 120 {
			bodyPreview = bodyPreview[:120] + "..."
		}
		bodyPreview = strings.ReplaceAll(bodyPreview, "\n", " ")
		warnf("[%s] %s callback from %s (%d bytes): %s",
			evt.Timestamp.Format(time.RFC3339), protocol, evt.RemoteAddr, evt.RawSize, bodyPreview)

		finding := newExploitFinding(
			report.SourceListener,
			evt.RemoteAddr,
			fmt.Sprintf("%s callback received from %s", protocol, evt.RemoteAddr),
			report.SeverityHigh,
			fmt.Sprintf("Received %s callback at %s from %s (%d bytes)",
				protocol, evt.Timestamp.Format(time.RFC3339), evt.RemoteAddr, evt.RawSize),
			map[string]interface{}{
				"module":      "listener",
				"action":      "callback",
				"mutating":    false,
				"protocol":    evt.Protocol,
				"remote_addr": evt.RemoteAddr,
				"raw_size":    evt.RawSize,
			},
		)
		finding.Evidence = evt.Body
		// Best-effort structured output — do not block the listener on write errors.
		data, err := json.Marshal(finding)
		if err != nil {
			return
		}
		// Always echo the callback to stderr for live visibility.
		fmt.Fprintln(os.Stderr, string(data))
		// If the operator configured an output file, persist each callback as a
		// JSONL line so canary hits land in their findings sink, not only the
		// transient console. Appended incrementally because the listener streams
		// until interrupted and has no single end-of-run flush.
		if out := strings.TrimSpace(cfg.OutputFile); out != "" {
			if f, ferr := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); ferr == nil {
				_, _ = fmt.Fprintln(f, string(data))
				_ = f.Close()
			}
		}
	}
}
