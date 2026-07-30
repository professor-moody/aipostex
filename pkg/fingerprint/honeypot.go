package fingerprint

import (
	"fmt"
	"strings"
)

// HoneypotSignal describes a single indicator that a target may be a honeypot.
type HoneypotSignal struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// wellKnownNonAIPorts maps port numbers to their canonical service names.
// These are ports where finding an AI service is extremely suspicious.
var wellKnownNonAIPorts = map[int]string{
	7:   "echo",
	9:   "discard",
	11:  "systat",
	13:  "daytime",
	15:  "netstat",
	17:  "qotd",
	19:  "chargen",
	20:  "ftp-data",
	21:  "ftp",
	22:  "ssh",
	23:  "telnet",
	25:  "smtp",
	37:  "time",
	53:  "dns",
	69:  "tftp",
	79:  "finger",
	110: "pop3",
	111: "rpcbind",
	113: "ident",
	119: "nntp",
	123: "ntp",
	135: "msrpc",
	137: "netbios-ns",
	138: "netbios-dgm",
	139: "netbios-ssn",
	143: "imap",
	161: "snmp",
	162: "snmp-trap",
	389: "ldap",
	445: "smb",
	465: "smtps",
	514: "syslog",
	515: "printer",
	520: "rip",
	587: "submission",
	636: "ldaps",
	873: "rsync",
	993: "imaps",
	995: "pop3s",
}

// aiServiceNames lists fingerprinted AI/ML service names for honeypot checks.
var aiServiceNames = map[string]bool{
	"ollama":            true,
	"vllm":              true,
	"litellm":           true,
	"lmstudio":          true,
	"localai":           true,
	"triton":            true,
	"torchserve":        true,
	"torchserve-mgmt":   true,
	"tfserving":         true,
	"hf-tgi":            true,
	"hf-tei":            true,
	"langserve":         true,
	"chromadb":          true,
	"weaviate":          true,
	"qdrant":            true,
	"milvus":            true,
	"bentoml":           true,
	"jupyter":           true,
	"mlflow":            true,
	"gradio":            true,
	"ray":               true,
	"streamlit":         true,
	"openai-compatible": true,
	"open-webui":        true,
	"a2a":               true,
	"kubeflow":          true,
	"wandb":             true,
	"mcp-sse":           true,
	"mcp-inspector":     true,
	"mcpjam-inspector":  true,
}

// OpenPortRatioThreshold is the fraction of open ports above which a
// honeypot warning is emitted.
const OpenPortRatioThreshold = 0.80

// OpenPortRatioMinPorts prevents targeted one/few-port checks from being
// mislabeled as honeypots just because every selected port is open.
const OpenPortRatioMinPorts = 10

// DetectHoneypotSignals inspects discovery observations for indicators that
// one or more targets may be honeypots. It checks three signal classes:
//  1. High open-port ratio (>80% of scanned ports open on a single host)
//  2. AI services confirmed on well-known non-AI ports
//  3. Contradictory banner diversity (future extension placeholder)
func DetectHoneypotSignals(observations []PortObservation, portsScanned int) []HoneypotSignal {
	if len(observations) == 0 || portsScanned <= 0 {
		return nil
	}

	var signals []HoneypotSignal

	// Group observations by host
	byHost := make(map[string][]PortObservation)
	for _, obs := range observations {
		byHost[obs.Host] = append(byHost[obs.Host], obs)
	}

	for host, hostObs := range byHost {
		// Signal 1: high open-port ratio
		ratio := float64(len(hostObs)) / float64(portsScanned)
		if portsScanned >= OpenPortRatioMinPorts && ratio > OpenPortRatioThreshold {
			signals = append(signals, HoneypotSignal{
				Host: host,
				Reason: fmt.Sprintf("%.0f%% of scanned ports are open (%d/%d)",
					ratio*100, len(hostObs), portsScanned),
			})
		}

		// Signal 2: AI service on well-known non-AI port
		for _, obs := range hostObs {
			canonicalPort, isWellKnown := wellKnownNonAIPorts[obs.Port]
			if !isWellKnown {
				continue
			}
			for _, result := range obs.Results {
				if !aiServiceNames[strings.ToLower(result.Service)] {
					continue
				}
				if result.MatchKind == MatchKindConfirmed || result.MatchKind == MatchKindSuspected {
					signals = append(signals, HoneypotSignal{
						Host: host,
						Reason: fmt.Sprintf("%s %s on well-known non-AI port %d/%s",
							result.Service, result.MatchKind, obs.Port, canonicalPort),
					})
				}
			}
		}
	}

	return signals
}
