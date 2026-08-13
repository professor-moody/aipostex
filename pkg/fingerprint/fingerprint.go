package fingerprint

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/professor-moody/aipostex/internal/runtimehttp"
	"github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

// ServiceProbe defines how to detect a specific AI service
type ServiceProbe struct {
	Name        string
	DefaultPort int
	Probes      []HTTPProbe
}

// HTTPProbe is a single HTTP request + match condition
type HTTPProbe struct {
	Method       string
	Path         string
	Headers      map[string]string
	Body         string
	MatchStatus  int
	MatchBody    string            // Substring match (positive)
	MatchBodyNot string            // Reject if body contains this substring
	MatchHeader  map[string]string // Match response header values (case-insensitive)
	VersionRegex string            // Optional regex to extract version from response body (first capture group)
	Specificity  int               // 1-100, higher = more confident
	Strength     ProbeStrength     // Optional override; empty defaults to strong
}

// Result represents a discovered AI service
type Result struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Service      string   `json:"service"`
	URL          string   `json:"url"`
	Specificity  int      `json:"specificity"`
	Version      string   `json:"version,omitempty"`
	ServerHeader string   `json:"server_header,omitempty"`
	Details      string   `json:"details,omitempty"`
	Probes       []string `json:"probes,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
	MatchKind    string   `json:"match_kind,omitempty"`
	Ambiguity    string   `json:"ambiguity_reason,omitempty"`
	ProxyLikely  bool     `json:"proxy_likely,omitempty"`
}

// PortObservation represents the final discovery record for a single TCP-open
// host:port, including any surviving identities and lower-confidence candidates.
type PortObservation struct {
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	URL               string   `json:"url"`
	PortState         string   `json:"port_state"`
	FingerprintStatus string   `json:"fingerprint_status,omitempty"`
	TimedOut          bool     `json:"timed_out,omitempty"`
	Incomplete        bool     `json:"incomplete,omitempty"`
	CandidateServices []string `json:"candidate_services,omitempty"`
	MatchedProbes     []string `json:"matched_probes,omitempty"`
	ServerHeader      string   `json:"server_header,omitempty"`
	Details           string   `json:"details,omitempty"`
	Results           []Result `json:"identities,omitempty"`
}

type ProbeStrength string

const (
	ProbeStrengthStrong     ProbeStrength = "strong"
	ProbeStrengthSupporting ProbeStrength = "supporting"
	ProbeStrengthGeneric    ProbeStrength = "generic"
)

const (
	MatchKindConfirmed     = "confirmed"
	MatchKindSuspected     = "suspected"
	MatchKindAmbiguous     = "ambiguous"
	MatchKindBanner        = "banner"
	MatchKindPortHeuristic = "port-heuristic"
)

// ScanProgressFunc is called during scanning to report progress.
type ScanProgressFunc func(event ScanProgressEvent)

// ScanProgressEvent describes a fingerprint scan progress update.
type ScanProgressEvent struct {
	Type    string // "tcp_open", "fingerprinting", "matched", "timed_out", "done"
	Host    string
	Port    int
	Service string
	Probe   string
	Current int
	Total   int
	Budget  time.Duration
}

type probeExpectation struct {
	serviceName  string
	defaultPort  int
	probe        HTTPProbe
	portMatched  bool
	probeKey     string
	displayProbe string
}

type requestPlan struct {
	method       string
	path         string
	headers      map[string]string
	body         string
	priority     int
	displayProbe string
	expectations []probeExpectation
}

// Scanner discovers AI services on a network
type Scanner struct {
	Context            context.Context
	DialContext        func(ctx context.Context, network, addr string) (net.Conn, error)
	Probes             []ServiceProbe
	HTTPClient         *http.Client
	Concurrency        int
	FingerprintTimeout time.Duration
	DialTimeout        time.Duration
	Verbose            bool
	OnProgress         ScanProgressFunc
	PreferHTTPSPorts   map[int]bool
}

// NewScanner creates a scanner with all built-in probes and a default HTTP client.
func NewScanner(timeout time.Duration, concurrency int) *Scanner {
	return NewScannerWithClient(nil, timeout, concurrency)
}

// NewScannerWithClient creates a scanner using the provided HTTP client.
// If httpClient is nil, a plain client with the given timeout is used.
func NewScannerWithClient(httpClient *http.Client, timeout time.Duration, concurrency int) *Scanner {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:       timeout,
			CheckRedirect: runtimehttp.LimitRedirects(1),
		}
	}
	return &Scanner{
		Context:            context.Background(),
		Probes:             BuiltinProbes(),
		Concurrency:        concurrency,
		FingerprintTimeout: timeout,
		DialTimeout:        time.Second,
		HTTPClient:         httpClient,
	}
}

// ScanHost checks a single host:port and returns an inventory-first observation.
func (s *Scanner) ScanHost(host string, port int) PortObservation {
	return s.scanHost(host, port, 0, 0)
}

func (s *Scanner) scanHost(host string, port, current, total int) PortObservation {
	observation := PortObservation{
		Host:      host,
		Port:      port,
		PortState: "open",
		URL:       defaultBaseURL(host, port),
	}
	if s.Context != nil && s.Context.Err() != nil {
		return observation
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := s.dialContext(addr)
	if err != nil {
		return PortObservation{}
	}
	conn.Close()
	s.emitProgress(ScanProgressEvent{Type: "tcp_open", Host: host, Port: port, Current: current, Total: total})

	if heuristicService := preHTTPPortHeuristicService(port); heuristicService != "" {
		observation = portHeuristicObservation(host, port, heuristicService)
		s.emitProgress(ScanProgressEvent{
			Type:    "matched",
			Host:    host,
			Port:    port,
			Service: heuristicService,
			Current: current,
			Total:   total,
			Probe:   "well-known port",
		})
		return observation
	}

	fingerprintCtx := s.requestContext()
	var cancel context.CancelFunc
	if s.FingerprintTimeout > 0 {
		fingerprintCtx, cancel = context.WithTimeout(fingerprintCtx, s.FingerprintTimeout)
		defer cancel()
	}
	s.emitProgress(ScanProgressEvent{
		Type:    "fingerprinting",
		Host:    host,
		Port:    port,
		Current: current,
		Total:   total,
		Budget:  s.FingerprintTimeout,
	})

	schemes := s.schemesForPort(port)

	requestPlans := buildRequestPlans(s.Probes, port)

	var bestResults map[string]*serviceMatch
	var bestBaseURL string
	var bestMatchedProbes []string
	var bestServerHeader string
	var bestDetails string
	timedOut := false
	for _, scheme := range schemes {
		baseURL := fmt.Sprintf("%s://%s", scheme, addr)
		observation.URL = baseURL
		sawTLSError := false
		services := make(map[string]*serviceMatch)
		matchedProbeSet := make(map[string]struct{})

	probeLoop:
		for _, plan := range requestPlans {
			if fingerprintCtx.Err() != nil {
				timedOut = errors.Is(fingerprintCtx.Err(), context.DeadlineExceeded)
				break probeLoop
			}
			if s.Context != nil && s.Context.Err() != nil {
				return buildObservation(host, port, bestBaseURL, bestResults, bestMatchedProbes, bestServerHeader, bestDetails, timedOut)
			}

			// Early termination: once all port-matched strong and
			// supporting probes have run (priority 0-1) and we have a
			// confirmed strong identification on this port's default
			// service, skip remaining lower-priority probes to conserve
			// the fingerprint time budget and avoid generic false
			// positives.
			if plan.priority >= 2 && hasStrongPortMatch(services, port) {
				break probeLoop
			}

			probeURL := baseURL + plan.path
			s.emitProgress(ScanProgressEvent{
				Type:    "fingerprinting",
				Host:    host,
				Port:    port,
				Probe:   plan.displayProbe,
				Current: current,
				Total:   total,
				Budget:  s.FingerprintTimeout,
			})

			var bodyReader io.Reader
			if plan.body != "" {
				bodyReader = strings.NewReader(plan.body)
			}

			req, err := http.NewRequestWithContext(fingerprintCtx, plan.method, probeURL, bodyReader)
			if err != nil {
				continue
			}
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", DefaultUserAgent)
			}
			for k, v := range plan.headers {
				req.Header.Set(k, v)
			}

			resp, err := s.HTTPClient.Do(req)
			if err != nil {
				if fingerprintCtx.Err() != nil || isTimeoutError(err) {
					timedOut = true
					break probeLoop
				}
				if isTLSProbeError(err) {
					sawTLSError = true
				}
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, common.FingerprintBodyLimit))
			resp.Body.Close()
			bodyStr := string(body)
			serverHdr := resp.Header.Get("Server")
			bodyPreview := stringutil.BoundedPreview(bodyStr, 200)

			// Always capture the first Server header and body preview for
			// banner-fallback identification even when no probe matches.
			if bestServerHeader == "" && serverHdr != "" {
				bestServerHeader = serverHdr
			}
			if bestDetails == "" && bodyPreview != "" {
				bestDetails = bodyPreview
			}

			for _, expectation := range plan.expectations {
				if !matchProbe(expectation.probe, resp.StatusCode, bodyStr, resp.Header) {
					continue
				}

				version := extractVersion(expectation.probe, bodyStr)
				existing, ok := services[expectation.serviceName]
				if !ok {
					s.emitProgress(ScanProgressEvent{
						Type:    "matched",
						Host:    host,
						Port:    port,
						Service: expectation.serviceName,
						Probe:   expectation.displayProbe,
						Current: current,
						Total:   total,
					})
					existing = &serviceMatch{
						specificity:  expectation.probe.Specificity,
						version:      version,
						serverHeader: serverHdr,
						details:      bodyPreview,
						probes:       []string{expectation.displayProbe},
						defaultPort:  expectation.defaultPort,
					}
					services[expectation.serviceName] = existing
				} else {
					existing.probes = append(existing.probes, expectation.displayProbe)
					if expectation.probe.Specificity > existing.specificity {
						existing.specificity = expectation.probe.Specificity
						existing.details = bodyPreview
					}
					if version != "" && existing.version == "" {
						existing.version = version
					}
					if serverHdr != "" && existing.serverHeader == "" {
						existing.serverHeader = serverHdr
					}
				}
				existing.recordMatch(expectation.probe, expectation.defaultPort)
				if _, seen := matchedProbeSet[expectation.displayProbe]; !seen {
					matchedProbeSet[expectation.displayProbe] = struct{}{}
				}
				if bestServerHeader == "" && serverHdr != "" {
					bestServerHeader = serverHdr
				}
				if bestDetails == "" && bodyPreview != "" {
					bestDetails = bodyPreview
				}
			}
		}

		if len(services) > 0 {
			bestResults = services
			bestBaseURL = baseURL
			bestMatchedProbes = sortedKeys(matchedProbeSet)
			break
		}
		if timedOut {
			break
		}
		// After HTTPS attempts with no fingerprint match, retry plain HTTP on
		// the same port when probes failed due to TLS (e.g. HTTP service on 443).
		if scheme != "https" || !sawTLSError {
			break
		}
	}

	if timedOut {
		observation.TimedOut = true
		observation.Incomplete = true
		s.emitProgress(ScanProgressEvent{
			Type:    "timed_out",
			Host:    host,
			Port:    port,
			Current: current,
			Total:   total,
			Budget:  s.FingerprintTimeout,
		})
	}

	return buildObservation(host, port, bestBaseURL, bestResults, bestMatchedProbes, bestServerHeader, bestDetails, timedOut)
}

func matchProbe(probe HTTPProbe, statusCode int, body string, headers http.Header) bool {
	if probe.MatchStatus != 0 && statusCode != probe.MatchStatus {
		return false
	}
	if probe.MatchBody != "" && !strings.Contains(body, probe.MatchBody) {
		return false
	}
	if probe.MatchBodyNot != "" && strings.Contains(body, probe.MatchBodyNot) {
		return false
	}
	for key, want := range probe.MatchHeader {
		got := headers.Get(key)
		if !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
			return false
		}
	}
	return true
}

var regexCache sync.Map

func cachedRegexp(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

func extractVersion(probe HTTPProbe, body string) string {
	if probe.VersionRegex == "" {
		return ""
	}
	re, err := cachedRegexp(probe.VersionRegex)
	if err != nil {
		return ""
	}
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func uniqueStringsOrdered(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func defaultBaseURL(host string, port int) string {
	if prefersHTTPS(port) {
		return fmt.Sprintf("https://%s:%d", host, port)
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

func (s *Scanner) schemesForPort(port int) []string {
	if s != nil && s.PreferHTTPSPorts[port] {
		return []string{"https", "http"}
	}
	if prefersHTTPS(port) {
		return []string{"https", "http"}
	}
	return []string{"http"}
}

func requestPlanKey(method, path string, headers map[string]string, body string) string {
	keys := make([]string, 0, len(headers))
	normalizedValues := make(map[string]string, len(headers))
	for key, value := range headers {
		normalized := strings.ToLower(key)
		keys = append(keys, normalized)
		normalizedValues[normalized] = value
	}
	sort.Strings(keys)
	headerParts := make([]string, 0, len(keys))
	for _, key := range keys {
		headerParts = append(headerParts, key+"="+normalizedValues[key])
	}
	return strings.Join([]string{strings.ToUpper(strings.TrimSpace(method)), path, strings.Join(headerParts, "&"), body}, "\x00")
}

func requestPriority(portMatched bool, strength ProbeStrength) int {
	switch normalizedProbeStrength(strength) {
	case ProbeStrengthStrong:
		if portMatched {
			return 0
		}
		return 2
	case ProbeStrengthSupporting:
		if portMatched {
			return 1
		}
		return 4
	default:
		if portMatched {
			return 3
		}
		return 5
	}
}

func buildRequestPlans(probes []ServiceProbe, port int) []requestPlan {
	plansByKey := make(map[string]*requestPlan)
	order := make([]*requestPlan, 0)
	for _, serviceProbe := range probes {
		portMatched := serviceProbe.DefaultPort == port
		for _, probe := range serviceProbe.Probes {
			method := probe.Method
			if method == "" {
				method = "GET"
			}
			key := requestPlanKey(method, probe.Path, probe.Headers, probe.Body)
			plan, ok := plansByKey[key]
			if !ok {
				headers := make(map[string]string, len(probe.Headers))
				for k, v := range probe.Headers {
					headers[k] = v
				}
				plan = &requestPlan{
					method:       method,
					path:         probe.Path,
					headers:      headers,
					body:         probe.Body,
					priority:     requestPriority(portMatched, probe.Strength),
					displayProbe: probe.Path,
				}
				plansByKey[key] = plan
				order = append(order, plan)
			} else {
				priority := requestPriority(portMatched, probe.Strength)
				if priority < plan.priority {
					plan.priority = priority
				}
			}
			plan.expectations = append(plan.expectations, probeExpectation{
				serviceName:  serviceProbe.Name,
				defaultPort:  serviceProbe.DefaultPort,
				probe:        probe,
				portMatched:  portMatched,
				probeKey:     key,
				displayProbe: probe.Path,
			})
		}
	}

	sort.SliceStable(order, func(i, j int) bool {
		if order[i].priority != order[j].priority {
			return order[i].priority < order[j].priority
		}
		if order[i].path != order[j].path {
			return order[i].path < order[j].path
		}
		return order[i].method < order[j].method
	})

	plans := make([]requestPlan, 0, len(order))
	for _, plan := range order {
		plans = append(plans, *plan)
	}
	return plans
}

type serviceMatch struct {
	specificity  int
	version      string
	serverHeader string
	details      string
	probes       []string
	defaultPort  int
	strongHits   int
	supportHits  int
	genericHits  int
}

func hasStrongPortMatch(services map[string]*serviceMatch, port int) bool {
	for _, m := range services {
		if m.strongHits > 0 && m.defaultPort == port {
			return true
		}
	}
	return false
}

func normalizedProbeStrength(strength ProbeStrength) ProbeStrength {
	switch strength {
	case ProbeStrengthSupporting, ProbeStrengthGeneric:
		return strength
	default:
		return ProbeStrengthStrong
	}
}

func (m *serviceMatch) recordMatch(probe HTTPProbe, defaultPort int) {
	m.defaultPort = defaultPort
	switch normalizedProbeStrength(probe.Strength) {
	case ProbeStrengthStrong:
		m.strongHits++
	case ProbeStrengthSupporting:
		m.supportHits++
	case ProbeStrengthGeneric:
		m.genericHits++
	}
}

func classifyMatch(result *Result, match *serviceMatch, port int) {
	if result == nil || match == nil {
		return
	}

	defaultPortMatch := match.defaultPort != 0 && match.defaultPort == port
	nonGenericHits := match.strongHits + match.supportHits

	switch {
	case match.strongHits > 0:
		result.MatchKind = MatchKindConfirmed
		result.Confidence = "high"
	case nonGenericHits >= 2:
		result.MatchKind = MatchKindConfirmed
		if defaultPortMatch {
			result.Confidence = "high"
		} else {
			result.Confidence = "medium"
		}
	case match.supportHits > 0:
		result.MatchKind = MatchKindSuspected
		result.Confidence = "medium"
		if !defaultPortMatch {
			result.Ambiguity = "non_default_port_without_strong_corroboration"
		} else {
			result.Ambiguity = "supporting_match_only"
		}
	default:
		result.MatchKind = MatchKindSuspected
		result.Confidence = "low"
		if !defaultPortMatch {
			result.Ambiguity = "generic_match_on_non_default_port"
		} else {
			result.Ambiguity = "generic_match_only"
		}
	}
}

func matchKindRank(kind string) int {
	switch strings.TrimSpace(kind) {
	case MatchKindConfirmed:
		return 0
	case MatchKindSuspected:
		return 1
	case MatchKindAmbiguous:
		return 2
	default:
		return 3
	}
}

func buildResults(host string, port int, baseURL string, services map[string]*serviceMatch) []Result {
	if len(services) == 0 {
		return nil
	}
	var results []Result
	for name, m := range services {
		if m.specificity < MinSpecificityThreshold {
			continue
		}
		url := baseURL
		if url == "" {
			url = fmt.Sprintf("http://%s:%d", host, port)
		}
		results = append(results, Result{
			Host:         host,
			Port:         port,
			Service:      name,
			URL:          url,
			Specificity:  m.specificity,
			Version:      m.version,
			ServerHeader: m.serverHeader,
			Details:      m.details,
			Probes:       uniqueStringsOrdered(m.probes),
		})
	}
	if len(results) == 0 {
		return nil
	}

	proxyLikely := len(results) >= 3
	confirmedCount := 0
	for i := range results {
		classifyMatch(&results[i], services[results[i].Service], port)
		if results[i].MatchKind == MatchKindConfirmed {
			confirmedCount++
		}
	}

	switch {
	case proxyLikely:
		for i := range results {
			results[i].ProxyLikely = true
			results[i].MatchKind = MatchKindAmbiguous
			results[i].Ambiguity = "proxy_likely"
		}
	case len(results) > 1 && confirmedCount == 0:
		for i := range results {
			results[i].MatchKind = MatchKindAmbiguous
			results[i].Ambiguity = "no_strong_winner"
		}
	case len(results) > 1 && confirmedCount > 1:
		for i := range results {
			results[i].MatchKind = MatchKindAmbiguous
			results[i].Ambiguity = "multiple_confirmed_matches"
		}
	}

	// Sort by specificity descending for deterministic output
	sort.Slice(results, func(i, j int) bool {
		if matchKindRank(results[i].MatchKind) != matchKindRank(results[j].MatchKind) {
			return matchKindRank(results[i].MatchKind) < matchKindRank(results[j].MatchKind)
		}
		if results[i].Specificity != results[j].Specificity {
			return results[i].Specificity > results[j].Specificity
		}
		return results[i].Service < results[j].Service
	})
	return results
}

func observationFingerprintStatus(results []Result, candidateServices []string) string {
	switch {
	case len(results) > 0:
		hasConfirmed := false
		hasSuspected := false
		hasAmbiguous := false
		for _, result := range results {
			switch result.MatchKind {
			case MatchKindConfirmed:
				hasConfirmed = true
			case MatchKindSuspected:
				hasSuspected = true
			case MatchKindAmbiguous:
				hasAmbiguous = true
			}
		}
		switch {
		case hasAmbiguous:
			return MatchKindAmbiguous
		case hasConfirmed:
			return MatchKindConfirmed
		case hasSuspected:
			return MatchKindSuspected
		default:
			return "identified"
		}
	case len(candidateServices) > 0:
		return "candidate"
	default:
		return "unidentified"
	}
}

func buildObservation(host string, port int, baseURL string, services map[string]*serviceMatch, matchedProbes []string, serverHeader, details string, timedOut bool) PortObservation {
	observation := PortObservation{
		Host:      host,
		Port:      port,
		PortState: "open",
		URL:       baseURL,
	}
	if observation.URL == "" {
		observation.URL = defaultBaseURL(host, port)
	}
	if timedOut {
		observation.TimedOut = true
		observation.Incomplete = true
	}

	results := buildResults(host, port, baseURL, services)
	observation.Results = results

	candidates := make([]string, 0)
	if len(services) > 0 {
		for name := range services {
			found := false
			for _, result := range results {
				if result.Service == name {
					found = true
					break
				}
			}
			if !found {
				candidates = append(candidates, name)
			}
		}
		sort.Strings(candidates)
	}

	observation.CandidateServices = candidates
	observation.MatchedProbes = uniqueStringsOrdered(matchedProbes)
	observation.FingerprintStatus = observationFingerprintStatus(results, candidates)
	observation.ServerHeader = serverHeader
	observation.Details = details
	if observation.ServerHeader == "" {
		for _, result := range results {
			if result.ServerHeader != "" {
				observation.ServerHeader = result.ServerHeader
				break
			}
		}
	}
	if observation.Details == "" {
		for _, result := range results {
			if result.Details != "" {
				observation.Details = result.Details
				break
			}
		}
	}

	// Banner fallback: when no AI probe matched and the port is not timed-out,
	// derive a low-confidence identity from the Server header so the operator
	// can see what is actually running on the port.
	if len(observation.Results) == 0 && len(observation.CandidateServices) == 0 && !observation.TimedOut && observation.ServerHeader != "" {
		banner := parseServerBanner(observation.ServerHeader)
		if banner != "" {
			observation.Results = []Result{{
				Host:         host,
				Port:         port,
				Service:      banner,
				URL:          observation.URL,
				Specificity:  5,
				ServerHeader: observation.ServerHeader,
				Confidence:   "banner",
				MatchKind:    MatchKindBanner,
				Probes:       []string{"Server header"},
			}}
			observation.FingerprintStatus = MatchKindBanner
		}
	}

	// Port-heuristic fallback: well-known non-HTTP service ports that cannot
	// be identified by HTTP probes. Tag them as suspected so the assessment
	// pipeline can attempt module enumeration.
	if len(observation.Results) == 0 && !observation.TimedOut {
		if heuristicService := portHeuristicService(port); heuristicService != "" {
			observation.Results = []Result{{
				Host:        host,
				Port:        port,
				Service:     heuristicService,
				URL:         observation.URL,
				Specificity: 10,
				Confidence:  "port-heuristic",
				MatchKind:   MatchKindPortHeuristic,
				Probes:      []string{"well-known port"},
			}}
			observation.FingerprintStatus = MatchKindPortHeuristic
		}
	}

	return observation
}

// portHeuristicService maps well-known non-HTTP ports to service names when
// no HTTP probe matched. This allows the assessment pipeline to attempt
// module enumeration for services that use non-HTTP protocols.
func portHeuristicService(port int) string {
	switch port {
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	default:
		return ""
	}
}

func preHTTPPortHeuristicService(port int) string {
	switch port {
	case 5432, 6379:
		return portHeuristicService(port)
	default:
		return ""
	}
}

func portHeuristicObservation(host string, port int, service string) PortObservation {
	return PortObservation{
		Host:              host,
		Port:              port,
		PortState:         "open",
		URL:               defaultBaseURL(host, port),
		FingerprintStatus: MatchKindPortHeuristic,
		CandidateServices: []string{service},
		MatchedProbes:     []string{"well-known port"},
		Results: []Result{{
			Host:        host,
			Port:        port,
			Service:     service,
			URL:         defaultBaseURL(host, port),
			Specificity: 10,
			Confidence:  "port-heuristic",
			MatchKind:   MatchKindPortHeuristic,
			Probes:      []string{"well-known port"},
		}},
	}
}

// parseServerBanner extracts a clean, human-readable service name from a
// Server header value.  e.g. "nginx/1.18.0" → "nginx",
// "Apache/2.4.41 (Ubuntu)" → "apache", "Python/3.11 aiohttp/3.9.5" → "aiohttp".
func parseServerBanner(header string) string {
	if header == "" {
		return ""
	}

	// Identify product/version tokens (space-separated tokens containing '/').
	parts := strings.Fields(header)
	var productTokens []string
	for _, p := range parts {
		if strings.Contains(p, "/") && !strings.HasPrefix(p, "(") {
			productTokens = append(productTokens, p)
		}
	}

	var name string
	switch len(productTokens) {
	case 0:
		// No version info: "uvicorn", "Gordian Embedded"
		name = header
	case 1:
		// Single product/version — take everything before the first '/'
		// in the original header so multi-word names are preserved.
		// e.g. "Oracle XML DB/Oracle9i ..." → "Oracle XML DB"
		idx := strings.Index(header, "/")
		name = strings.TrimSpace(header[:idx])
	default:
		// Multiple products: "Python/3.11 aiohttp/3.9.5" → "aiohttp"
		last := productTokens[len(productTokens)-1]
		if idx := strings.Index(last, "/"); idx > 0 {
			name = last[:idx]
		} else {
			name = last
		}
	}

	// Strip trailing semicolons from compound headers
	name = strings.TrimRight(name, ";")
	// Strip parenthesized version suffixes: "Jetty(9.2.11.v20150529)" → "Jetty"
	if idx := strings.Index(name, "("); idx > 0 {
		name = strings.TrimSpace(name[:idx])
	}
	if name == "" {
		return strings.ToLower(header)
	}
	return strings.ToLower(name)
}

// ScanRange scans multiple hosts and ports concurrently.
func (s *Scanner) ScanRange(hosts []string, ports []int) []PortObservation {
	var (
		observations []PortObservation
		mu           sync.Mutex
		wg           sync.WaitGroup
		sem          = make(chan struct{}, s.Concurrency)
		started      int
		completed    int
		total        = len(hosts) * len(ports)
	)

outer:
	for _, host := range hosts {
		for _, port := range ports {
			if s.Context != nil && s.Context.Err() != nil {
				break outer
			}
			wg.Add(1)
			sem <- struct{}{}

			if s.Context != nil && s.Context.Err() != nil {
				wg.Done()
				break outer
			}
			mu.Lock()
			started++
			probeCur := started
			mu.Unlock()

			go func(h string, p int) {
				defer wg.Done()
				defer func() { <-sem }()

				found := s.scanHost(h, p, probeCur, total)
				mu.Lock()
				if found.Port != 0 {
					observations = append(observations, found)
				}
				completed++
				cur := completed
				mu.Unlock()

				s.emitProgress(ScanProgressEvent{Type: "done", Host: h, Port: p, Current: cur, Total: total})
			}(host, port)
		}
	}

	wg.Wait()
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].Host != observations[j].Host {
			return observations[i].Host < observations[j].Host
		}
		return observations[i].Port < observations[j].Port
	})
	return observations
}

func (s *Scanner) requestContext() context.Context {
	if s.Context != nil {
		return s.Context
	}
	return context.Background()
}

func (s *Scanner) emitProgress(event ScanProgressEvent) {
	if s.OnProgress != nil {
		s.OnProgress(event)
	}
}

func (s *Scanner) dialContext(addr string) (net.Conn, error) {
	if s.DialContext != nil {
		return s.DialContext(s.requestContext(), "tcp", addr)
	}
	dt := s.DialTimeout
	if dt <= 0 {
		dt = 3 * time.Second
	}
	dialer := &net.Dialer{Timeout: dt}
	return dialer.DialContext(s.requestContext(), "tcp", addr)
}

func prefersHTTPS(port int) bool {
	switch port {
	case 443, 6443, 8443, 9443:
		return true
	default:
		return false
	}
}

func isTLSProbeError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		var tlsRecordErr *tls.RecordHeaderError
		if errors.As(urlErr.Err, &tlsRecordErr) {
			return true
		}
		var certErr *tls.CertificateVerificationError
		if errors.As(urlErr.Err, &certErr) {
			return true
		}
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "tls") ||
		strings.Contains(lower, "server gave http response to https client") ||
		strings.Contains(lower, "malformed http response")
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// maxCIDRHostBits is the maximum number of host bits allowed for CIDR
// expansion. Both EstimateCIDRSize and ExpandCIDR enforce this limit so
// the estimate check in scan-network never passes a range that ExpandCIDR
// would reject.
const maxCIDRHostBits = 20

// DefaultUserAgent is used on fingerprint probe requests when no other
// User-Agent is configured, to avoid rejection by services and WAFs that
// require the header.
const DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"

// MinSpecificityThreshold is the minimum specificity for a fingerprint
// result to be included in multi-result output.
const MinSpecificityThreshold = 30

// BuiltinProbes returns all built-in service detection probes
func BuiltinProbes() []ServiceProbe {
	return []ServiceProbe{
		{
			Name:        "ollama",
			DefaultPort: 11434,
			Probes: []HTTPProbe{
				{Path: "/", MatchStatus: 200, MatchBody: "Ollama is running", Specificity: 100},
				// Exclude Ray's dashboard /api/version ({"version":"4","ray_version":"..."}),
				// which also carries a bare "version" key. A real Ollama never returns
				// "ray_version", so this can't suppress genuine Ollama detection.
				{Path: "/api/version", MatchStatus: 200, MatchBody: `"version"`, MatchBodyNot: "ray_version", VersionRegex: `"version"\s*:\s*"([^"]+)"`, Specificity: 95},
				{Path: "/api/tags", MatchStatus: 200, MatchBody: `"models"`, MatchBodyNot: "chromadb", Specificity: 85},
			},
		},
		{
			Name:        "chromadb",
			DefaultPort: 8000,
			Probes: []HTTPProbe{
				{Path: "/api/v2/heartbeat", MatchStatus: 200, MatchBody: "nanosecond heartbeat", Specificity: 90},
				{Path: "/api/v1/heartbeat", MatchStatus: 200, MatchBody: "nanosecond heartbeat", Specificity: 85},
			},
		},
		{
			Name:        "vllm",
			DefaultPort: 8000,
			Probes: []HTTPProbe{
				{Path: "/v1/models", MatchStatus: 200, MatchBody: `"data":`, Specificity: 40, Strength: ProbeStrengthGeneric},
			},
		},
		{
			Name:        "litellm",
			DefaultPort: 4000,
			Probes: []HTTPProbe{
				{Path: "/health", MatchStatus: 200, MatchBody: "litellm", Specificity: 85},
				{Path: "/health/liveliness", MatchStatus: 200, MatchBody: "alive", Specificity: 80},
				{Path: "/v1/models", MatchStatus: 200, MatchBody: `"data":`, Specificity: 25, Strength: ProbeStrengthGeneric},
			},
		},
		{
			Name:        "lmstudio",
			DefaultPort: 1234,
			Probes: []HTTPProbe{
				{Path: "/v1/models", MatchStatus: 200, MatchBody: `"data":`, Specificity: 40, Strength: ProbeStrengthGeneric},
			},
		},
		{
			Name:        "localai",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{Path: "/v1/models", MatchStatus: 200, MatchBody: `"data":`, Specificity: 35, Strength: ProbeStrengthGeneric},
				{Path: "/readyz", MatchStatus: 200, MatchBody: "ok", Specificity: 40, Strength: ProbeStrengthSupporting},
			},
		},
		{
			Name:        "weaviate",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{Path: "/v1/meta", MatchStatus: 200, MatchBody: `"version"`, VersionRegex: `"version"\s*:\s*"([^"]+)"`, Specificity: 90},
				{Path: "/v1/schema", MatchStatus: 200, MatchBody: "classes", Specificity: 85},
			},
		},
		{
			Name:        "qdrant",
			DefaultPort: 6333,
			Probes: []HTTPProbe{
				{Path: "/collections", MatchStatus: 200, MatchBody: `"result"`, MatchHeader: map[string]string{"Content-Type": "application/json"}, Specificity: 85},
				{Path: "/", MatchStatus: 200, MatchBody: "qdrant", Specificity: 70},
			},
		},
		{
			Name:        "milvus",
			DefaultPort: 19530,
			Probes: []HTTPProbe{
				{Method: "POST", Path: "/v2/vectordb/collections/list", Body: "{}", Headers: map[string]string{"Content-Type": "application/json"}, MatchStatus: 200, MatchBody: "collection_names", Specificity: 80},
				{Method: "POST", Path: "/v2/vectordb/collections/list", Body: "{}", Headers: map[string]string{"Content-Type": "application/json"}, MatchStatus: 200, MatchBody: "data", Specificity: 70},
				{Path: "/v1/health", MatchStatus: 200, MatchBody: "ok", Specificity: 40},
			},
		},
		{
			Name:        "jupyter",
			DefaultPort: 8888,
			Probes: []HTTPProbe{
				{Path: "/api", MatchStatus: 200, MatchBody: `"jupyter_server"`, Specificity: 90},
				{Path: "/api", MatchStatus: 200, MatchBody: `"notebook"`, Specificity: 75},
				{Path: "/", MatchStatus: 200, MatchBody: "jupyter", Specificity: 50},
			},
		},
		{
			Name:        "mlflow",
			DefaultPort: 5000,
			Probes: []HTTPProbe{
				{Path: "/api/2.0/mlflow/experiments/search", MatchStatus: 200, MatchBody: "experiment", Specificity: 90},
				{Path: "/api/2.0/mlflow/registered-models/search", MatchStatus: 200, MatchBody: "registered_models", Specificity: 85},
			},
		},
		{
			Name:        "gradio",
			DefaultPort: 7860,
			Probes: []HTTPProbe{
				{Path: "/info", MatchStatus: 200, MatchBody: `"version"`, VersionRegex: `"version"\s*:\s*"([^"]+)"`, Specificity: 60},
				{Path: "/", MatchStatus: 200, MatchBody: "gradio", Specificity: 50},
			},
		},
		{
			Name:        "bentoml",
			DefaultPort: 3000,
			Probes: []HTTPProbe{
				{Path: "/docs.json", MatchStatus: 200, MatchBody: "openapi", Specificity: 60},
				{Path: "/metrics", MatchStatus: 200, MatchBody: "bentoml", Specificity: 58, Strength: ProbeStrengthSupporting},
				{Path: "/healthz", MatchStatus: 200, Specificity: 40},
			},
		},
		{
			Name:        "streamlit",
			DefaultPort: 8501,
			Probes: []HTTPProbe{
				{Path: "/_stcore/health", MatchStatus: 200, MatchBody: "ok", Specificity: 90},
			},
		},
		{
			Name:        "ray",
			DefaultPort: 8265,
			Probes: []HTTPProbe{
				{Path: "/api/version", MatchStatus: 200, MatchBody: "ray", VersionRegex: `"ray_version"\s*:\s*"([^"]+)"`, Specificity: 85},
			},
		},
		{
			Name:        "open-webui",
			DefaultPort: 3000,
			Probes: []HTTPProbe{
				{Path: "/", MatchStatus: 200, MatchBody: "Open WebUI", Specificity: 80},
			},
		},
		{
			Name:        "mcp-sse",
			DefaultPort: 3000,
			Probes: []HTTPProbe{
				{
					// Modern Streamable HTTP transport (official SDK default at /mcp).
					// Requires the text/event-stream Accept header or FastMCP replies
					// 406; the initialize result is SSE-framed but still carries
					// serverInfo in the body.
					Method: "POST", Path: "/mcp",
					Headers:     map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
					Body:        `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"aipostex","version":"fingerprint"}},"id":1}`,
					MatchStatus: 200, MatchBody: "serverInfo", Specificity: 95,
				},
				{
					// Legacy SSE POST channel.
					Method: "POST", Path: "/message",
					Headers:     map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
					Body:        `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"aipostex","version":"fingerprint"}},"id":1}`,
					MatchStatus: 200, MatchBody: "serverInfo", Specificity: 95,
				},
			},
		},
		{
			Name:        "mcp-inspector",
			DefaultPort: 6274,
			// Fingerprint on the inspector's own API (servers/tools), NOT a "/" body
			// substring: a docs/blog/vendor page that merely names "MCP Inspector" 200s on
			// "/" and would false-match. The API endpoints are app-specific.
			Probes: []HTTPProbe{
				{Path: "/api/servers", MatchStatus: 200, MatchBody: "transportType", Specificity: 97},
				{Path: "/api/tools", MatchStatus: 200, MatchBody: "toolName", Specificity: 92},
			},
		},
		{
			Name:        "mcpjam-inspector",
			DefaultPort: 6274,
			Probes: []HTTPProbe{
				{Path: "/", MatchStatus: 200, MatchBody: "MCPJam Inspector", Specificity: 95},
				{Path: "/api/servers", MatchStatus: 200, MatchBody: "serverUrl", Specificity: 97},
				{Path: "/", MatchStatus: 200, MatchBody: "MCPJam", Specificity: 80},
			},
		},
		{
			Name:        "openai-compatible",
			DefaultPort: 8000,
			Probes: []HTTPProbe{
				{Path: "/v1/models", MatchStatus: 200, MatchBody: `"data":`, Specificity: 20, Strength: ProbeStrengthGeneric},
			},
		},
		{
			Name:        "triton",
			DefaultPort: 8000,
			Probes: []HTTPProbe{
				{Path: "/v2/health/ready", MatchStatus: 200, Specificity: 70, Strength: ProbeStrengthSupporting},
				{Path: "/v2/models", MatchStatus: 200, MatchBody: "models", Specificity: 85},
			},
		},
		{
			Name:        "torchserve",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{Path: "/ping", MatchStatus: 200, MatchBody: "Healthy", Specificity: 80},
				{Path: "/models", MatchStatus: 200, MatchBody: "models", Specificity: 75},
			},
		},
		{
			Name:        "torchserve-mgmt",
			DefaultPort: 8081,
			Probes: []HTTPProbe{
				{Path: "/models", MatchStatus: 200, MatchBody: "models", Specificity: 75},
			},
		},
		{
			Name:        "tfserving",
			DefaultPort: 8501,
			Probes: []HTTPProbe{
				{Path: "/v1/models", MatchStatus: 200, MatchBody: "model_version_status", Specificity: 90},
			},
		},
		{
			Name:        "hf-tgi",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				// Match model_pipeline_tag (TGI-specific: "text-generation"), NOT model_id — a
				// bare model_id is also present in TEI's /info, so matching it tags every
				// embeddings server as TGI too and routes hf-token replays to a `generate` that
				// 404s. model_pipeline_tag cleanly separates TGI (generation) from TEI (model_type).
				{Path: "/info", MatchStatus: 200, MatchBody: "model_pipeline_tag", Specificity: 85},
			},
		},
		{
			Name:        "hf-tei",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{Path: "/info", MatchStatus: 200, MatchBody: "model_type", Specificity: 85},
			},
		},
		{
			Name:        "langserve",
			DefaultPort: 8000,
			Probes: []HTTPProbe{
				{Path: "/docs", MatchStatus: 200, MatchBody: "LangServe", Specificity: 80},
			},
		},
		{
			Name:        "kubeflow",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{Path: "/pipeline/", MatchStatus: 200, MatchBody: "pipeline", Specificity: 75},
			},
		},
		{
			Name:        "a2a",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{Path: "/.well-known/agent-card.json", MatchStatus: 200, MatchBody: `"skills"`, Specificity: 90},
				{Path: "/.well-known/agent.json", MatchStatus: 200, MatchBody: `"name"`, Specificity: 85, Strength: ProbeStrengthSupporting},
			},
		},
		{
			Name:        "wandb",
			DefaultPort: 8080,
			Probes: []HTTPProbe{
				{
					Method: "POST", Path: "/graphql",
					Headers: map[string]string{"Content-Type": "application/json"},
					Body:    `{"query":"query Viewer { viewer { username entity } }"}`,
					// `"viewer":` matches a real wandb viewer object; a non-wandb GraphQL
					// endpoint that 200s with "Cannot query field 'viewer'" won't contain it.
					MatchStatus: 200, MatchBody: `"viewer":`, Specificity: 90,
				},
				{Path: "/healthz", MatchStatus: 200, MatchBody: "wandb", Specificity: 70, Strength: ProbeStrengthSupporting},
			},
		},
		{
			Name:        "kube-apiserver",
			DefaultPort: 6443,
			Probes: []HTTPProbe{
				// Anonymous /version is allowed on misconfigured/open clusters and
				// carries the gitVersion (e.g. v1.31.5+k3s1).
				{Path: "/version", MatchStatus: 200, MatchBody: `"gitVersion"`, VersionRegex: `"gitVersion"\s*:\s*"([^"]+)"`, Specificity: 95},
				// A default-secure apiserver rejects anonymous reads with a Status
				// object — still a positive kube-apiserver identification.
				{Path: "/version", MatchStatus: 401, MatchBody: "Unauthorized", Specificity: 82, Strength: ProbeStrengthSupporting},
				// Anonymous API discovery on an open cluster returns APIVersions.
				{Path: "/api", MatchStatus: 200, MatchBody: `"APIVersions"`, Specificity: 88, Strength: ProbeStrengthSupporting},
			},
		},
	}
}

// ExpandCIDR expands a CIDR notation to individual IPs
// EstimateCIDRSize returns the number of usable host addresses in the given
// CIDR without allocating. Single hosts return 1.
func EstimateCIDRSize(cidr string) (int, error) {
	if !strings.Contains(cidr, "/") {
		return 1, nil
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	ones, bits := ipnet.Mask.Size()
	if bits == 0 || ones < 0 {
		return 0, fmt.Errorf("invalid cidr mask")
	}
	hostBits := bits - ones
	if hostBits > maxCIDRHostBits {
		return 0, fmt.Errorf("CIDR range too large: /%d (%d host bits, max 2^%d addresses per target)", ones, hostBits, maxCIDRHostBits)
	}
	total := 1 << uint(hostBits) //nolint:gosec // hostBits is bounded by maxCIDRHostBits check above
	if total > 2 {
		total -= 2
	}
	return total, nil
}

func ExpandCIDR(cidr string) ([]string, error) {
	// Single host
	if !strings.Contains(cidr, "/") {
		return []string{cidr}, nil
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, bits := ipnet.Mask.Size()
	if bits == 0 || ones < 0 {
		return nil, fmt.Errorf("invalid cidr mask")
	}
	if bits-ones > maxCIDRHostBits {
		return nil, fmt.Errorf("CIDR range too large: %s (max 2^%d addresses per target)", cidr, maxCIDRHostBits)
	}

	var ips []string
	masked := ip.Mask(ipnet.Mask)
	current := append(net.IP(nil), masked...)
	for ipnet.Contains(current) {
		ips = append(ips, current.String())
		incrementIP(current)
	}

	// Remove network and broadcast for /24+
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
