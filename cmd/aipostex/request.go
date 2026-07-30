package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/output"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/report"
)

// The operator console `request` primitive: issue an arbitrary HTTP operation
// against a service THROUGH the tool. The operator drives — nothing runs on its
// own. The tool handles transport, injects whatever auth the operator supplies
// (a --header / --api-key, or NONE for an unauthenticated service), prints the
// raw response, and captures it as a finding so secrets in the response feed the
// loot index. This is NOT a curl the tool emits for you; it is the tool making
// the request, session-integrated and loot-capturing. See the per-module verbs
// (`<module> request …`) for the same primitive with the module's target/auth.

// Shared flags for both the top-level `request` command and the per-module
// `request` verbs. Only one command runs per invocation, so sharing is safe.
var (
	requestTarget      string
	requestHeaders     []string
	requestAPIKey      string
	requestBody        string
	requestBodyFile    string
	requestContentType string
	requestRaw         bool
)

var requestCmd = &cobra.Command{
	Use:   "request METHOD PATH-OR-URL",
	Short: "Issue an arbitrary HTTP request to a service (operator console)",
	Long: `Issue an arbitrary HTTP request to a service through the tool.

The operator supplies the method and path (or a full URL); the tool makes the
request, prints the raw response, and captures it as a finding so any secrets in
the response are extracted into the loot index. Works authenticated (supply
--header or --api-key) or unauthenticated (supply neither — many AI services are
exposed without auth). Nothing executes on its own: you issue every request.

  # unauthenticated read
  aipostex request -t http://10.0.20.20:8265 GET /api/jobs/

  # authenticated, with a looted key
  aipostex request -t http://10.0.20.20:4000 GET /v1/models \
    --api-key sk-litellm-lab-auth-key-FAKE123

  # POST a body (Content-Type defaults to application/json)
  aipostex request -t http://10.0.20.30:5000 POST /api/2.0/mlflow/experiments/search \
    --header 'Authorization: Basic cmF5LXBpcGVsaW5lOi4uLg==' --body '{"max_results":10}'

Per service module, the same primitive reuses that module's --target/--header/--api-key:
  aipostex mlflow -t http://10.0.20.30:5000 request GET /api/2.0/mlflow/experiments/search`,
	GroupID: operationsGroupID,
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		method, path := args[0], args[1]
		target := strings.TrimSpace(requestTarget)
		if target == "" && !isFullRequestURL(path) {
			return missingFlagError("target", formatCommandExample("request -t http://127.0.0.1:8000 GET /"))
		}
		headers, err := exploitcommon.ParseHeaderFlags(requestHeaders)
		if err != nil {
			return err
		}
		// Top-level --api-key uses the Bearer convention (the common shape for the
		// AI services this tool targets); use --header for any other auth scheme.
		if key := strings.TrimSpace(requestAPIKey); key != "" && headers.Get("Authorization") == "" {
			headers.Set("Authorization", "Bearer "+key)
		}
		return runConsoleRequest(cmd.Context(), consoleRequestParams{
			source:  report.SourceRequest,
			module:  "request",
			target:  target,
			method:  method,
			path:    path,
			headers: headers,
		})
	},
}

type consoleRequestParams struct {
	source  string
	module  string
	target  string
	method  string
	path    string
	headers http.Header
}

// runConsoleRequest performs one operator-issued HTTP request and records it.
func runConsoleRequest(ctx context.Context, p consoleRequestParams) error {
	fullURL, err := buildRequestURL(p.target, p.path)
	if err != nil {
		return err
	}
	body, contentType, err := resolveRequestBody()
	if err != nil {
		return err
	}
	headers := p.headers
	if headers == nil {
		headers = make(http.Header)
	}
	if len(body) > 0 {
		if contentType != "" {
			headers.Set("Content-Type", contentType)
		} else if headers.Get("Content-Type") == "" {
			headers.Set("Content-Type", "application/json")
		}
	}

	client, err := cfg.NewHTTPClient()
	if err != nil {
		return err
	}

	method := strings.ToUpper(strings.TrimSpace(p.method))
	if method == "" {
		method = http.MethodGet
	}
	// A state-changing method (POST/PUT/PATCH/DELETE) is a mutation — gate it behind
	// --force-exploit like every other mutating action, and grade it influenced (not a read).
	if requestMethodMutates(method) {
		if err := requireForceExploit(p.module + " request " + method); err != nil {
			return err
		}
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := exploitcommon.NewRequestWithContext(ctx, method, fullURL, headers, reader)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		// No response received: surface the transport error to the operator; no
		// finding (there is nothing to capture).
		return fmt.Errorf("%s %s failed: %w", method, fullURL, err)
	}
	defer resp.Body.Close()
	respBody, truncated, err := exploitcommon.ReadAllCapped(resp.Body, exploitcommon.DefaultResponseBodyLimitBytes)
	if err != nil {
		return fmt.Errorf("reading response from %s: %w", fullURL, err)
	}

	// Interactive payoff: in the console view, print the raw response to stdout
	// (so the operator can pipe/grep it) while the finding block renders to
	// stderr. Structured formats keep stdout clean for the finding itself.
	if cfg.Format == "console" {
		note := ""
		if truncated {
			note = " (truncated)"
		}
		fmt.Fprintf(stderrWriter, "→ %s %d · %d bytes%s\n", method, resp.StatusCode, len(respBody), note)
		if len(respBody) > 0 {
			// Pretty-print a single-line JSON body by default so the operator reads
			// structured output, not a run-on blob; --raw keeps the exact bytes.
			body := respBody
			if !requestRaw {
				if pretty := output.IndentJSON(string(respBody)); pretty != string(respBody) {
					body = []byte(pretty)
				}
			}
			os.Stdout.Write(body)
			if !bytes.HasSuffix(body, []byte("\n")) {
				fmt.Fprintln(os.Stdout)
			}
		}
	}

	mutating := requestMethodMutates(method)
	stage, landed, severity := classifyConsoleRequest(method, resp.StatusCode)
	title := fmt.Sprintf("request %s %s → %d", method, requestPathLabel(p.path, fullURL), resp.StatusCode)
	desc := fmt.Sprintf("Operator-issued %s request to %s returned HTTP %d (%d bytes); response captured as evidence.", method, fullURL, resp.StatusCode, len(respBody))
	finding := newExploitFinding(
		p.source,
		requestFindingTarget(p.target, fullURL),
		title,
		severity,
		desc,
		map[string]interface{}{
			"module":          p.module,
			"action":          "request",
			"mutating":        mutating,
			"request_method":  method,
			"request_url":     fullURL,
			"response_status": resp.StatusCode,
		},
	)
	finding.Evidence = string(respBody)
	if truncated {
		finding.Metadata["evidence_truncated"] = true
		finding.Metadata["evidence_limit_bytes"] = exploitcommon.DefaultResponseBodyLimitBytes
	}
	finding.Metadata = applyStageLanded(finding.Metadata, stage, landed, p.module+"-request", "request")

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              p.module,
		Action:              "request",
		ResourcesEnumerated: 1,
		Mutating:            mutating,
	})
}

// requestMethodMutates reports whether an HTTP method is state-changing. Such a request is
// gated behind --force-exploit and graded influenced (accepted mutation), never read-confirmed.
func requestMethodMutates(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// classifyConsoleRequest labels a manual request honestly by METHOD and status. A safe method
// (GET/HEAD/OPTIONS) on 2xx confirms the operator read the service (read-confirmed). A
// state-changing method on 2xx is an accepted mutation whose downstream effect the tool cannot
// verify (impact/influenced). Non-2xx is only reachability. Severity stays low: the value is the
// captured response + looted secrets, not a vuln claim.
func classifyConsoleRequest(method string, status int) (stage, landed, severity string) {
	ok := status >= 200 && status < 300
	if requestMethodMutates(method) {
		if ok {
			return "impact", "influenced", report.SeverityHigh
		}
		return "recon", "reachable", report.SeverityInfo
	}
	if ok {
		return "access", "read-confirmed", report.SeverityInfo
	}
	return "recon", "reachable", report.SeverityInfo
}

// resolveRequestBody reads the request body from --body (literal), --body-file
// (path, or "-" for stdin), and returns the operator-supplied Content-Type.
func resolveRequestBody() (body []byte, contentType string, err error) {
	contentType = strings.TrimSpace(requestContentType)
	switch {
	case strings.TrimSpace(requestBodyFile) == "-":
		body, err = io.ReadAll(os.Stdin)
	case strings.TrimSpace(requestBodyFile) != "":
		body, err = os.ReadFile(requestBodyFile)
	case requestBody != "":
		body = []byte(requestBody)
	}
	if err != nil {
		return nil, "", fmt.Errorf("reading request body: %w", err)
	}
	return body, contentType, nil
}

func buildRequestURL(target, path string) (string, error) {
	if isFullRequestURL(path) {
		return path, nil
	}
	base := exploitcommon.NormalizeTarget(target)
	if base == "" {
		return "", missingFlagError("target", formatCommandExample("request -t http://127.0.0.1:8000 GET /"))
	}
	if path == "" {
		return base, nil
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path, nil
}

func isFullRequestURL(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// requestPathLabel keeps titles compact: the path for the common case, the full
// URL when the operator passed one directly.
func requestPathLabel(path, fullURL string) string {
	if isFullRequestURL(path) {
		return fullURL
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func requestFindingTarget(target, fullURL string) string {
	if t := exploitcommon.NormalizeTarget(target); t != "" {
		return t
	}
	return fullURL
}

// bindRequestBodyFlags adds the body flags shared by the top-level command and
// every per-module `request` verb.
func bindRequestBodyFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&requestBody, "body", "", "Request body (literal string)")
	cmd.Flags().StringVar(&requestBodyFile, "body-file", "", "Read request body from a file, or '-' for stdin")
	cmd.Flags().StringVar(&requestContentType, "content-type", "", "Content-Type header for the body (default application/json when a body is present)")
	cmd.Flags().BoolVar(&requestRaw, "raw", false, "Print the exact response body (default pretty-prints JSON)")
}

// moduleRequestBinding wires a per-module `request` verb to that module's target
// and auth. The verb inherits the module's persistent --target/--header/--api-key
// flags, so the operator who just ran `<module> enum -t URL …` can immediately
// `<module> request METHOD /path` without re-supplying them.
type moduleRequestBinding struct {
	cmd     *cobra.Command
	module  string
	source  string
	target  func() string
	headers func() (http.Header, error)
	example string
}

// registerModuleConsoleRequests attaches a `request` verb to each HTTP service
// module. Protocol/stateful services (jupyter kernel, mcp, a2a) get the
// interactive `shell` later; k8s's console is the kubectl kubeconfig handoff.
func registerModuleConsoleRequests() {
	bindings := []moduleRequestBinding{
		{
			cmd: mlflowCmd, module: "mlflow", source: report.SourceMLflow,
			target:  func() string { return mlflowTarget },
			headers: func() (http.Header, error) { return exploitcommon.ParseHeaderFlags(mlflowHeaders) },
			example: "mlflow -t http://127.0.0.1:5000 request GET /api/2.0/mlflow/experiments/search",
		},
		{
			cmd: rayCmd, module: "ray", source: report.SourceRay,
			target:  func() string { return rayTarget },
			headers: func() (http.Header, error) { return exploitcommon.ParseHeaderFlags(rayHeaders) },
			example: "ray -t http://127.0.0.1:8265 request GET /api/jobs/",
		},
		{
			cmd: ollamaCmd, module: "ollama", source: report.SourceOllama,
			target:  func() string { return ollamaTarget },
			headers: func() (http.Header, error) { return exploitcommon.ParseHeaderFlags(ollamaHeaders) },
			example: "ollama -t http://127.0.0.1:11434 request GET /api/tags",
		},
		{
			cmd: openAICompatCmd, module: "openai-compat", source: report.SourceOpenAICompat,
			target:  func() string { return openAICompatTarget },
			headers: bearerHeaderResolver(func() []string { return openAICompatHeaders }, func() string { return openAICompatAPIKey }),
			example: "openai-compat -t http://127.0.0.1:8000 request GET /v1/models",
		},
		{
			cmd: litellmCmd, module: "litellm", source: report.SourceLiteLLM,
			target:  func() string { return litellmTarget },
			headers: bearerHeaderResolver(func() []string { return litellmHeaders }, func() string { return litellmAPIKey }),
			example: "litellm -t http://127.0.0.1:4000 request GET /v1/models",
		},
		{
			cmd: vectordbCmd, module: "vectordb", source: report.SourceVectorDB,
			target: func() string { return vdbTarget },
			headers: func() (http.Header, error) {
				headers, err := exploitcommon.ParseHeaderFlags(vdbHeaders)
				if err != nil {
					return nil, err
				}
				return exploitcommon.ApplyAPIKey(headers, vdbType, strings.TrimSpace(vdbAPIKey)), nil
			},
			example: "vectordb -t http://127.0.0.1:8000 request GET /api/v1/collections",
		},
		{
			cmd: huggingfaceCmd, module: "huggingface", source: report.SourceHuggingFace,
			target:  func() string { return hfTarget },
			headers: func() (http.Header, error) { return exploitcommon.ParseHeaderFlags(hfHeaders) },
			example: "huggingface -t http://127.0.0.1:8080 request GET /info",
		},
	}
	for _, b := range bindings {
		b.cmd.AddCommand(newModuleRequestCmd(b))
	}
}

// bearerHeaderResolver builds a header resolver that adds an Authorization: Bearer
// header from the module's --api-key when one is set and no explicit Authorization
// header was supplied — matching how these modules already apply their key.
func bearerHeaderResolver(headerFlags func() []string, apiKey func() string) func() (http.Header, error) {
	return func() (http.Header, error) {
		headers, err := exploitcommon.ParseHeaderFlags(headerFlags())
		if err != nil {
			return nil, err
		}
		if key := strings.TrimSpace(apiKey()); key != "" && headers.Get("Authorization") == "" {
			headers.Set("Authorization", "Bearer "+key)
		}
		return headers, nil
	}
}

func newModuleRequestCmd(b moduleRequestBinding) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "request METHOD PATH-OR-URL",
		Short: fmt.Sprintf("Issue an arbitrary HTTP request to the %s target (operator console)", b.module),
		Long: fmt.Sprintf(`Issue an arbitrary HTTP request to the %s target through the tool.

Reuses this module's --target/--header%s, so after running the module's verbs you
can keep operating the service by hand. Works authenticated or unauthenticated.
The response is printed and captured as a finding for the loot index.

  aipostex %s`, b.module, moduleAuthFlagNote(b.module), b.example),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			method, path := args[0], args[1]
			target := strings.TrimSpace(b.target())
			if target == "" && !isFullRequestURL(path) {
				return missingFlagError("target", formatCommandExample(b.example))
			}
			headers, err := b.headers()
			if err != nil {
				return err
			}
			return runConsoleRequest(cmd.Context(), consoleRequestParams{
				source:  b.source,
				module:  b.module,
				target:  target,
				method:  method,
				path:    path,
				headers: headers,
			})
		},
	}
	bindRequestBodyFlags(cmd)
	return cmd
}

func moduleAuthFlagNote(module string) string {
	switch module {
	case "openai-compat", "litellm", "vectordb":
		return "/--api-key"
	default:
		return ""
	}
}
