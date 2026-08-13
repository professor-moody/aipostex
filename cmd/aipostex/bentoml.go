package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/inferenceprobe"
	"github.com/professor-moody/aipostex/pkg/exploit/bentoml"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	bentoTarget   string
	bentoHeaders  []string
	bentoEndpoint string
	bentoPayload  string
)

var bentomlCmd = &cobra.Command{
	Use:   "bentoml",
	Short: "Enumerate and exploit BentoML services",
	Long: `Post-exploitation module for BentoML model serving services.

Examples:
  aipostex bentoml --target http://10.0.0.60:3000 enum
  aipostex bentoml --target http://10.0.0.60:3000 routes
  aipostex bentoml --target http://10.0.0.60:3000 predict --endpoint /predict --payload '{"input":"test"}' --force-exploit`,
	Example: strings.Join([]string{
		formatCommandExample("bentoml --target http://127.0.0.1:3000 enum"),
		formatCommandExample("bentoml --target http://127.0.0.1:3000 routes"),
		formatCommandExample("bentoml --target http://127.0.0.1:3000 predict --endpoint /predict --payload '{\"input\":\"test\"}' --force-exploit"),
	}, "\n"),
}

var bentoEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate BentoML service metadata",
	Long: `Enumerate a BentoML service: metadata, health, and API routes.

Identifies the service and the model it wraps, and establishes whether the
inference surface answers unauthenticated — BentoML deployments frequently
expose the full serving API to anyone who can reach the port.

This is a read-only probing operation.`,
	Example: formatCommandExample("bentoml --target http://127.0.0.1:3000 enum"),
	RunE:    runBentoEnum,
}

var bentoRoutesCmd = &cobra.Command{
	Use:   "routes",
	Short: "List prediction endpoints from OpenAPI spec",
	Long: `Parse the service's OpenAPI spec to list every prediction endpoint with its
input schema.

The spec is the map of the serving surface: which routes accept input, and the
exact shape each expects. Because the schema is recovered, aipostex emits
schema-shaped predict follow-ons — the difference between guessing a payload and
sending one the service will actually accept.

This is a read-only probing operation.`,
	Example: formatCommandExample("bentoml --target http://127.0.0.1:3000 routes"),
	RunE:    runBentoRoutes,
}

var bentoPredictCmd = &cobra.Command{
	Use:   "predict",
	Short: "Send a prediction request to a BentoML endpoint",
	Long: `Send a prediction request to test inference access.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("bentoml --target http://127.0.0.1:3000 predict --endpoint /predict --payload '{\"input\":\"test\"}' --force-exploit"),
	RunE:    runBentoPredict,
}

var bentoMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Extract Prometheus metrics from BentoML",
	Long: `Retrieve the service's Prometheus metrics.

Metrics hand an unauthenticated caller operational detail: request counts,
latencies, and per-model performance. That shows which models are actually in
use and how heavily, so effort goes to the live model rather than an idle one.

This is a read-only probing operation.`,
	Example: formatCommandExample("bentoml --target http://127.0.0.1:3000 metrics"),
	RunE:    runBentoMetrics,
}

func init() {
	bentomlCmd.PersistentFlags().StringVarP(&bentoTarget, "target", "t", "", "BentoML service URL (required)")
	bentomlCmd.PersistentFlags().StringSliceVar(&bentoHeaders, "header", nil, "Additional HTTP header(s)")

	bentoPredictCmd.Flags().StringVar(&bentoEndpoint, "endpoint", "/", "Prediction endpoint path")
	bentoPredictCmd.Flags().StringVar(&bentoPayload, "payload", "", "JSON payload for prediction (required)")

	bentomlCmd.AddCommand(bentoEnumCmd, bentoRoutesCmd, bentoPredictCmd, bentoMetricsCmd)
}

func runBentoEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := newBentoClient()
	if err != nil {
		return err
	}
	info, err := client.Enumerate()
	if err != nil {
		return fmt.Errorf("enumerating bentoml service: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceBentoML,
			bentoTarget,
			"BentoML service enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated BentoML service (name=%s, version=%s, healthy=%t, routes=%d)",
				safeLabel(info.Name), safeLabel(info.Version), info.Healthy, len(info.Routes)),
			map[string]interface{}{
				"module":      "bentoml",
				"action":      "enum",
				"mutating":    false,
				"provider":    "bentoml",
				"version":     info.Version,
				"headers":     headerNames(headers),
				"healthy":     info.Healthy,
				"route_count": len(info.Routes),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "bentoml-enum", "service")

	enumPlan := buildBentoWorkflowPlan(bentoTarget, info.Routes, "enum")
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, enumPlan)

	infof("Enumerated BentoML service (routes=%d)", len(info.Routes))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "bentoml",
		Action:              "enum",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{enumPlan},
	})
}

func runBentoRoutes(cmd *cobra.Command, args []string) error {
	client, _, err := newBentoClient()
	if err != nil {
		return err
	}
	routes, err := client.ListRoutes()
	if err != nil {
		return fmt.Errorf("listing routes: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceBentoML,
			bentoTarget,
			"BentoML API routes enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated %d API route(s) from OpenAPI spec", len(routes)),
			map[string]interface{}{
				"module":      "bentoml",
				"action":      "routes",
				"mutating":    false,
				"provider":    "bentoml",
				"route_count": len(routes),
			},
		),
	}
	plan := buildBentoWorkflowPlan(bentoTarget, routes, "routes")
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	for _, route := range routes {
		finding := newExploitFinding(
			report.SourceBentoML,
			bentoTarget,
			fmt.Sprintf("BentoML route: %s %s", route.Method, route.Path),
			report.SeverityInfo,
			fmt.Sprintf("API route %s %s — %s", route.Method, route.Path, safeLabel(route.Summary)),
			map[string]interface{}{
				"module":   "bentoml",
				"action":   "routes",
				"mutating": false,
				"provider": "bentoml",
				"endpoint": route.Path,
			},
		)
		findings = append(findings, finding)
	}

	infof("Enumerated %d BentoML route(s)", len(routes))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "bentoml",
		Action:              "routes",
		ResourcesEnumerated: len(routes),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func runBentoPredict(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("bentoml predict"); err != nil {
		return err
	}
	if strings.TrimSpace(bentoPayload) == "" {
		return missingFlagError("payload", formatCommandExample("bentoml --target http://127.0.0.1:3000 predict --endpoint /predict --payload '{\"input\":\"test\"}' --force-exploit"))
	}
	client, _, err := newBentoClient()
	if err != nil {
		return err
	}

	result, err := client.Predict(bentoEndpoint, json.RawMessage(bentoPayload))
	if err != nil {
		return fmt.Errorf("prediction request: %w", err)
	}

	// Inference reality probe: distinguish real, input-dependent inference from a canned
	// fixture by sending a mutated input and comparing outputs. Only claim
	// execution-confirmed when verified real; otherwise reachable (detection).
	probe := inferenceprobe.Verify(json.RawMessage(bentoPayload), func(input []byte) (string, int, error) {
		r, e := client.Predict(bentoEndpoint, json.RawMessage(input))
		return r.Body, r.StatusCode, e
	})
	stage, landed := "recon", "reachable"
	title := fmt.Sprintf("BentoML inference not verified: %s", bentoEndpoint)
	severity := report.SeverityMedium
	if result.Success && probe.Real {
		stage, landed = "impact", probe.Landed()
		title = fmt.Sprintf("BentoML input-dependent inference verified: %s", bentoEndpoint)
		severity = report.SeverityCritical
	} else if !result.Success {
		title = fmt.Sprintf("BentoML prediction endpoint rejected request: %s", bentoEndpoint)
	}

	finding := newExploitFinding(
		report.SourceBentoML,
		bentoTarget,
		title,
		severity,
		fmt.Sprintf("Prediction request to %s returned status %d (success=%t); %s", bentoEndpoint, result.StatusCode, result.Success, probe.Evidence),
		map[string]interface{}{
			"module":             "bentoml",
			"action":             "predict",
			"mutating":           false,
			"provider":           "bentoml",
			"endpoint":           bentoEndpoint,
			"status_code":        result.StatusCode,
			"stage":              stage,
			"landed":             landed,
			"inference_verified": probe.Real,
		},
	)
	finding.Evidence = result.Body

	plan := buildBentoPredictWorkflowPlan(bentoTarget)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "bentoml",
		Action:              "predict",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func buildBentoWorkflowPlan(target string, routes []bentoml.Route, stage string) workflowPlan {
	target = canonicalServiceURL(target)
	recs := []workflowRecommendation{}
	if stage != "routes" {
		recs = append(recs, newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" routes"), "Enumerate prediction endpoints from OpenAPI spec.", false, 10))
	}
	recs = append(recs, newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" metrics"), "Extract Prometheus metrics.", false, 30))
	priority := 20
	for _, route := range routes {
		if strings.ToUpper(route.Method) != http.MethodPost {
			continue
		}
		payload, ok := bentoExamplePayload(route)
		if !ok {
			payload = `{"input":"aipostex-sample"}`
		}
		command := formatCommandExample("bentoml --target " + target +
			" predict --endpoint " + shellSafeArg(route.Path) +
			" --payload " + shellSafeArg(payload) +
			" --force-exploit")
		recs = append(recs, newWorkflowRecommendation(command, "Use the disclosed OpenAPI request schema to verify input-dependent inference.", true, priority))
		priority += 10
	}
	return workflowPlan{
		Target:          target,
		Stage:           stage,
		Rationale:       "BentoML OpenAPI routes anchor concrete prediction tests.",
		Recommendations: recs,
	}
}

// buildBentoPredictWorkflowPlan chains a completed inference test into enumeration
// of other prediction routes and metrics, so an inference finding is never a dead
// end. All follow-ons are read-only.
func buildBentoPredictWorkflowPlan(target string) workflowPlan {
	target = canonicalServiceURL(target)
	return workflowPlan{
		Target:    target,
		Stage:     "impact",
		Rationale: "A reachable prediction endpoint should flow into enumeration of other routes and operational metrics.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" routes"), "Enumerate other prediction endpoints from the OpenAPI spec to broaden the inference surface.", false, 10),
			newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" metrics"), "Extract Prometheus metrics for request volumes and served-model telemetry.", false, 20),
		},
	}
}

// buildBentoMetricsWorkflowPlan turns an exposed metrics endpoint into route and
// service enumeration.
func buildBentoMetricsWorkflowPlan(target string) workflowPlan {
	target = canonicalServiceURL(target)
	return workflowPlan{
		Target:    target,
		Stage:     "recon",
		Rationale: "An exposed metrics endpoint confirms reachability; pivot into route enumeration and service discovery.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" routes"), "Enumerate prediction endpoints from the OpenAPI spec.", false, 10),
			newWorkflowRecommendation(formatCommandExample("bentoml --target "+target+" enum"), "Re-enumerate the service (name/version/health/route count).", false, 20),
		},
	}
}

func bentoExamplePayload(route bentoml.Route) (string, bool) {
	schema, ok := bentoJSONSchema(route.InputSchema)
	if !ok {
		return "", false
	}
	raw, err := json.Marshal(bentoExampleForSchema(schema))
	return string(raw), err == nil
}

func bentoJSONSchema(requestBody map[string]interface{}) (map[string]interface{}, bool) {
	content, ok := requestBody["content"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	for _, contentType := range []string{"application/json", "application/vnd.bentoml+json"} {
		if media, ok := content[contentType].(map[string]interface{}); ok {
			if schema, ok := media["schema"].(map[string]interface{}); ok {
				return schema, true
			}
		}
	}
	for _, key := range bentoSortedKeys(content) {
		media, ok := content[key].(map[string]interface{})
		if !ok {
			continue
		}
		if schema, ok := media["schema"].(map[string]interface{}); ok {
			return schema, true
		}
	}
	return nil, false
}

func bentoExampleForSchema(schema map[string]interface{}) interface{} {
	switch strings.ToLower(exploitcommon.PickString(schema, "type")) {
	case "object":
		out := map[string]interface{}{}
		properties, _ := schema["properties"].(map[string]interface{})
		required := bentoRequiredFields(schema)
		if len(required) == 0 {
			required = bentoSortedKeys(properties)
		}
		for _, name := range required {
			propSchema, _ := properties[name].(map[string]interface{})
			out[name] = bentoExampleForSchema(propSchema)
		}
		if len(out) == 0 {
			out["input"] = "aipostex-sample"
		}
		return out
	case "array":
		itemSchema, _ := schema["items"].(map[string]interface{})
		return []interface{}{bentoExampleForSchema(itemSchema)}
	case "integer":
		return 1
	case "number":
		return 0.25
	case "boolean":
		return true
	case "string":
		return "aipostex-sample"
	default:
		return "aipostex-sample"
	}
}

func bentoRequiredFields(schema map[string]interface{}) []string {
	raw, ok := schema["required"].([]interface{})
	if !ok {
		return nil
	}
	fields := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			fields = append(fields, s)
		}
	}
	sort.Strings(fields)
	return fields
}

func bentoSortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func runBentoMetrics(cmd *cobra.Command, args []string) error {
	client, _, err := newBentoClient()
	if err != nil {
		return err
	}
	metrics, err := client.Metrics()
	if err != nil {
		return fmt.Errorf("retrieving metrics: %w", err)
	}

	severity := report.SeverityInfo
	if metrics.HasMetrics {
		severity = report.SeverityMedium
	}

	finding := newExploitFinding(
		report.SourceBentoML,
		bentoTarget,
		"BentoML metrics endpoint exposed",
		severity,
		fmt.Sprintf("Metrics endpoint accessible (has_metrics=%t)", metrics.HasMetrics),
		map[string]interface{}{
			"module":      "bentoml",
			"action":      "metrics",
			"mutating":    false,
			"provider":    "bentoml",
			"has_metrics": metrics.HasMetrics,
		},
	)
	finding.Evidence = metrics.Raw

	plan := buildBentoMetricsWorkflowPlan(bentoTarget)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, plan)

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "bentoml",
		Action:              "metrics",
		ResourcesEnumerated: 1,
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{plan},
	})
}

func newBentoClient() (*bentoml.Client, http.Header, error) {
	if strings.TrimSpace(bentoTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("bentoml --target http://127.0.0.1:3000 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(bentoHeaders)
	if err != nil {
		return nil, nil, err
	}
	target := normalizeAndWarnTarget(bentoTarget)
	bentoTarget = target
	client, err := bentoml.NewClient(currentContext(), target, cfg.Timeout, headers)
	if err != nil {
		return nil, nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, nil, err
	}
	client.HTTPClient = httpClient
	return client, headers, nil
}
