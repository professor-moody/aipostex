package main

import (
	"fmt"
	"strings"
)

func buildGradioEnumWorkflowPlan(target string, apiNames []string, fnIndexes []int) workflowPlan {
	target = canonicalServiceURL(target)
	apiName := shellSafeArg(firstOrPlaceholder(apiNames, "<api-name>"))
	fnIndex := "<fn-index>"
	if len(fnIndexes) > 0 && fnIndexes[0] >= 0 {
		fnIndex = fmt.Sprintf("%d", fnIndexes[0])
	}
	recs := []workflowRecommendation{
		newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" predict --api-name "+apiName+" --input-json '[\"hello\"]'"), "Use a discovered named endpoint when available.", false, 10),
		newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" predict --fn-index "+fnIndex+" --input-json '[\"hello\"]'"), "Use a discovered function index when no API name is exposed.", false, 20),
		newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" file-chain --file <discovered-file-ref>"), "Supply a file reference a predict or config disclosed for bounded reads and serve correlation.", false, 30),
	}
	// The gated probes need a concrete endpoint; only offer them once enum actually named
	// one, so a --force-exploit command never carries an <api-name> placeholder. And
	// serve-probe needs a concrete file handle that only a predict/upload returns, so it
	// is surfaced by the download-file / file-chain plans, not emitted here with a token.
	if apiName != "<api-name>" {
		recs = append(recs,
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" queue-probe --api-name "+apiName+" --input-json '[\"hello\"]' --force-exploit"), "Only after enum suggests the endpoint is queue-backed.", true, 40),
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" upload-file --force-exploit"), "Only after enum suggests the endpoint accepts file input.", true, 50),
		)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "enum",
		Landed:          "reachable",
		ChainSource:     "gradio-enum",
		Rationale:       "Gradio config and endpoint discovery should hand off into bounded predict, then file, queue, or upload proofs.",
		Recommendations: recs,
	}
}

func buildGradioEndpointWorkflowPlan(target, apiName string, fnIndex int) workflowPlan {
	target = canonicalServiceURL(target)
	apiName = shellSafeArg(apiName)
	recommendations := []workflowRecommendation{}
	if strings.TrimSpace(apiName) != "" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" predict --api-name "+apiName+" --input-json '[\"hello\"]'"), "Call this discovered named endpoint directly.", false, 10),
		)
	}
	if fnIndex >= 0 {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" predict --fn-index "+fmt.Sprintf("%d", fnIndex)+" --input-json '[\"hello\"]'"), "Use the discovered function index if the named route is unavailable.", false, 20),
		)
	}
	if strings.TrimSpace(apiName) != "" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" queue-probe --api-name "+apiName+" --input-json '[\"hello\"]' --force-exploit"), "Only after confirming this endpoint is queue-backed.", true, 30),
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" upload-file --force-exploit"), "Only after confirming this endpoint accepts file input.", true, 40),
		)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "correlation",
		Landed:          "reachable",
		ChainSource:     "gradio-endpoint",
		Rationale:       "A discovered Gradio endpoint should map straight to a bounded predict call.",
		Recommendations: recommendations,
	}
}

func buildGradioDownloadFileSummaryWorkflowPlan(target, file string) workflowPlan {
	target = canonicalServiceURL(target)
	file = shellSafeArg(firstOrPlaceholder([]string{file}, "<file-ref>"))
	return workflowPlan{
		Target:      target,
		Stage:       "proof",
		Landed:      "read-confirmed",
		ChainSource: "gradio-download-file",
		Rationale:   "File downloaded; correlate into serve/read chains for broader exposure proof.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" file-chain --file "+file), "Correlate this file reference into a bounded serve/read chain.", false, 10),
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" serve-probe --file "+file+" --force-exploit"), "Only after confirming the file reference is real and bounded.", true, 20),
		},
	}
}

func buildGradioPredictWorkflowPlan(target string, fileRefs []string, apiName string, fnIndex int) workflowPlan {
	target = canonicalServiceURL(target)
	apiName = shellSafeArg(apiName)
	recommendations := []workflowRecommendation{}
	for _, fileRef := range fileRefs {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" download-file --file "+shellSafeArg(fileRef)), "Read a file reference returned by the predict response.", false, 10+len(recommendations)*10),
		)
	}
	if len(recommendations) == 0 {
		if strings.TrimSpace(apiName) != "" {
			recommendations = append(recommendations,
				newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" queue-probe --api-name "+apiName+" --input-json '[\"hello\"]' --force-exploit"), "Check whether this endpoint is queue-backed.", true, 10),
				newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" upload-file --force-exploit"), "Check whether this endpoint accepts file uploads.", true, 20),
			)
		}
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" file-chain --file <discovered-file-ref>"), "Supply a file reference a predict or config disclosed for bounded reads.", false, 30),
		)
		return workflowPlan{
			Target:          target,
			Stage:           "proof",
			Landed:          "influenced",
			ChainSource:     "gradio-predict",
			Rationale:       "Predict completed without file references; try queue, upload, or file probes.",
			Recommendations: recommendations,
		}
	}
	return workflowPlan{
		Target:          target,
		Stage:           "proof",
		Landed:          "influenced",
		ChainSource:     "gradio-predict",
		Rationale:       "The predict response returned concrete file references for follow-on reads.",
		Recommendations: recommendations,
	}
}

func buildGradioQueueWorkflowPlan(target, apiName string, fnIndex int) workflowPlan {
	target = canonicalServiceURL(target)
	apiName = shellSafeArg(apiName)
	recommendations := []workflowRecommendation{}
	if strings.TrimSpace(apiName) != "" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" upload-file --force-exploit"), "Use upload proof only when the same route appears file-capable.", true, 10),
		)
	} else if fnIndex >= 0 {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" upload-file --force-exploit"), "Use upload proof only when the same route appears file-capable.", true, 10),
		)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "takeover",
		Landed:          "influenced",
		ChainSource:     "gradio-queue-probe",
		Rationale:       "Queued execution was reachable, so the next active proof should stay bounded and route-specific.",
		Recommendations: recommendations,
	}
}

func buildGradioFileChainWorkflowPlan(target, file string) workflowPlan {
	target = canonicalServiceURL(target)
	file = shellSafeArg(firstOrPlaceholder([]string{file}, "<file-ref>"))
	return workflowPlan{
		Target:      target,
		Stage:       "proof",
		Landed:      "read-confirmed",
		ChainSource: "gradio-file-chain",
		Rationale:   "A concrete Gradio file handle can be downloaded first, then checked for serve/read reuse.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" download-file --file "+file), "Read the concrete file handle first.", false, 10),
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" serve-probe --file "+file+" --force-exploit"), "Only after confirming the file reference is real and bounded.", true, 40),
		},
	}
}

func buildGradioServeWorkflowPlan(target, file string) workflowPlan {
	target = canonicalServiceURL(target)
	file = shellSafeArg(firstOrPlaceholder([]string{file}, "<file-ref>"))
	return workflowPlan{
		Target:      target,
		Stage:       "takeover",
		Landed:      "read-confirmed",
		ChainSource: "gradio-serve-probe",
		Rationale:   "A validated Gradio file handle can be checked for re-serve or alternate file exposure paths.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("gradio --target "+target+" file-chain --file "+file), "Re-run the bounded file chain for this handle.", false, 10),
		},
	}
}
