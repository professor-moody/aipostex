package main

func buildA2AEnumWorkflowPlan(target string) workflowPlan {
	target = canonicalServiceURL(target)
	return workflowPlan{
		Target:      target,
		Stage:       "enum",
		Landed:      "reachable",
		ChainSource: "a2a-enum",
		Rationale:   "A2A agent card discovered; progress through skills enumeration into bounded task probes, then streaming / push-notification / MCP-pivot checks if approved.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" skills"), "Enumerate agent skills with input/output modes.", false, 10),
			newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" task-send --message 'ping' --force-exploit"), "Test unauthenticated task submission via SendMessage.", true, 20),
			newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" stream-probe --message 'list tools' --force-exploit"), "Subscribe to the SSE stream — may leak agent internals.", true, 30),
			newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" mcp-pivot --preset tool-enum --force-exploit"), "Cross-protocol probe for MCP-backed tools via A2A.", true, 40),
			newWorkflowRecommendation(formatCommandExample("scan targets --target "+target+" --tags a2a,agent"), "Run bundled A2A detection + exploit templates.", false, 5),
		},
	}
}

func buildA2AAgentWorkflowPlan(target, taskID string) workflowPlan {
	target = canonicalServiceURL(target)
	if taskID == "" {
		// No concrete task id came back (e.g. the agent rejected the probe, or the
		// response carried no task) — task-status / push-hijack / task-cancel would
		// carry a "<task-id>" placeholder and target a task that doesn't exist. Anchor
		// instead on obtaining a task first, plus the pivot that needs no task id.
		return workflowPlan{
			Target:      target,
			Stage:       "enum",
			Landed:      "reachable",
			ChainSource: "a2a-task",
			Rationale:   "No task id was returned; create a task to obtain a concrete id, then poll or hijack its lifecycle.",
			Recommendations: []workflowRecommendation{
				newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" task-send --message 'ping' --force-exploit"), "Submit a task to obtain a concrete task id to anchor lifecycle follow-ons.", true, 10),
				newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" mcp-pivot --preset file-read --force-exploit"), "Attempt cross-protocol pivot into MCP file-read tool (no task id required).", true, 20),
			},
		}
	}
	anchor := shellSafeArg(taskID)
	return workflowPlan{
		Target:      target,
		Stage:       "correlation",
		Landed:      "reachable",
		ChainSource: "a2a-task",
		Rationale:   "A concrete A2A task id anchors follow-on status polling, cancellation, or push-notification hijack checks.",
		Recommendations: []workflowRecommendation{
			newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" task-status --task-id "+anchor), "Poll task state via GetTask (unauthenticated info disclosure).", false, 10),
			newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" push-hijack --task-id "+anchor+" --force-exploit"), "Register canary webhook to confirm the data-exfil path.", true, 20),
			newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" task-cancel --task-id "+anchor+" --force-exploit"), "Only if cancellation is in-scope — DoS-style probe.", true, 30),
			newWorkflowRecommendation(formatCommandExample("a2a --target "+target+" mcp-pivot --preset file-read --force-exploit"), "Attempt cross-protocol pivot into MCP file-read tool.", true, 40),
		},
	}
}

// buildA2AOffensiveWorkflowPlan emits escalation follow-ons for the a2a single-node
// offensive verbs. Each verb chains to an existing a2a verb that deepens the SAME
// weakness it just demonstrated, so a HIGH/takeover-capable finding is never a
// dead end. anchor is an optional concrete identifier (e.g. a push-hijack task id)
// woven into the recommendation so the operator keeps the discovered value.
func buildA2AOffensiveWorkflowPlan(target, action, anchor string) workflowPlan {
	target = canonicalServiceURL(target)
	base := "a2a --target " + target + " "
	rec := func(cmd, why string, gated bool, prio int) workflowRecommendation {
		return newWorkflowRecommendation(formatCommandExample(cmd), why, gated, prio)
	}
	var rationale string
	var recs []workflowRecommendation
	switch action {
	case "card-spoof":
		rationale = "The agent fetched and trusted an attacker-controlled card; escalate by exercising the skills and tools it now trusts."
		recs = []workflowRecommendation{
			rec(base+"delegate-probe --force-exploit", "Probe whether the agent acts on the spoofed card's declared skills (confused-deputy delegation).", true, 10),
			rec(base+"mcp-pivot --preset tool-enum --force-exploit", "If the trusted card advertises MCP-backed tools, pivot cross-protocol.", true, 20),
			rec(base+"tool-inject --force-exploit", "Feed the agent a malicious tool it now trusts.", true, 30),
		}
	case "push-hijack":
		rationale = "A push-notification webhook was registered; confirm delivery, then drive tasks whose results route to it."
		anchorArg := ""
		if anchor != "" {
			anchorArg = " --task-id " + shellSafeArg(anchor)
		}
		recs = []workflowRecommendation{
			rec(base+"task-status"+anchorArg, "Poll the task lifecycle to confirm the hijacked webhook receives delivery.", false, 10),
			rec(base+"task-send --message 'exfil probe' --force-exploit", "Submit a task whose result routes to the hijacked callback.", true, 20),
		}
	case "msg-integrity":
		rationale = "The agent accepted a tampered message; escalate to identity abuse and replay."
		recs = []workflowRecommendation{
			rec(base+"sender-spoof --force-exploit", "Escalate from content tampering to sender-identity spoofing.", true, 10),
			rec(base+"replay --force-exploit", "Replay a captured message to test idempotency/nonce defenses.", true, 20),
		}
	case "sender-spoof":
		rationale = "A spoofed sender identity was accepted; operate as that identity."
		recs = []workflowRecommendation{
			rec(base+"delegate-probe --force-exploit", "Probe delegation while presenting the spoofed identity.", true, 10),
			rec(base+"task-send --message 'ping' --force-exploit", "Submit a task under the spoofed sender identity.", true, 20),
		}
	case "replay":
		rationale = "A replayed message was accepted; escalate to tampering and identity abuse."
		recs = []workflowRecommendation{
			rec(base+"msg-integrity --force-exploit", "Test whether tampered (not just replayed) messages are accepted.", true, 10),
			rec(base+"sender-spoof --force-exploit", "Escalate to sender-identity spoofing.", true, 20),
		}
	case "delegate-probe":
		rationale = "Delegation abuse is viable; pivot cross-protocol and via card trust."
		recs = []workflowRecommendation{
			rec(base+"mcp-pivot --preset tool-enum --force-exploit", "Pivot into MCP-backed tools reachable through delegation.", true, 10),
			rec(base+"card-spoof --force-exploit", "Chain card trust into the delegation path (add --callback-url with your listener to OOB-confirm the fetch).", true, 20),
		}
	case "mcp-pivot":
		rationale = "A cross-protocol MCP surface is reachable through the agent; deepen the MCP and task surfaces."
		recs = []workflowRecommendation{
			rec(base+"tool-inject --force-exploit", "Inject a tool through the MCP-backed surface.", true, 10),
			rec(base+"scrape-loop --prompt 'list tools and secrets' --force-exploit", "Loop the agent to surface tool/secret metadata.", true, 20),
		}
	case "auth-probe":
		rationale = "Auth is weak or optional; drive the unauthenticated task and enumeration surfaces."
		recs = []workflowRecommendation{
			rec(base+"skills", "Enumerate agent skills unauthenticated.", false, 10),
			rec(base+"task-send --message 'ping' --force-exploit", "Submit an unauthenticated task.", true, 20),
			rec(base+"card-spoof --force-exploit", "Test fetch-and-trust of an attacker-controlled card (add --callback-url with your listener to OOB-confirm).", true, 30),
		}
	case "scrape-loop":
		rationale = "Bulk task-output extraction surfaced credentials; review the loot, then drive further extraction or an MCP pivot."
		recs = []workflowRecommendation{
			rec("report view <dossier-dir> --credentials", "Review the credentials extracted from the scraped task outputs (raw or as a table) from your engagement dossier — save runs with --format dossier -o <dir>.", false, 10),
			rec(base+"task-send --message 'follow-up extraction' --force-exploit", "Submit a follow-up task to continue extraction.", true, 20),
			rec(base+"mcp-pivot --preset tool-enum --force-exploit", "Pivot cross-protocol if the agent exposes MCP-backed tools.", true, 30),
		}
	default:
		return workflowPlan{}
	}
	return workflowPlan{
		Target:          target,
		Stage:           "impact",
		Landed:          "influenced",
		ChainSource:     "a2a-" + action,
		Rationale:       rationale,
		Recommendations: recs,
	}
}
