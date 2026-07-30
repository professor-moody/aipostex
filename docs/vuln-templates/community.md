---
title: Community Templates
---

# Community Templates — the detection corpus

> Talk beat (after the benchmark results): *"aipostex is a binary, but the durable thing is
> the shared AI-infra detection corpus. The binary is just the runner — and the community is
> the incubator, not the trusted core."*

The hard, lasting work in AI-infra security is **knowing what to look for** across a sprawl of
fast-moving services. aipostex captures that as YAML templates, in three lanes:

| Lane | Where | Trust |
|------|-------|-------|
| **Core** | embedded in the `aipostex` binary | curated, release-tested, trusted |
| **Community** | [`aipostex-templates`](https://github.com/professor-moody/aipostex-templates), via `--templates-dir` | fast-moving, PR-reviewed, lint-gated |
| **Candidate core** | community → promoted after review + lab proof | on its way to core |

Run the community set alongside the built-in core:

```bash
aipostex scan targets --target http://host:port --templates-dir ./aipostex-templates
```

Community templates can make HTTP requests; exploit templates (`info.type: exploit`) run only
with `--mode full`. They are **never** silently trusted as core — they must be net-new (no
embedded-ID collisions) and pass `aipostex templates lint`.

## Contribute one

Found a weird AI service in the wild? Teach the scanner to find it:

1. Find a weird AI service.
2. Write a template (see [Writing Templates](writing.md) + the repo's `CONTRIBUTING.md`).
3. `aipostex templates lint --templates-dir .`
4. Test it against the [lab](https://professor-moody.github.io/aipostex-lab/) or a real instance.
5. Open a PR.

- Repo + authoring guide: [github.com/professor-moody/aipostex-templates](https://github.com/professor-moody/aipostex-templates)
- Wanted templates (ideas to claim): [open issues](https://github.com/professor-moody/aipostex-templates/issues) —
  LangGraph, CrewAI, AutoGen, Bedrock-compatible gateways, SageMaker Studio, Databricks MLflow,
  Vertex AI workbenches, more MCP servers.

## RRR honesty for templates

Classify every finding by what it actually proves — and never claim more:

- **Detection surface** → `landed: reachable`
- **Credential gate** (wrong/no cred fails, harvested cred succeeds) → `read-confirmed`
- **State-change / real payoff** (write+readback, callback, real output) → `execution-confirmed`
