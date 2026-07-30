package main

import (
	"github.com/professor-moody/aipostex/internal/enrichment"
	"github.com/professor-moody/aipostex/pkg/report"
)

func summarizeJSONShape(raw string) string {
	return enrichment.SummarizeJSONShape(raw)
}

func extractFileReferences(raw string) []string {
	return enrichment.ExtractFileReferences(raw)
}

func artifactKind(path, body string) string {
	return enrichment.ArtifactKind(path, body)
}

func sensitivityHints(path, body string) []string {
	return enrichment.SensitivityHints(path, body)
}

func gradioEndpointRiskLabel(queue, fileInput, fileOutput bool) string {
	return enrichment.GradioEndpointRiskLabel(queue, fileInput, fileOutput)
}

func summarizeCapabilityLabels(values ...string) string {
	return enrichment.SummarizeCapabilityLabels(values...)
}

func classifyRayLogLanded(raw string) string {
	return enrichment.ClassifyRayLogLanded(raw)
}

func classifyArtifactPreview(path, body string) (kind string, hints []string, landed string) {
	return enrichment.ClassifyArtifactPreview(path, body)
}

func classifyGradioServeChain(downloaded bool, fileRef string, body string) string {
	return enrichment.ClassifyGradioServeChain(downloaded, fileRef, body)
}

func applyStageLanded(metadata map[string]interface{}, stage, strength, chainSource string, capabilityLabels ...string) map[string]interface{} {
	return enrichment.ApplyStageLanded(metadata, stage, strength, chainSource, capabilityLabels...)
}

func ensureFindingStageLandedDefaults(f *report.Finding) {
	enrichment.EnsureFindingStageLandedDefaults(f)
}
