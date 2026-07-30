package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestInferStageRespectsExplicitMetadata(t *testing.T) {
	f := report.Finding{
		Source:   report.SourceVulnCheck,
		Severity: report.SeverityCritical,
		Metadata: map[string]interface{}{"stage": "own"},
	}
	if got := inferStage(f); got != "own" {
		t.Fatalf("expected explicit takeover, got %s", got)
	}
}

func TestInferStageFingerprintAlwaysDiscovery(t *testing.T) {
	f := report.Finding{Source: report.SourceFingerprint, Severity: report.SeverityInfo}
	if got := inferStage(f); got != "recon" {
		t.Fatalf("expected discovery for fingerprint, got %s", got)
	}
}

func TestInferStageVulnCheckBySeverity(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{report.SeverityCritical, "impact"},
		{report.SeverityHigh, "impact"},
		{report.SeverityMedium, "access"},
		{report.SeverityLow, "recon"},
		{report.SeverityInfo, "recon"},
	}
	for _, tc := range tests {
		f := report.Finding{Source: report.SourceVulnCheck, Severity: tc.severity}
		got := inferStage(f)
		if got != tc.expected {
			t.Errorf("inferStage(vulncheck, %s) = %s, want %s", tc.severity, got, tc.expected)
		}
	}
}

func TestInferStageNormalizesMixedCaseSeverity(t *testing.T) {
	for _, sev := range []string{"HIGH", "High", "hIgH"} {
		f := report.Finding{Source: report.SourceVulnCheck, Severity: sev}
		got := inferStage(f)
		if got != "impact" {
			t.Errorf("inferStage(vulncheck, %q) = %s, want proof", sev, got)
		}
	}
	for _, sev := range []string{"CRITICAL", "Critical"} {
		f := report.Finding{Source: report.SourceVulnCheck, Severity: sev}
		got := inferStage(f)
		if got != "impact" {
			t.Errorf("inferStage(vulncheck, %q) = %s, want proof", sev, got)
		}
	}
	for _, sev := range []string{"MEDIUM", "Medium"} {
		f := report.Finding{Source: report.SourceVulnCheck, Severity: sev}
		got := inferStage(f)
		if got != "access" {
			t.Errorf("inferStage(vulncheck, %q) = %s, want correlation", sev, got)
		}
	}
}

func TestSevCountsNormalized(t *testing.T) {
	findings := []report.Finding{
		{Target: "http://a:1", Title: "A", Severity: "HIGH", Source: report.SourceVulnCheck},
		{Target: "http://a:1", Title: "B", Severity: "Critical", Source: report.SourceVulnCheck},
	}
	g := buildGraph(findings)
	proof := g.hosts[0].stages["impact"]
	if proof == nil {
		t.Fatal("expected impact stage")
	}
	if proof.sevCounts[report.SeverityHigh] != 1 {
		t.Fatalf("expected 1 high in normalized sevCounts, got %d", proof.sevCounts[report.SeverityHigh])
	}
	if proof.sevCounts[report.SeverityCritical] != 1 {
		t.Fatalf("expected 1 critical in normalized sevCounts, got %d", proof.sevCounts[report.SeverityCritical])
	}
}

func TestMixedCaseSeverityKeepsGraphStyling(t *testing.T) {
	findings := []report.Finding{
		{Target: "http://a:1", Title: "Critical Bug", Severity: "Critical", Source: report.SourceVulnCheck},
	}

	g := buildGraph(findings)
	proof := g.hosts[0].stages["impact"]
	if proof == nil {
		t.Fatal("expected impact stage")
	}
	if proof.maxSev != report.SeverityCritical {
		t.Fatalf("expected normalized maxSev %q, got %q", report.SeverityCritical, proof.maxSev)
	}

	mermaid := renderMermaid(g)
	if !strings.Contains(mermaid, `_impact[[`) {
		t.Fatal("expected high-severity node styling in Mermaid output")
	}

	dot := renderDOT(g)
	if !strings.Contains(dot, `fillcolor="#ff7b72"`) {
		t.Fatal("expected critical fill color in DOT output")
	}
}

func TestInferStageModuleSourcesDefaultToCorrelation(t *testing.T) {
	for _, src := range []string{
		report.SourceOllama, report.SourceVectorDB, report.SourceMCP,
		report.SourceRay, report.SourceMLflow, report.SourceGradio,
		report.SourceJupyter, report.SourceOpenAICompat,
	} {
		f := report.Finding{Source: src, Severity: report.SeverityInfo}
		got := inferStage(f)
		if got != "access" {
			t.Errorf("inferStage(%s) = %s, want correlation", src, got)
		}
	}
}

func TestBuildGraphInfersStagesFromScanNetwork(t *testing.T) {
	findings := []report.Finding{
		{
			Target:   "http://10.0.0.5:11434",
			Title:    "AI service discovered: ollama",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Metadata: map[string]interface{}{"service": "ollama"},
		},
		{
			Target:   "http://10.0.0.5:8888",
			Title:    "AI service discovered: jupyter",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Metadata: map[string]interface{}{"service": "jupyter"},
		},
		{
			Target:     "http://10.0.0.5:11434",
			Title:      "Ollama Version Disclosure",
			Severity:   report.SeverityMedium,
			Source:     report.SourceVulnCheck,
			TemplateID: "ollama-version-001",
		},
		{
			Target:     "http://10.0.0.5:11434",
			Title:      "Ollama No Auth RCE",
			Severity:   report.SeverityCritical,
			Source:     report.SourceVulnCheck,
			TemplateID: "ollama-auth-001",
		},
		{
			Target:     "http://10.0.0.5:11434",
			Title:      "LLMjacking Risk",
			Severity:   report.SeverityHigh,
			Source:     report.SourceVulnCheck,
			TemplateID: "ollama-llmjack-001",
		},
	}

	g := buildGraph(findings)
	if len(g.hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(g.hosts))
	}
	host := g.hosts[0]

	if _, ok := host.stages["recon"]; !ok {
		t.Fatal("expected recon stage from fingerprint findings")
	}
	if _, ok := host.stages["access"]; !ok {
		t.Fatal("expected access stage from medium vulncheck findings")
	}
	if _, ok := host.stages["impact"]; !ok {
		t.Fatal("expected impact stage from critical/high vulncheck findings")
	}
	if host.stages["recon"].findCount != 2 {
		t.Fatalf("expected 2 discovery findings, got %d", host.stages["recon"].findCount)
	}
	if host.stages["access"].findCount != 1 {
		t.Fatalf("expected 1 correlation finding, got %d", host.stages["access"].findCount)
	}
	if host.stages["impact"].findCount != 2 {
		t.Fatalf("expected 2 proof findings, got %d", host.stages["impact"].findCount)
	}
}

func TestBuildGraphBucketsFileDiscoveryUnderLocalFiles(t *testing.T) {
	g := buildGraph([]report.Finding{
		{Target: "/tmp/a.env", Title: "Secrets A", Severity: report.SeverityHigh, Source: report.SourceFileDiscovery},
		{Target: "/tmp/b.env", Title: "Secrets B", Severity: report.SeverityMedium, Source: report.SourceFileDiscovery},
	})

	if len(g.hosts) != 1 {
		t.Fatalf("expected 1 grouped host for file discovery, got %d", len(g.hosts))
	}
	if g.hosts[0].host != "local-files" {
		t.Fatalf("expected local-files host bucket, got %q", g.hosts[0].host)
	}
}

func TestStageLabelDiscovery(t *testing.T) {
	sn := &stageNode{
		stage:     "recon",
		findCount: 3,
		services:  []string{"ollama", "jupyter", "chromadb"},
		targets:   []string{"http://10.0.0.5:11434", "http://10.0.0.5:8888", "http://10.0.0.5:8000"},
		sevCounts: map[string]int{report.SeverityInfo: 3},
	}
	label := stageLabel(sn)
	if !strings.Contains(label, "3 services") {
		t.Fatalf("expected '3 services' in label, got: %s", label)
	}
	if !strings.Contains(label, "3 ports") {
		t.Fatalf("expected '3 ports' in label, got: %s", label)
	}
}

func TestStageLabelCorrelation(t *testing.T) {
	sn := &stageNode{
		stage:       "access",
		findCount:   5,
		templateIDs: []string{"tmpl-a", "tmpl-b", "tmpl-c"},
		sevCounts:   map[string]int{report.SeverityMedium: 5},
	}
	label := stageLabel(sn)
	if !strings.Contains(label, "5 vulns across 3 templates") {
		t.Fatalf("expected '5 vulns across 3 templates', got: %s", label)
	}
}

func TestStageLabelProof(t *testing.T) {
	sn := &stageNode{
		stage:     "impact",
		findCount: 4,
		topTitle:  "RCE Confirmed",
		sevCounts: map[string]int{report.SeverityCritical: 2, report.SeverityHigh: 2},
	}
	label := stageLabel(sn)
	if !strings.Contains(label, "4 critical/high") {
		t.Fatalf("expected '4 critical/high', got: %s", label)
	}
	if !strings.Contains(label, "RCE Confirmed") {
		t.Fatalf("expected top title in proof label, got: %s", label)
	}
}

func TestBuildGraphGroupsByHost(t *testing.T) {
	findings := []report.Finding{
		{
			Target:   "http://10.0.0.5:11434",
			Title:    "Ollama Detected",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Metadata: map[string]interface{}{"stage": "recon", "service": "ollama"},
		},
		{
			Target:   "http://10.0.0.5:11434",
			Title:    "Ollama No Auth",
			Severity: report.SeverityCritical,
			Source:   report.SourceVulnCheck,
			Metadata: map[string]interface{}{"stage": "impact"},
		},
		{
			Target:   "http://10.0.0.6:8888",
			Title:    "Jupyter Detected",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Metadata: map[string]interface{}{"stage": "recon", "service": "jupyter"},
		},
	}

	g := buildGraph(findings)
	if len(g.hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(g.hosts))
	}

	var host5 *hostNode
	for _, h := range g.hosts {
		if h.host == "10.0.0.5" {
			host5 = h
		}
	}
	if host5 == nil {
		t.Fatal("host 10.0.0.5 not found")
	}
	if len(host5.stages) != 2 {
		t.Fatalf("expected 2 stages for host 10.0.0.5, got %d", len(host5.stages))
	}
	if host5.stages["impact"].maxSev != report.SeverityCritical {
		t.Fatalf("expected critical severity at impact stage, got %s", host5.stages["impact"].maxSev)
	}
}

func TestRenderMermaidWithInferredStages(t *testing.T) {
	findings := []report.Finding{
		{
			Target:   "http://10.0.0.5:11434",
			Title:    "Ollama Detected",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Metadata: map[string]interface{}{"service": "ollama"},
		},
		{
			Target:     "http://10.0.0.5:11434",
			Title:      "RCE Confirmed",
			Severity:   report.SeverityCritical,
			Source:     report.SourceVulnCheck,
			TemplateID: "ollama-auth-001",
		},
	}

	g := buildGraph(findings)
	mermaid := renderMermaid(g)

	if !strings.Contains(mermaid, "flowchart TD") {
		t.Fatal("expected mermaid flowchart header")
	}
	if !strings.Contains(mermaid, "subgraph") {
		t.Fatal("expected subgraph for host")
	}
	if !strings.Contains(mermaid, "recon") {
		t.Fatal("expected recon stage node")
	}
	if !strings.Contains(mermaid, "impact") {
		t.Fatal("expected impact stage node")
	}
	if !strings.Contains(mermaid, "-->") {
		t.Fatal("expected edge between stages")
	}
	if !strings.Contains(mermaid, "1 services") {
		t.Fatal("expected service count in discovery label")
	}
	if !strings.Contains(mermaid, "RCE Confirmed") {
		t.Fatal("expected top title in proof label")
	}
}

func TestRenderDOT(t *testing.T) {
	findings := []report.Finding{
		{
			Target:   "http://10.0.0.5:11434",
			Title:    "Service Found",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Metadata: map[string]interface{}{"stage": "recon"},
		},
		{
			Target:   "http://10.0.0.5:11434",
			Title:    "Vuln Found",
			Severity: report.SeverityHigh,
			Source:   report.SourceVulnCheck,
			Metadata: map[string]interface{}{"stage": "access"},
		},
	}

	g := buildGraph(findings)
	dot := renderDOT(g)

	if !strings.Contains(dot, "digraph attack_graph") {
		t.Fatal("expected DOT digraph header")
	}
	if !strings.Contains(dot, "cluster_") {
		t.Fatal("expected cluster subgraph")
	}
	if !strings.Contains(dot, "->") {
		t.Fatal("expected edges")
	}
}

func TestBuildGraphDefaultsToDiscovery(t *testing.T) {
	findings := []report.Finding{
		{
			Target:   "http://10.0.0.5:11434",
			Title:    "No Metadata",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
		},
	}

	g := buildGraph(findings)
	if len(g.hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(g.hosts))
	}
	if _, ok := g.hosts[0].stages["recon"]; !ok {
		t.Fatal("expected finding without stage to default to discovery")
	}
}

func TestMermaidSafe(t *testing.T) {
	got := mermaidSafe("10.0.0.5")
	if strings.Contains(got, ".") {
		t.Fatalf("expected dots to be replaced, got %s", got)
	}
}

func TestStageNodeTracksServices(t *testing.T) {
	findings := []report.Finding{
		{
			Target:   "http://10.0.0.5:11434",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Metadata: map[string]interface{}{"service": "ollama"},
		},
		{
			Target:   "http://10.0.0.5:8888",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Metadata: map[string]interface{}{"service": "jupyter"},
		},
		{
			Target:   "http://10.0.0.5:8000",
			Severity: report.SeverityInfo,
			Source:   report.SourceFingerprint,
			Metadata: map[string]interface{}{"service": "chromadb"},
		},
	}

	g := buildGraph(findings)
	disc := g.hosts[0].stages["recon"]
	if len(disc.services) != 3 {
		t.Fatalf("expected 3 services, got %d: %v", len(disc.services), disc.services)
	}
}

func TestStageNodeTracksTemplateIDs(t *testing.T) {
	findings := []report.Finding{
		{
			Target:     "http://10.0.0.5:11434",
			Severity:   report.SeverityMedium,
			Source:     report.SourceVulnCheck,
			TemplateID: "tmpl-a",
		},
		{
			Target:     "http://10.0.0.5:11434",
			Severity:   report.SeverityMedium,
			Source:     report.SourceVulnCheck,
			TemplateID: "tmpl-a",
		},
		{
			Target:     "http://10.0.0.5:11434",
			Severity:   report.SeverityMedium,
			Source:     report.SourceVulnCheck,
			TemplateID: "tmpl-b",
		},
	}

	g := buildGraph(findings)
	corr := g.hosts[0].stages["access"]
	if len(corr.templateIDs) != 2 {
		t.Fatalf("expected 2 unique templates, got %d: %v", len(corr.templateIDs), corr.templateIDs)
	}
}

// ---------------------------------------------------------------------------
// stageLabel — additional cases
// ---------------------------------------------------------------------------

func TestStageLabelTakeover(t *testing.T) {
	sn := &stageNode{
		stage:     "own",
		findCount: 2,
		topTitle:  "Full RCE via Ollama",
		sevCounts: map[string]int{report.SeverityCritical: 2},
	}
	label := stageLabel(sn)
	if !strings.Contains(label, "own: 2 findings") {
		t.Fatalf("expected 'own: 2 findings', got: %s", label)
	}
	if !strings.Contains(label, "Full RCE via Ollama") {
		t.Fatalf("expected top title in takeover label, got: %s", label)
	}
}

func TestStageLabelTakeoverLongTitle(t *testing.T) {
	sn := &stageNode{
		stage:     "own",
		findCount: 1,
		topTitle:  strings.Repeat("A", 60),
		sevCounts: map[string]int{report.SeverityCritical: 1},
	}
	label := stageLabel(sn)
	if !strings.Contains(label, "...") {
		t.Fatalf("expected truncated title with ..., got: %s", label)
	}
}

func TestStageLabelDefault(t *testing.T) {
	sn := &stageNode{
		stage:     "custom-stage",
		findCount: 7,
		sevCounts: map[string]int{},
	}
	label := stageLabel(sn)
	if !strings.Contains(label, "custom-stage: 7 findings") {
		t.Fatalf("expected 'custom-stage: 7 findings', got: %s", label)
	}
}

func TestStageLabelDiscoveryNoServices(t *testing.T) {
	sn := &stageNode{
		stage:     "recon",
		findCount: 5,
		services:  nil,
		targets:   nil,
		sevCounts: map[string]int{report.SeverityInfo: 5},
	}
	label := stageLabel(sn)
	if !strings.Contains(label, "recon: 5 findings") {
		t.Fatalf("expected 'recon: 5 findings', got: %s", label)
	}
}

func TestStageLabelCorrelationNoTemplates(t *testing.T) {
	sn := &stageNode{
		stage:       "access",
		findCount:   3,
		templateIDs: nil,
		sevCounts:   map[string]int{report.SeverityMedium: 3},
	}
	label := stageLabel(sn)
	if !strings.Contains(label, "access: 3 findings") {
		t.Fatalf("expected 'access: 3 findings', got: %s", label)
	}
}

func TestStageLabelProofLongTitle(t *testing.T) {
	sn := &stageNode{
		stage:     "impact",
		findCount: 1,
		topTitle:  strings.Repeat("X", 60),
		sevCounts: map[string]int{report.SeverityCritical: 1},
	}
	label := stageLabel(sn)
	if !strings.Contains(label, "...") {
		t.Fatalf("expected truncated proof title, got: %s", label)
	}
}

// ---------------------------------------------------------------------------
// runGraph — integration with temp files
// ---------------------------------------------------------------------------

func TestRunGraphWithTempInput(t *testing.T) {
	collection := report.FindingCollection{
		EngagementID: "test-graph",
		Findings: []report.Finding{
			{
				Source:   report.SourceFingerprint,
				Target:   "http://10.0.0.5:11434",
				Title:    "Ollama Detected",
				Severity: report.SeverityInfo,
				Metadata: map[string]interface{}{"service": "ollama"},
			},
			{
				Source:   report.SourceVulnCheck,
				Target:   "http://10.0.0.5:11434",
				Title:    "Ollama No Auth",
				Severity: report.SeverityCritical,
			},
		},
	}
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "graph-input.json")
	data, err := json.Marshal(collection)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(inputPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	prevInput := graphInput
	prevFormat := graphFormat
	defer func() {
		graphInput = prevInput
		graphFormat = prevFormat
	}()

	for _, format := range []string{"mermaid", "dot"} {
		t.Run(format, func(t *testing.T) {
			graphInput = inputPath
			graphFormat = format

			withTestConfig(t, func() {
				outputPath := filepath.Join(tmpDir, "graph-"+format+".out")
				cfg.OutputFile = outputPath

				var stderr strings.Builder
				origWriter := stderrWriter
				stderrWriter = &stderr
				defer func() { stderrWriter = origWriter }()

				if err := runGraph(nil, nil); err != nil {
					t.Fatalf("runGraph(%s) error: %v", format, err)
				}
				stat, err := os.Stat(outputPath)
				if err != nil {
					t.Fatalf("output file not created: %v", err)
				}
				if stat.Size() == 0 {
					t.Fatal("output file is empty")
				}
			})
		})
	}
}

func TestRunGraphInvalidFormat(t *testing.T) {
	collection := report.FindingCollection{
		EngagementID: "test-graph",
		Findings: []report.Finding{
			{Source: report.SourceFingerprint, Target: "http://10.0.0.5:11434",
				Title: "Test", Severity: report.SeverityInfo},
		},
	}
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.json")
	data, _ := json.Marshal(collection)
	_ = os.WriteFile(inputPath, data, 0o600)

	prevInput := graphInput
	prevFormat := graphFormat
	defer func() {
		graphInput = prevInput
		graphFormat = prevFormat
	}()

	graphInput = inputPath
	graphFormat = "invalid-format"

	withTestConfig(t, func() {
		err := runGraph(nil, nil)
		if err == nil {
			t.Fatal("expected error for invalid format")
		}
		if !strings.Contains(err.Error(), "unknown --format") {
			t.Errorf("expected unknown format error, got: %v", err)
		}
	})
}

func TestRunGraphDiscoveryOnlyWarning(t *testing.T) {
	collection := report.FindingCollection{
		EngagementID: "test-graph",
		Findings: []report.Finding{
			{Source: report.SourceFingerprint, Target: "http://10.0.0.5:11434",
				Title: "Ollama Detected", Severity: report.SeverityInfo,
				Metadata: map[string]interface{}{"service": "ollama"}},
		},
	}
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.json")
	data, _ := json.Marshal(collection)
	_ = os.WriteFile(inputPath, data, 0o600)

	prevInput := graphInput
	prevFormat := graphFormat
	defer func() {
		graphInput = prevInput
		graphFormat = prevFormat
	}()

	graphInput = inputPath
	graphFormat = "mermaid"

	withTestConfig(t, func() {
		cfg.OutputFile = filepath.Join(tmpDir, "graph.mermaid")

		var stderr strings.Builder
		origWriter := stderrWriter
		stderrWriter = &stderr
		defer func() { stderrWriter = origWriter }()

		_ = runGraph(nil, nil)
		if !strings.Contains(stderr.String(), "recon stage") {
			t.Fatal("expected discovery-only warning")
		}
	})
}

func TestSeverityRankForGraph(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{report.SeverityCritical, 0},
		{report.SeverityHigh, 1},
		{report.SeverityMedium, 2},
		{report.SeverityLow, 3},
		{report.SeverityInfo, 4},
	}
	for _, tc := range tests {
		if got := severityRankForGraph(tc.sev); got != tc.want {
			t.Errorf("severityRankForGraph(%q) = %d, want %d", tc.sev, got, tc.want)
		}
	}
	if severityRankForGraph(report.SeverityCritical) >= severityRankForGraph(report.SeverityHigh) {
		t.Error("critical should rank before high")
	}
}

func TestDotEscape(t *testing.T) {
	if got := dotEscape(`hello "world"`); !strings.Contains(got, `\"`) {
		t.Errorf("expected escaped quotes, got %q", got)
	}
	if got := dotEscape("line1\nline2"); !strings.Contains(got, `\n`) {
		t.Errorf("expected escaped newlines, got %q", got)
	}
}

func TestStringInSlice(t *testing.T) {
	if !stringInSlice("a", []string{"a", "b"}) {
		t.Error("expected true for existing element")
	}
	if stringInSlice("c", []string{"a", "b"}) {
		t.Error("expected false for missing element")
	}
	if stringInSlice("a", nil) {
		t.Error("expected false for nil slice")
	}
}
