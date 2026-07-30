package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/professor-moody/aipostex/pkg/report"
)

// SARIF 2.1.0 types -- only the subset we emit.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string               `json:"name"`
	Version        string               `json:"version,omitempty"`
	InformationURI string               `json:"informationUri,omitempty"`
	Rules          []sarifReportingDesc `json:"rules,omitempty"`
}

type sarifReportingDesc struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	Help             *sarifMessage          `json:"help,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
	DefaultConfig    *sarifDefaultConfig    `json:"defaultConfiguration,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             sarifMessage           `json:"message"`
	Locations           []sarifLocation        `json:"locations,omitempty"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFWriter writes findings as a SARIF 2.1.0 JSON document.
type SARIFWriter struct {
	w        io.WriteCloser
	findings []report.Finding
}

func NewSARIFWriter(path string) (*SARIFWriter, error) {
	var w io.WriteCloser
	if path == "" || path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("creating sarif output file: %w", err)
		}
		w = f
	}
	return &SARIFWriter{w: w}, nil
}

func (sw *SARIFWriter) WriteHeader() error { return nil }

func (sw *SARIFWriter) WriteFinding(f report.Finding) error {
	sw.findings = append(sw.findings, f)
	return nil
}

func (sw *SARIFWriter) WriteFooter(_ map[string]int) error {
	return sw.render()
}

func (sw *SARIFWriter) Close() error {
	if sw.w != os.Stdout {
		return sw.w.Close()
	}
	return nil
}

func (sw *SARIFWriter) render() error {
	ruleIndex := map[string]int{}
	var rules []sarifReportingDesc

	for _, f := range sw.findings {
		rid := sarifRuleID(f)
		if _, exists := ruleIndex[rid]; exists {
			continue
		}
		ruleIndex[rid] = len(rules)

		desc := sarifReportingDesc{
			ID:               rid,
			ShortDescription: sarifMessage{Text: f.Title},
			DefaultConfig:    &sarifDefaultConfig{Level: sarifLevel(f.Severity)},
			Properties: map[string]interface{}{
				"security-severity": sarifSecuritySeverity(f),
			},
		}
		if f.Remediation != "" {
			desc.Help = &sarifMessage{Text: f.Remediation}
		}
		if len(f.Tags) > 0 {
			desc.Properties["tags"] = f.Tags
		}
		rules = append(rules, desc)
	}

	var results []sarifResult
	for _, f := range sw.findings {
		rid := sarifRuleID(f)
		idx := ruleIndex[rid]

		msg := sarifMessage{Text: f.Title}
		if f.Description != "" {
			msg.Text = f.Title + " -- " + f.Description
		}
		if f.Evidence != "" {
			msg.Markdown = "**Evidence:** " + f.Evidence
		}

		r := sarifResult{
			RuleID:    rid,
			RuleIndex: idx,
			Level:     sarifLevel(f.Severity),
			Message:   msg,
			Locations: []sarifLocation{
				{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.Target},
				}},
			},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": sarifFingerprint(f.Target, rid),
			},
		}
		props := map[string]interface{}{}
		if len(f.Tags) > 0 {
			props["tags"] = f.Tags
		}
		if f.ID != "" {
			props["finding_id"] = f.ID
		}
		if f.Source != "" {
			props["source"] = f.Source
		}
		if f.TemplateID != "" {
			props["template_id"] = f.TemplateID
		}
		if f.CVSS > 0 {
			props["cvss"] = f.CVSS
		}
		if len(f.Metadata) > 0 {
			props["metadata"] = f.Metadata
		}
		if len(props) > 0 {
			r.Properties = props
		}
		results = append(results, r)
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "aipostex",
				InformationURI: "https://github.com/professor-moody/aipostex",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling sarif: %w", err)
	}
	_, err = sw.w.Write(data)
	return err
}

func sarifRuleID(f report.Finding) string {
	if f.TemplateID != "" {
		return f.TemplateID
	}
	return f.Source + "/" + strings.ReplaceAll(strings.ToLower(f.Title), " ", "-")
}

func sarifLevel(severity string) string {
	switch severity {
	case report.SeverityCritical, report.SeverityHigh:
		return "error"
	case report.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifSecuritySeverity(f report.Finding) string {
	if f.CVSS > 0 {
		return fmt.Sprintf("%.1f", f.CVSS)
	}
	switch f.Severity {
	case report.SeverityCritical:
		return "9.5"
	case report.SeverityHigh:
		return "8.0"
	case report.SeverityMedium:
		return "5.5"
	case report.SeverityLow:
		return "2.5"
	default:
		return "1.0"
	}
}

func sarifFingerprint(target, ruleID string) string {
	h := sha256.Sum256([]byte(target + "|" + ruleID))
	return fmt.Sprintf("%x", h[:16])
}
