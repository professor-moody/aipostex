package vulncheck

import (
	"fmt"
	"strings"
)

type LintSeverity string

const (
	LintError   LintSeverity = "error"
	LintWarning LintSeverity = "warning"
)

type LintIssue struct {
	Severity   LintSeverity
	TemplateID string
	SourcePath string
	Rule       string
	Message    string
}

func LintTemplates(templates []*Template) []LintIssue {
	var issues []LintIssue
	for _, tmpl := range templates {
		if strings.TrimSpace(tmpl.Info.Type) == "" {
			issues = append(issues, lintIssue(tmpl, LintError, "missing-info-type", "info.type must be explicit: detection or exploit"))
		}
		if exploitNamedTemplate(tmpl) && !tmpl.IsExploit() {
			issues = append(issues, lintIssue(tmpl, LintError, "exploit-name-type-mismatch", "template id or tags indicate exploit but info.type is not exploit"))
		}
		if advisoryTemplate(tmpl) {
			issues = append(issues, lintAdvisory(tmpl)...)
		}
		if !tmpl.IsExploit() {
			issues = append(issues, lintReadOnlyMethods(tmpl)...)
		}
	}
	return issues
}

func lintAdvisory(tmpl *Template) []LintIssue {
	var issues []LintIssue
	idLower := strings.ToLower(tmpl.ID)
	tags := lowerSet(tmpl.Info.Tags)
	if strings.HasPrefix(idLower, "cve-") {
		if hasTagPrefix(tags, "ghsa") && !hasTagPrefix(tags, "cve") {
			issues = append(issues, lintIssue(tmpl, LintError, "advisory-tag-mismatch", "CVE template must not be tagged only as GHSA"))
		}
		if !hasTagPrefix(tags, "cve") {
			issues = append(issues, lintIssue(tmpl, LintWarning, "missing-cve-tag", "CVE template should include a cve-* tag"))
		}
	}
	if strings.HasPrefix(idLower, "ghsa-") {
		if hasTagPrefix(tags, "cve-") {
			issues = append(issues, lintIssue(tmpl, LintError, "advisory-tag-mismatch", "GHSA template must not use cve-* tags"))
		}
		if _, ok := tags["ghsa"]; !ok {
			issues = append(issues, lintIssue(tmpl, LintWarning, "missing-ghsa-tag", "GHSA template should include the ghsa tag"))
		}
	}
	if len(tmpl.Info.References) == 0 {
		issues = append(issues, lintIssue(tmpl, LintError, "advisory-missing-references", "advisory template must include references"))
	}
	if tmpl.Info.CVSS <= 0 {
		issues = append(issues, lintIssue(tmpl, LintWarning, "advisory-missing-cvss", "advisory template should include a positive CVSS score"))
	}
	if !hasAnyRemediation(tmpl) {
		issues = append(issues, lintIssue(tmpl, LintError, "advisory-missing-remediation", "at least one advisory finding must include remediation"))
	}
	return issues
}

func lintReadOnlyMethods(tmpl *Template) []LintIssue {
	var issues []LintIssue
	for i, step := range tmpl.Detect {
		if nonGET(step.Method) && !step.ReadOnly {
			issues = append(issues, lintIssue(tmpl, LintError, "detection-non-get-without-read-only",
				fmt.Sprintf("detect step %d uses %s without read_only: true", i, strings.ToUpper(step.Method))))
		}
	}
	for i, check := range tmpl.Checks {
		if nonGET(check.Method) && !check.ReadOnly {
			issues = append(issues, lintIssue(tmpl, LintError, "detection-non-get-without-read-only",
				fmt.Sprintf("check %d %q uses %s without read_only: true", i, check.Name, strings.ToUpper(check.Method))))
		}
	}
	return issues
}

func lintIssue(tmpl *Template, severity LintSeverity, rule, message string) LintIssue {
	return LintIssue{
		Severity:   severity,
		TemplateID: tmpl.ID,
		SourcePath: tmpl.SourcePath,
		Rule:       rule,
		Message:    message,
	}
}

func advisoryTemplate(tmpl *Template) bool {
	id := strings.ToLower(tmpl.ID)
	return strings.HasPrefix(id, "cve-") || strings.HasPrefix(id, "ghsa-") || strings.HasPrefix(id, "tra-")
}

func exploitNamedTemplate(tmpl *Template) bool {
	if strings.Contains(strings.ToLower(tmpl.ID), "exploit") {
		return true
	}
	for _, tag := range tmpl.Info.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), "exploit") {
			return true
		}
	}
	return false
}

func hasAnyRemediation(tmpl *Template) bool {
	for _, check := range tmpl.Checks {
		if strings.TrimSpace(check.Finding.Remediation) != "" {
			return true
		}
	}
	return false
}

func nonGET(method string) bool {
	return strings.ToUpper(strings.TrimSpace(method)) != httpMethodGet
}

const httpMethodGet = "GET"

func lowerSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	return out
}

func hasTagPrefix(tags map[string]struct{}, prefix string) bool {
	for tag := range tags {
		if strings.HasPrefix(tag, prefix) {
			return true
		}
	}
	return false
}
