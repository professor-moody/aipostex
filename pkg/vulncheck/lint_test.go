package vulncheck

import "testing"

func TestLintTemplatesDetectsSafetyAndAdvisoryIssues(t *testing.T) {
	tmpl := &Template{
		ID:         "ghsa-test-exploit",
		SourcePath: "unit.yaml",
		Info: TemplateInfo{
			Name:        "Bad GHSA",
			Severity:    "high",
			Author:      "unit",
			Description: "bad template",
			Tags:        []string{"cve-2025", "exploit"},
		},
		Checks: []Check{
			{
				Name:     "post detect",
				Method:   "POST",
				Path:     "/message",
				Matchers: []Matcher{{Type: MatchStatus, Value: "200"}},
				Finding:  FindingTemplate{Title: "title", Description: "desc"},
			},
		},
	}
	issues := LintTemplates([]*Template{tmpl})
	for _, rule := range []string{
		"missing-info-type",
		"exploit-name-type-mismatch",
		"advisory-missing-references",
		"advisory-tag-mismatch",
		"advisory-missing-remediation",
		"detection-non-get-without-read-only",
	} {
		if !hasLintRule(issues, rule) {
			t.Fatalf("expected lint rule %q in %#v", rule, issues)
		}
	}
}

func TestLintTemplatesAllowsReadOnlyPostDetection(t *testing.T) {
	tmpl := &Template{
		ID: "mcp-detect",
		Info: TemplateInfo{
			Name:        "MCP detect",
			Type:        TemplateTypeDetection,
			Severity:    "medium",
			Author:      "unit",
			Description: "read-only detect",
			Tags:        []string{"mcp"},
		},
		Checks: []Check{
			{
				Name:     "initialize",
				Method:   "POST",
				ReadOnly: true,
				Path:     "/message",
				Matchers: []Matcher{{Type: MatchStatus, Value: "200"}},
				Finding:  FindingTemplate{Title: "title", Description: "desc"},
			},
		},
	}
	if issues := LintTemplates([]*Template{tmpl}); len(issues) != 0 {
		t.Fatalf("expected no lint issues, got %#v", issues)
	}
}

func hasLintRule(issues []LintIssue, rule string) bool {
	for _, issue := range issues {
		if issue.Rule == rule {
			return true
		}
	}
	return false
}
