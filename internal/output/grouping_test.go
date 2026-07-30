package output

import (
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
)

func TestGroupFindingsByHostBucketsFileDiscoveryUnderLocalFiles(t *testing.T) {
	groups := groupFindingsByHost([]report.Finding{
		{Source: report.SourceFileDiscovery, Target: "/tmp/one.env", Title: "one"},
		{Source: report.SourceFileDiscovery, Target: "/tmp/two.env", Title: "two"},
		{Source: report.SourceVulnCheck, Target: "http://10.0.0.5:11434", Title: "three"},
	})

	if len(groups) != 2 {
		t.Fatalf("expected 2 host groups, got %#v", groups)
	}
	if groups[0].host != "10.0.0.5" || groups[1].host != "local-files" {
		t.Fatalf("unexpected grouped hosts: %#v", groups)
	}
	if len(groups[1].findings) != 2 {
		t.Fatalf("expected 2 local file findings, got %#v", groups[1].findings)
	}
}
