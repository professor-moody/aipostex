package main

import (
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/internal/credchain"
	"github.com/professor-moody/aipostex/pkg/report"
)

// Regression for AIP34-K8S-SA-NOT-CHAINABLE: the stolen SA token must actually reach the
// dossier's loot/commands.sh. credchain.ExtractFromFindings skips non-chainable structured
// records, so the sa-loot record must be marked chainable — otherwise the promised
// k8s-sa-token re-auth follow-ons are never generated. This exercises the real path
// (lootCredentialRecord shape -> ExtractFromFindings -> GenerateChainActions).
func TestK8SSALootTokenReachesLootCommands(t *testing.T) {
	rec := lootCredentialRecord(
		"k8s-sa-token", "ml-prod/pod sa-token", "eyJhbGci.tokvalue.sig",
		"https://10.0.1.50:6443", "stolen SA bearer token")
	rec[0]["chainable"] = credchain.IsChainableType("k8s-sa-token")

	f := report.Finding{
		ID:       "sa-loot-1",
		Target:   "https://10.0.1.50:6443",
		Source:   report.SourceK8s,
		Metadata: map[string]interface{}{"extracted_credentials": rec},
	}

	store := credchain.ExtractFromFindings([]report.Finding{f})
	var joined string
	for _, a := range credchain.GenerateChainActions(store) {
		joined += a.Command + "\n"
	}

	for _, want := range []string{"access-review", "secret-read", "eyJhbGci.tokvalue.sig"} {
		if !strings.Contains(joined, want) {
			t.Errorf("k8s-sa-token loot command missing %q; got:\n%s", want, joined)
		}
	}
}
