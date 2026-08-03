package main

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/credchain"
	"github.com/professor-moody/aipostex/internal/output"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

var (
	reportViewSource        string
	reportViewService       string
	reportViewTarget        string
	reportViewSeverity      string
	reportViewTitleContains string
	reportViewID            string
	reportViewEvidence      bool
	reportViewCredentials   bool
	reportViewCommands      bool
	reportViewChains        bool
	reportViewLimit         int
	reportViewDossierDir    string
)

var reportViewCmd = &cobra.Command{
	Use:   "view [findings.json|findings.jsonl]",
	Short: "Inspect raw findings, evidence, credentials, and generated commands",
	Long: `Inspect aipostex JSON or JSONL findings without losing raw evidence.
Use this after saving long or secret-heavy runs with --format jsonl -o findings.jsonl.

Filters (--source/--service, --severity, --target, --title-contains, --id) narrow
the console view and also scope what --chains and --dossier-dir see.

Chains (--chains)
  Reconstruct the operator's attack chains from the findings: for each looted,
  chainable credential, show find -> loot -> chain -> reached (the demo narrative).
  The find/loot/command spine is exact. "reached" is only a CORRELATION — a finding
  that already exists on the unlocked target (matched by host + module, and shown
  with its OWN landed value); it is NOT a verified credential replay and may even
  predate the loot. A chainable credential whose next hop hasn't been run yet renders
  as a gap that names the exact next command.

Dossier (--dossier-dir <dir>)
  Write the filtered findings as an operator file set instead of printing to the
  console — organized, parseable, copy-ready:
    credentials.json/.csv/.txt  looted credentials, each tagged with its
                                landed/stage and source finding
    commands.sh                 credential-injected aipostex follow-on commands, by target
    manual/                     NATIVE post-ex handoff: a kubeconfig from a stolen SA
                                token, env.sh exports, and pivots.sh (raw kubectl/curl)
    targets.csv                 in-scope targets: service, finding count, worst severity
    evidence/<id>.txt           raw evidence per finding
    findings.jsonl, README.md   the source findings + an index
  The credential files hold live secrets and are written owner-only (0600/0700).
  Query them with jq/grep — they carry source_service and target_url — or scope a
  service-specific dossier up front with --service.`,
	Example: strings.Join([]string{
		formatCommandExample("report view findings.jsonl"),
		formatCommandExample("report view findings.jsonl --chains"),
		formatCommandExample("report view findings.jsonl --credentials --commands"),
		formatCommandExample("report view findings.jsonl --source ray --title-contains runtime_env --evidence"),
		formatCommandExample("report view findings.jsonl --dossier-dir ./engagement-dossier"),
		formatCommandExample("report view findings.jsonl --service mlflow --dossier-dir ./mlflow-dossier"),
	}, "\n"),
	Args: cobra.ExactArgs(1),
	RunE: runReportView,
}

func init() {
	reportViewCmd.Flags().StringVar(&reportViewSource, "source", "", "Filter by finding source/module")
	reportViewCmd.Flags().StringVar(&reportViewService, "service", "", "Alias for --source: filter by service/module (e.g. ray, mlflow)")
	reportViewCmd.Flags().StringVar(&reportViewTarget, "target", "", "Filter by target substring")
	reportViewCmd.Flags().StringVar(&reportViewSeverity, "severity", "", "Filter by severity")
	reportViewCmd.Flags().StringVar(&reportViewTitleContains, "title-contains", "", "Filter by title substring")
	reportViewCmd.Flags().StringVar(&reportViewID, "id", "", "Filter by finding ID")
	reportViewCmd.Flags().BoolVar(&reportViewEvidence, "evidence", false, "Print full raw evidence for matching findings")
	reportViewCmd.Flags().BoolVar(&reportViewCredentials, "credentials", false, "Print extracted credential values for matching findings")
	reportViewCmd.Flags().BoolVar(&reportViewCommands, "commands", false, "Print credential-derived follow-up commands (with --chains: show each hop's full runnable command)")
	reportViewCmd.Flags().BoolVar(&reportViewChains, "chains", false, "Render looted credentials as attack chains (find → loot → chain → reached/gap)")
	reportViewCmd.Flags().IntVar(&reportViewLimit, "limit", 0, "Maximum matching findings to display (0 = no limit)")
	reportViewCmd.Flags().StringVar(&reportViewDossierDir, "dossier-dir", "", "Write an operator dossier (credentials, commands, targets, evidence) to this directory")
}

func runReportView(_ *cobra.Command, args []string) error {
	collection, err := loadFindingCollection(args[0])
	if err != nil {
		return err
	}
	findings := filterReportViewFindings(collection.Findings)
	fmt.Printf("Findings matched: %d", len(findings))
	if len(collection.Findings) != len(findings) {
		fmt.Printf(" of %d", len(collection.Findings))
	}
	fmt.Println()

	if reportViewDossierDir != "" {
		return writeDossier(reportViewDossierDir, findings, collection)
	}

	// Section flags compose: --chains, --credentials, and --evidence each render their own
	// section and can be combined in one view. With no section flag at all, print the list.
	if !reportViewChains && !reportViewEvidence && !reportViewCredentials && !reportViewCommands {
		printReportViewFindingList(findings)
		return nil
	}
	if reportViewChains {
		if err := renderChainView(findings, reportViewCommands); err != nil {
			return err
		}
	}
	if reportViewCredentials {
		printReportViewCredentials(findings)
	}
	// --commands is a standalone section only when NOT charting chains; with --chains it is
	// consumed as "show each hop's full command inline", so a flat section would just duplicate it.
	if reportViewCommands && !reportViewChains {
		printReportViewCommands(findings)
	}
	if reportViewEvidence {
		printReportViewEvidence(findings)
	}
	return nil
}

func filterReportViewFindings(findings []report.Finding) []report.Finding {
	filtered := make([]report.Finding, 0, len(findings))
	for _, finding := range findings {
		if !reportViewFindingMatches(finding) {
			continue
		}
		filtered = append(filtered, finding)
		if reportViewLimit > 0 && len(filtered) >= reportViewLimit {
			break
		}
	}
	return filtered
}

func reportViewFindingMatches(f report.Finding) bool {
	if reportViewID != "" && f.ID != reportViewID {
		return false
	}
	// --service is an alias for --source; --source wins if both are set.
	source := reportViewSource
	if source == "" {
		source = reportViewService
	}
	if source != "" && !strings.EqualFold(f.Source, source) {
		return false
	}
	if reportViewSeverity != "" && !strings.EqualFold(f.Severity, reportViewSeverity) {
		return false
	}
	if reportViewTarget != "" && !strings.Contains(strings.ToLower(f.Target), strings.ToLower(reportViewTarget)) {
		return false
	}
	if reportViewTitleContains != "" && !strings.Contains(strings.ToLower(f.Title), strings.ToLower(reportViewTitleContains)) {
		return false
	}
	return true
}

func printReportViewFindingList(findings []report.Finding) {
	if len(findings) == 0 {
		return
	}
	tbl := output.NewTable(
		output.Column{Header: "ID"},
		output.Column{Header: "SEVERITY"},
		output.Column{Header: "SOURCE"},
		output.Column{Header: "TARGET", Flex: true},
		output.Column{Header: "TITLE", Flex: true},
	)
	for _, finding := range findings {
		tbl.AddRow(
			finding.ID,
			finding.Severity,
			finding.Source,
			output.NormalizeCell(finding.Target),
			output.NormalizeCell(finding.Title),
		)
	}
	// Render once so columns align, then interleave each finding's preview sub-line
	// under its row (lines[0] is the header; lines[i+1] is findings[i]). Cap at the
	// frame width (not the uncapped TableWidth) so the aggregate table lines up with
	// the framed Evidence/Credentials sections printed below it in the same view.
	lines := tbl.Render(output.FrameWidth())
	fmt.Println(lines[0])
	for i, finding := range findings {
		fmt.Println(lines[i+1])
		if preview := reportViewFindingPreview(finding); preview != "" {
			fmt.Printf("  %s\n", preview)
		}
	}
}

func printReportViewEvidence(findings []report.Finding) {
	fmt.Println()
	fmt.Println(consoleSectionHeader("Evidence"))
	if len(findings) > 20 && reportViewID == "" && reportViewLimit == 0 {
		fmt.Printf("printing full evidence for %d findings; use --id, --title-contains, --severity, or --limit to narrow this view\n\n", len(findings))
	}
	for _, finding := range findings {
		fmt.Printf("%s  %s  %s\n", finding.ID, finding.Severity, finding.Title)
		if strings.TrimSpace(finding.Evidence) == "" {
			fmt.Println("(no raw evidence)")
		} else {
			// Full evidence (maxLines <= 0), reflowed/pretty-printed through the same
			// renderer the module output uses. No redaction — raw values are intentional.
			for _, line := range output.ReflowEvidence(finding.Evidence, output.FrameWidth(), 0) {
				fmt.Println(line)
			}
		}
		fmt.Println()
	}
}

func printReportViewCredentials(findings []report.Finding) {
	records := credentialRecordsForReportView(findings)
	fmt.Println()
	fmt.Println(consoleSectionHeader("Credentials"))
	if len(records) == 0 {
		fmt.Println("(none)")
		return
	}
	chainableCount := 0
	for _, rec := range records {
		if rec.Chainable {
			chainableCount++
		}
	}
	fmt.Printf("  %d credential(s): %d actionable pivot(s), %d viewer-only\n",
		len(records), chainableCount, len(records)-chainableCount)
	printReportViewCredentialGroup("Actionable Pivots", filterCredentialRecords(records, true))
	printReportViewCredentialGroup("Viewer-Only Secrets", filterCredentialRecords(records, false))
}

func printReportViewCredentialGroup(title string, records []credchain.CredentialRecord) {
	if len(records) == 0 {
		return
	}
	fmt.Printf("\n  %s\n", title)
	// No STATUS column: it would just repeat the group header ("Viewer-Only Secrets" /
	// "Actionable Pivots") on every row — pure redundancy, and the width that pushed the
	// widest rows past the terminal and wrapped the SOURCE tail.
	tbl := output.NewTable(
		output.Column{Header: "#", Align: output.AlignRight},
		output.Column{Header: "TYPE"},
		// NAME + TARGET must stay complete — a truncated credential name/endpoint is
		// useless for operator scanning (the full value is also printed below the row).
		output.Column{Header: "NAME", NoTrunc: true},
		output.Column{Header: "TARGET", NoTrunc: true},
		output.Column{Header: "SOURCE"},
	).WithIndent(4)
	for idx, rec := range records {
		target := rec.TargetURL
		if target == "" {
			target = rec.SourceTarget
		}
		tbl.AddRow(
			strconv.Itoa(idx+1),
			output.NormalizeCell(rec.Type),
			output.NormalizeCell(rec.Name),
			output.NormalizeCell(target),
			compactReportSourceID(rec.Source),
		)
	}
	// Render once for aligned columns, then print each row followed by its full,
	// untruncated value: (and optional note:) sub-lines — the credential value must
	// stay copy-complete, so it is never routed through a table column.
	lines := tbl.Render(output.TableWidth())
	fmt.Println(lines[0])
	for idx, rec := range records {
		fmt.Println(lines[idx+1])
		fmt.Printf("        value: %s\n", rec.Value)
		if rec.Note != "" {
			fmt.Printf("        note: %s\n", reportViewCredentialNote(rec.Note))
		}
	}
}

func printReportViewCommands(findings []report.Finding) {
	store := credchain.ExtractFromFindings(findings)
	actions := credchain.GenerateChainActions(store)
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].TargetURL != actions[j].TargetURL {
			return actions[i].TargetURL < actions[j].TargetURL
		}
		return actions[i].Command < actions[j].Command
	})
	fmt.Println()
	fmt.Println(consoleSectionHeader("Commands"))
	if len(actions) == 0 {
		fmt.Println("(none)")
		return
	}
	seen := make(map[string]struct{})
	grouped := make(map[string][]string)
	for _, action := range actions {
		command := formatCommandExample(action.Command)
		if _, ok := seen[command]; ok {
			continue
		}
		seen[command] = struct{}{}
		target := action.TargetURL
		if target == "" {
			target = "<target>"
		}
		grouped[target] = append(grouped[target], command)
	}
	targets := make([]string, 0, len(grouped))
	for target := range grouped {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		return reportViewTargetSortKey(targets[i]) < reportViewTargetSortKey(targets[j])
	})
	for _, target := range targets {
		fmt.Printf("\n  %s\n", target)
		for _, command := range grouped[target] {
			fmt.Printf("    %s\n", command)
		}
	}
}

func filterCredentialRecords(records []credchain.CredentialRecord, chainable bool) []credchain.CredentialRecord {
	out := make([]credchain.CredentialRecord, 0, len(records))
	for _, rec := range records {
		if rec.Chainable == chainable {
			out = append(out, rec)
		}
	}
	return out
}

func compactReportSourceID(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "-"
	}
	if len(source) <= 24 {
		return source
	}
	parts := strings.Split(source, "-")
	if len(parts) >= 2 {
		suffix := parts[1]
		if len(suffix) > 8 {
			suffix = suffix[:8]
		}
		return parts[0] + "-" + suffix
	}
	return source[:21] + "..."
}

func reportViewCredentialNote(note string) string {
	note = strings.TrimSpace(note)
	switch note {
	case "sensitive runtime_env value; no concrete aipostex follow-on module inferred":
		return "no concrete aipostex follow-on module inferred"
	default:
		return note
	}
}

func reportViewTargetSortKey(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return target
	}
	return u.Host + u.Path
}

func credentialRecordsForReportView(findings []report.Finding) []credchain.CredentialRecord {
	records := credchain.ExtractCredentialRecords(findings)
	seen := make(map[string]struct{})
	seenTypeValueSource := make(map[string]struct{})
	for _, rec := range records {
		seen[reportViewCredentialKey(rec)] = struct{}{}
		seenTypeValueSource[rec.Type+"\x00"+rec.Value+"\x00"+rec.Source] = struct{}{}
	}
	store := credchain.ExtractFromFindings(findings)
	for target, creds := range store.All() {
		for _, cred := range creds {
			if _, ok := seenTypeValueSource[cred.Type+"\x00"+cred.Value+"\x00"+cred.Source]; ok {
				continue
			}
			rec := credchain.CredentialRecord{
				Type:         cred.Type,
				Value:        cred.Value,
				Source:       cred.Source,
				SourceTarget: target,
				TargetURL:    target,
				Chainable:    len(credchain.GenerateChainActions(singleCredentialStore(target, cred))) > 0,
				Note:         "extracted from raw finding evidence",
			}
			key := reportViewCredentialKey(rec)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			records = append(records, rec)
		}
	}
	records = dedupeCredsPreferSpecificType(records)
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Chainable != records[j].Chainable {
			return records[i].Chainable
		}
		leftTarget := records[i].TargetURL
		if leftTarget == "" {
			leftTarget = records[i].SourceTarget
		}
		rightTarget := records[j].TargetURL
		if rightTarget == "" {
			rightTarget = records[j].SourceTarget
		}
		if leftTarget != rightTarget {
			return leftTarget < rightTarget
		}
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].Source < records[j].Source
	})
	return records
}

// dedupeCredsPreferSpecificType drops a generic/service-token record when the SAME
// value+target also carries a more specific type — e.g. `sk-proj-…` typed both
// `api-key` (from an OPENAI_API_KEY label) and `service-token` (from the hyphenated
// token regex) collapses to the single, more useful `api-key`.
func dedupeCredsPreferSpecificType(records []credchain.CredentialRecord) []credchain.CredentialRecord {
	keyOf := func(r credchain.CredentialRecord) string {
		t := r.TargetURL
		if t == "" {
			t = r.SourceTarget
		}
		return t + "\x00" + r.Value
	}
	best := make(map[string]int, len(records))
	for _, r := range records {
		k := keyOf(r)
		if s := credTypeSpecificity(r.Type); best[k] == 0 || s < best[k] {
			best[k] = s
		}
	}
	out := make([]credchain.CredentialRecord, 0, len(records))
	for _, r := range records {
		// Keep only records whose type is as specific as the best seen for this value.
		if credTypeSpecificity(r.Type) <= best[keyOf(r)] {
			out = append(out, r)
		}
	}
	return out
}

// credTypeSpecificity ranks how specific a credential type is (lower = more
// specific = preferred when the same value is classified multiple ways).
func credTypeSpecificity(t string) int {
	switch t {
	case "service-token":
		return 100
	case "api-key":
		return 90
	case "bearer-token":
		return 80
	default:
		return 1 // any concretely-named type (openai-api-key, hf-token, …)
	}
}

func singleCredentialStore(target string, cred credchain.Credential) *credchain.Store {
	store := credchain.NewStore()
	store.Add(target, cred)
	return store
}

func reportViewCredentialKey(rec credchain.CredentialRecord) string {
	return rec.Type + "\x00" + rec.Name + "\x00" + rec.Value + "\x00" + rec.Source + "\x00" + rec.TargetURL
}

func reportViewFindingPreview(f report.Finding) string {
	if strings.TrimSpace(f.Evidence) != "" {
		return stringutil.BoundedPreview(f.Evidence, 120)
	}
	return stringutil.BoundedPreview(f.Description, 120)
}
