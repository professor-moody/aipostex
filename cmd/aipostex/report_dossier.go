package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/professor-moody/aipostex/internal/credchain"
	"github.com/professor-moody/aipostex/pkg/report"
)

// dossierCredential is one credential in the dossier, joined to its source finding's
// landed/stage — the aipostex-native part: the operator can tell confirmed-usable loot
// from speculative loot at a glance, and where each secret came from.
type dossierCredential struct {
	Type          string `json:"type"`
	Name          string `json:"name,omitempty"`
	Value         string `json:"value"`
	SourceFinding string `json:"source_finding,omitempty"`
	SourceService string `json:"source_service,omitempty"`
	SourceTarget  string `json:"source_target,omitempty"`
	TargetURL     string `json:"target_url,omitempty"`
	Chainable     bool   `json:"chainable"`
	Stage         string `json:"stage,omitempty"`
	Landed        string `json:"landed,omitempty"`
	Note          string `json:"note,omitempty"`
}

type dossierCommandGroup struct {
	Target   string
	Commands []string
}

// writeDossier turns a filtered findings set into an operator dossier directory: the
// looted credentials (with landed/stage), the credential-injected follow-on commands, the
// in-scope targets, and the raw evidence — all in parseable, greppable files.
func writeDossier(dir string, findings []report.Finding, collection report.FindingCollection) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating dossier dir: %w", err)
	}

	findingByID := make(map[string]report.Finding, len(findings))
	for _, f := range findings {
		findingByID[f.ID] = f
	}

	creds := dossierCredentials(findings, findingByID)
	commands := dossierCommands(findings)

	if err := writeDossierCredentials(dir, creds); err != nil {
		return err
	}
	if err := writeDossierCommands(dir, commands); err != nil {
		return err
	}
	kubeconfigs, pivots, err := writeDossierManual(dir, creds)
	if err != nil {
		return err
	}
	targetCount, err := writeDossierTargets(dir, findings)
	if err != nil {
		return err
	}
	evidenceCount, err := writeDossierEvidence(dir, findings)
	if err != nil {
		return err
	}
	if err := writeDossierFindings(dir, findings); err != nil {
		return err
	}
	if err := writeDossierReadme(dir, findings, creds, commands, targetCount, evidenceCount, kubeconfigs, pivots); err != nil {
		return err
	}

	chainable, cmdCount := 0, 0
	for _, c := range creds {
		if c.Chainable {
			chainable++
		}
	}
	for _, g := range commands {
		cmdCount += len(g.Commands)
	}
	infof("wrote dossier to %s: %d credential(s) (%d chainable), %d command(s), %d native pivot(s), %d kubeconfig(s), %d target(s), %d evidence file(s)",
		dir, len(creds), chainable, cmdCount, pivots, kubeconfigs, targetCount, evidenceCount)
	return nil
}

func dossierCredentials(findings []report.Finding, findingByID map[string]report.Finding) []dossierCredential {
	records := credentialRecordsForReportView(findings)
	out := make([]dossierCredential, 0, len(records))
	for _, rec := range records {
		dc := dossierCredential{
			Type:          rec.Type,
			Name:          rec.Name,
			Value:         rec.Value,
			SourceFinding: rec.Source,
			SourceTarget:  rec.SourceTarget,
			TargetURL:     rec.TargetURL,
			Chainable:     rec.Chainable,
			Note:          rec.Note,
		}
		if f, ok := findingByID[rec.Source]; ok {
			dc.Stage = dossierMeta(f.Metadata, "stage")
			dc.Landed = dossierMeta(f.Metadata, "landed")
			dc.SourceService = dossierFindingService(f)
		}
		out = append(out, dc)
	}
	return out
}

func dossierCommands(findings []report.Finding) []dossierCommandGroup {
	store := credchain.ExtractFromFindings(findings)
	actions := credchain.GenerateChainActions(store)
	seen := make(map[string]struct{})
	grouped := make(map[string][]string)
	for _, a := range actions {
		cmd := formatCommandExample(a.Command)
		if _, ok := seen[cmd]; ok {
			continue
		}
		seen[cmd] = struct{}{}
		target := a.TargetURL
		if target == "" {
			target = "<target>"
		}
		grouped[target] = append(grouped[target], cmd)
	}
	targets := make([]string, 0, len(grouped))
	for t := range grouped {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	out := make([]dossierCommandGroup, 0, len(targets))
	for _, t := range targets {
		sort.Strings(grouped[t])
		out = append(out, dossierCommandGroup{Target: t, Commands: grouped[t]})
	}
	return out
}

func writeDossierCredentials(dir string, creds []dossierCredential) error {
	// credentials.json — the full structured record (secrets → mode 0600).
	buf, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		buf = []byte("[]")
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), append(buf, '\n'), 0o600); err != nil {
		return err
	}

	// credentials.csv
	var csvBuf strings.Builder
	w := csv.NewWriter(&csvBuf)
	_ = w.Write([]string{"type", "name", "value", "source_service", "source_finding", "source_target", "target_url", "chainable", "stage", "landed", "note"})
	for _, c := range creds {
		_ = w.Write([]string{c.Type, c.Name, c.Value, c.SourceService, c.SourceFinding, c.SourceTarget, c.TargetURL, fmt.Sprintf("%t", c.Chainable), c.Stage, c.Landed, c.Note})
	}
	w.Flush()
	if err := os.WriteFile(filepath.Join(dir, "credentials.csv"), []byte(csvBuf.String()), 0o600); err != nil {
		return err
	}

	// credentials.txt — copy-ready, grouped by source service.
	var txt strings.Builder
	txt.WriteString("# aipostex dossier — looted credentials (copy-ready), grouped by service.\n\n")
	byService := make(map[string][]dossierCredential)
	var services []string
	for _, c := range creds {
		svc := c.SourceService
		if svc == "" {
			svc = "unknown"
		}
		if _, ok := byService[svc]; !ok {
			services = append(services, svc)
		}
		byService[svc] = append(byService[svc], c)
	}
	sort.Strings(services)
	for _, svc := range services {
		txt.WriteString("# " + svc + "\n")
		for _, c := range byService[svc] {
			if c.Name != "" {
				txt.WriteString(c.Name + "=" + c.Value + "\n")
			} else {
				txt.WriteString(c.Value + "\n")
			}
		}
		txt.WriteString("\n")
	}
	return os.WriteFile(filepath.Join(dir, "credentials.txt"), []byte(txt.String()), 0o600)
}

func writeDossierCommands(dir string, groups []dossierCommandGroup) error {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# aipostex dossier — credential-injected follow-on commands.\n")
	b.WriteString("# Each command reuses a looted credential against the service where it applies.\n")
	b.WriteString("# Review before running; these are suggestions, not a script to run blind.\n\n")
	if len(groups) == 0 {
		b.WriteString("# No chainable credentials — nothing to run.\n")
	}
	for _, g := range groups {
		b.WriteString("# " + g.Target + "\n")
		for _, c := range g.Commands {
			b.WriteString(c + "\n")
		}
		b.WriteString("\n")
	}
	// 0o700, not 0o755: commands.sh embeds looted credentials inline, so it must
	// be no more readable than the 0o600 credential files — owner-only, but still
	// executable so the operator can run it directly.
	return os.WriteFile(filepath.Join(dir, "commands.sh"), []byte(b.String()), 0o700) //nolint:gosec // intentional owner-only executable operator script
}

func writeDossierTargets(dir string, findings []report.Finding) (int, error) {
	type tinfo struct {
		service string
		count   int
		maxSev  string
	}
	agg := make(map[string]*tinfo)
	var order []string
	for _, f := range findings {
		t := strings.TrimSpace(f.Target)
		if t == "" {
			continue
		}
		ti := agg[t]
		if ti == nil {
			ti = &tinfo{}
			agg[t] = ti
			order = append(order, t)
		}
		ti.count++
		if s := dossierFindingService(f); s != "" && ti.service == "" {
			ti.service = s
		}
		ti.maxSev = worseSeverity(ti.maxSev, f.Severity)
	}
	sort.Strings(order)

	var buf strings.Builder
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"target", "service", "findings", "max_severity"})
	for _, t := range order {
		ti := agg[t]
		_ = w.Write([]string{t, ti.service, fmt.Sprintf("%d", ti.count), ti.maxSev})
	}
	w.Flush()
	return len(order), os.WriteFile(filepath.Join(dir, "targets.csv"), []byte(buf.String()), 0o600)
}

func writeDossierEvidence(dir string, findings []report.Finding) (int, error) {
	evdir := filepath.Join(dir, "evidence")
	count := 0
	for _, f := range findings {
		if strings.TrimSpace(f.Evidence) == "" {
			continue
		}
		if count == 0 {
			if err := os.MkdirAll(evdir, 0o700); err != nil {
				return 0, err
			}
		}
		name := sanitizeDossierName(f.ID)
		if name == "" {
			name = fmt.Sprintf("finding-%d", count+1)
		}
		if err := os.WriteFile(filepath.Join(evdir, name+".txt"), []byte(f.Evidence), 0o600); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func writeDossierFindings(dir string, findings []report.Finding) error {
	var b strings.Builder
	for _, f := range findings {
		line, err := json.Marshal(f)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return os.WriteFile(filepath.Join(dir, "findings.jsonl"), []byte(b.String()), 0o600)
}

func writeDossierReadme(dir string, findings []report.Finding, creds []dossierCredential, commands []dossierCommandGroup, targetCount, evidenceCount, kubeconfigs, pivots int) error {
	stats := findingStats(findings)
	chainable, cmdCount := 0, 0
	for _, c := range creds {
		if c.Chainable {
			chainable++
		}
	}
	for _, g := range commands {
		cmdCount += len(g.Commands)
	}
	var b strings.Builder
	b.WriteString("# aipostex dossier\n\n")
	b.WriteString("Operator files generated by `aipostex report view --dossier-dir`.\n\n")
	fmt.Fprintf(&b, "- **Findings:** %d  (%d critical, %d high, %d medium, %d low, %d info)\n",
		len(findings), stats[report.SeverityCritical], stats[report.SeverityHigh],
		stats[report.SeverityMedium], stats[report.SeverityLow], stats[report.SeverityInfo])
	fmt.Fprintf(&b, "- **Credentials:** %d  (%d chainable)\n", len(creds), chainable)
	fmt.Fprintf(&b, "- **Commands:** %d aipostex, %d native pivot(s), %d kubeconfig(s)\n", cmdCount, pivots, kubeconfigs)
	fmt.Fprintf(&b, "- **Targets:** %d\n", targetCount)
	fmt.Fprintf(&b, "- **Evidence files:** %d\n\n", evidenceCount)
	b.WriteString("## Files\n\n")
	b.WriteString("| File | Contents |\n|---|---|\n")
	b.WriteString("| `credentials.json` / `.csv` | Looted credentials, each tagged with its **`landed`/`stage`** and **source finding** — so you know what's confirmed-usable vs speculative. |\n")
	b.WriteString("| `credentials.txt` | Copy-ready `name=value` credentials, grouped by service. |\n")
	b.WriteString("| `commands.sh` | Credential-injected `aipostex` follow-on commands, grouped by target. Review before running. |\n")
	b.WriteString("| `manual/kubeconfig-<ns>` | Ready-to-use kubeconfig(s) built from a stolen SA token: `kubectl --kubeconfig manual/kubeconfig-<ns> get secrets -A`. |\n")
	b.WriteString("| `manual/env.sh` | Looted credentials as `export` lines — `source` it, then reuse `$VARS` in raw curl/kubectl. |\n")
	b.WriteString("| `manual/pivots.sh` | **Native** post-exploitation one-liners (kubectl/curl) — the by-hand counterpart to `commands.sh`. Read-only unless a line is marked DESTRUCTIVE. |\n")
	b.WriteString("| `targets.csv` | In-scope targets: service, finding count, worst severity. |\n")
	b.WriteString("| `evidence/` | Raw evidence per finding (`<finding-id>.txt`). |\n")
	b.WriteString("| `findings.jsonl` | The findings this dossier was built from. |\n")
	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(b.String()), 0o600)
}

// --- small helpers ---

func dossierMeta(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
		return strings.TrimSpace(fmt.Sprint(v))
	}
	return ""
}

func dossierFindingService(f report.Finding) string {
	if s := findingService(f); s != "" { // tag-based inference (scan.go)
		return s
	}
	for _, key := range []string{"service", "module", "provider"} {
		if s := dossierMeta(f.Metadata, key); s != "" {
			return s
		}
	}
	return f.Source
}

func dossierSevRank(s string) int {
	switch report.NormalizeSeverity(s) {
	case report.SeverityCritical:
		return 5
	case report.SeverityHigh:
		return 4
	case report.SeverityMedium:
		return 3
	case report.SeverityLow:
		return 2
	case report.SeverityInfo:
		return 1
	}
	return 0
}

func worseSeverity(a, b string) string {
	if dossierSevRank(a) >= dossierSevRank(b) && a != "" {
		return report.NormalizeSeverity(a)
	}
	return report.NormalizeSeverity(b)
}

func sanitizeDossierName(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
