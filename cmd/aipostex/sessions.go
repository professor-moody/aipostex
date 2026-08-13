package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/professor-moody/aipostex/internal/reportgen"
	"github.com/professor-moody/aipostex/internal/session"
	"github.com/professor-moody/aipostex/pkg/report"
)

var (
	sessionName  string
	sessionID    string
	sessionForce bool
	sessionDir   string
	sessionsAll  bool

	// export flags
	sessionExportFile   string
	sessionExportFormat string

	// notes flags
	sessionNotesText   string
	sessionNotesAppend bool
)

var sessionsCmd = &cobra.Command{
	Use:     "sessions",
	Short:   "Manage engagement sessions",
	Example: formatCommandExample("sessions start acme-engagement"),
	Long:    `Start, stop, list, and inspect engagement sessions that group findings across multiple commands.`,
	GroupID: operationsGroupID,
}

var sessionsStartCmd = &cobra.Command{
	Use:   "start [name]",
	Short: "Start a new engagement session",
	Long: `Start an engagement session. While it is active, every finding-emitting command
(discover, scan, and the exploit modules) automatically accumulates its findings into
the session's engagement dossier — no per-command --output/--format flags needed.
Read the loot back with 'report view <dir> --chains' (or cat/jq the files); 'sessions
stop' ends it.`,
	Args: cobra.MaximumNArgs(1),
	Example: strings.Join([]string{
		formatCommandExample("sessions start acme-mlops"),
		formatCommandExample("sessions start --name 'client-pentest-2025' --dir ~/engagements/client"),
	}, "\n"),
	RunE: runSessionsStart,
}

var sessionsPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Delete stopped sessions that captured no findings",
	Long: `Delete stopped sessions that captured no findings.

Housekeeping for the engagement store: probing runs that landed nothing still
leave session directories behind. Pruning clears the empty ones so the session
list reflects work that actually produced evidence. Sessions holding findings are
never removed.`,
	Example: formatCommandExample("sessions prune"),
	RunE:    runSessionsPrune,
}

var sessionsStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop an active session",
	Long: `Stop an active session.

Ends accumulation: after stopping, bare module commands no longer append their
findings to the engagement. The session and everything it captured remain on
disk — only the recording stops.`,
	Example: formatCommandExample("sessions stop --id ses-abc123"),
	RunE:    runSessionsStop,
}

var sessionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all sessions",
	Long: `List all sessions.

Shows every engagement recorded on this box with its state and finding count, so
you can see which session is currently accumulating and which past runs hold
evidence worth reporting on.`,
	Example: formatCommandExample("sessions list"),
	RunE:    runSessionsList,
}

var sessionsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show details for a session",
	Long: `Show the details for a session.

Reports what a single engagement captured — its findings, the credentials looted
into it, and its lifecycle state — without leaving the CLI or re-rendering a
report.`,
	Example: formatCommandExample("sessions show --id ses-abc123"),
	RunE:    runSessionsShow,
}

var sessionsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export findings scoped to a session",
	Long: `Export findings from an engagement file filtered to a specific session.
Only findings tagged with the given session ID are included.

Supports JSON, JSONL, HTML, and Markdown output formats.`,
	Example: strings.Join([]string{
		formatCommandExample("sessions export --id ses-abc123 --findings-file scan.json"),
		formatCommandExample("sessions export --id ses-abc123 --findings-file scan.json --format html -o session-report.html"),
		formatCommandExample("sessions export --findings-file scan.jsonl --format jsonl"),
	}, "\n"),
	RunE: runSessionsExport,
}

var sessionsNotesCmd = &cobra.Command{
	Use:   "notes",
	Short: "Set or append notes on a session",
	Long: `Set or append notes on an engagement session.
By default, replaces existing notes. Use --append to add to existing notes.`,
	Example: strings.Join([]string{
		formatCommandExample("sessions notes --id ses-abc123 --text 'Phase 1 complete'"),
		formatCommandExample("sessions notes --text 'Found creds on MLflow' --append"),
	}, "\n"),
	RunE: runSessionsNotes,
}

func init() {
	sessionsStartCmd.Flags().StringVar(&sessionName, "name", "", "Human-readable session name (or pass it as a positional argument)")
	sessionsStartCmd.Flags().StringVar(&sessionDir, "dir", "", "Engagement dossier directory (default: ~/engagements/<name>)")
	sessionsStartCmd.Flags().BoolVar(&sessionForce, "force", false, "Stop any active session and start a new one")
	sessionsListCmd.Flags().BoolVar(&sessionsAll, "all", false, "Include stopped, empty sessions")
	sessionsStopCmd.Flags().StringVar(&sessionID, "id", "", "Session ID to stop (default: active session)")
	sessionsShowCmd.Flags().StringVar(&sessionID, "id", "", "Session ID to show (default: active session)")

	sessionsExportCmd.Flags().StringVar(&sessionID, "id", "", "Session ID to export (default: active session)")
	sessionsExportCmd.Flags().StringVar(&sessionExportFile, "findings-file", "", "Path to engagement JSON or JSONL file (required)")
	sessionsExportCmd.Flags().StringVar(&sessionExportFormat, "format", "json", "Output format: json, jsonl, html, markdown")
	sessionsExportCmd.Flags().StringVarP(&cfg.OutputFile, "output", "o", "", "Output file path (default: stdout)")

	sessionsNotesCmd.Flags().StringVar(&sessionID, "id", "", "Session ID (default: active session)")
	sessionsNotesCmd.Flags().StringVar(&sessionNotesText, "text", "", "Note text to set or append (required)")
	sessionsNotesCmd.Flags().BoolVar(&sessionNotesAppend, "append", false, "Append to existing notes instead of replacing")

	sessionsCmd.AddCommand(sessionsStartCmd, sessionsStopCmd, sessionsListCmd, sessionsShowCmd, sessionsExportCmd, sessionsNotesCmd, sessionsPruneCmd)
}

func getSessionStore() (*session.Store, error) {
	return session.DefaultStore()
}

// activeEngagementDir returns the engagement dossier of the currently-active
// session, or "" if none. Resolved once per process (a CLI run is one command).
var (
	activeEngagementOnce  sync.Once
	activeEngagementCache string
)

func activeEngagementDir() string {
	activeEngagementOnce.Do(func() {
		store, err := getSessionStore()
		if err != nil {
			return
		}
		if sess, _ := store.Active(); sess != nil {
			activeEngagementCache = sess.Dir
		}
	})
	return activeEngagementCache
}

func runSessionsStart(cmd *cobra.Command, args []string) error {
	store, err := getSessionStore()
	if err != nil {
		return err
	}

	// Name may be a positional arg (`sessions start acme`) or --name.
	name := sessionName
	if name == "" && len(args) > 0 {
		name = strings.TrimSpace(args[0])
	}

	// Check for already-active session.
	active, _ := store.Active()
	if active != nil && !sessionForce {
		return fmt.Errorf("session %s is already active (started %s); stop it first or use --force to override",
			active.ID, active.StartTime.Format("2006-01-02 15:04:05"))
	}
	if active != nil && sessionForce {
		_, _ = store.Stop(active.ID)
	}

	// Resolve the engagement dossier directory: --dir, else ~/engagements/<name-or-id>.
	dir := strings.TrimSpace(sessionDir)
	if dir == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return fmt.Errorf("resolving home directory: %w", herr)
		}
		label := name
		if label == "" {
			label = "engagement"
		}
		dir = filepath.Join(home, "engagements", sanitizeEngagementLabel(label))
	}
	// Guard against silently merging into a prior engagement of the same name: if the
	// target dir already holds findings, refuse unless --force. Otherwise a repeated
	// `sessions start acme` would accumulate new findings on top of the old dossier.
	if f, _ := engagementStats(dir); f > 0 && !sessionForce {
		return fmt.Errorf("engagement dir %s already holds %d finding(s); "+
			"choose a new name (or --dir), or pass --force to add to the existing dossier", dir, f)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating engagement dir %s: %w", dir, err)
	}

	sess, err := store.Start(name, dir)
	if err != nil {
		return fmt.Errorf("starting session: %w", err)
	}
	infof("Session started: %s", sess.ID)
	if sess.Name != "" {
		infof("  Name:       %s", sess.Name)
	}
	infof("  Engagement: %s", sess.Dir)
	infof("  Findings from now on accumulate here; read them with: %s",
		formatCommandExample("report view "+sess.Dir+" --chains"))
	fmt.Println(sess.ID)
	return nil
}

// sanitizeEngagementLabel keeps a session name safe as a single directory name.
func sanitizeEngagementLabel(label string) string {
	repl := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}
	return strings.Map(repl, label)
}

func runSessionsStop(cmd *cobra.Command, args []string) error {
	store, err := getSessionStore()
	if err != nil {
		return err
	}

	id := strings.TrimSpace(sessionID)
	if id == "" {
		active, _ := store.Active()
		if active == nil {
			return fmt.Errorf("no active session; specify --id")
		}
		id = active.ID
	}

	sess, err := store.Stop(id)
	if err != nil {
		return fmt.Errorf("stopping session: %w", err)
	}
	findings, _ := engagementStats(sess.Dir)
	infof("Session stopped: %s (findings: %d, duration: %s)",
		sess.ID, findings, sess.EndTime.Sub(sess.StartTime).Truncate(1e9))
	if sess.Dir != "" {
		infof("  Engagement dossier: %s", sess.Dir)
		infof("  Review: %s", formatCommandExample("report view "+sess.Dir+" --chains"))
	}
	return nil
}

// engagementStats derives live counts from a session's dossier directory, so the
// list reflects what was actually captured rather than a counter that may drift.
func engagementStats(dir string) (findings, targets int) {
	if dir == "" {
		return 0, 0
	}
	if data, err := os.ReadFile(filepath.Join(dir, "findings.jsonl")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) != "" {
				findings++
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "targets.csv")); err == nil {
		rows := 0
		for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if strings.TrimSpace(line) != "" {
				rows++
			}
		}
		if rows > 0 {
			targets = rows - 1 // drop the header row
		}
	}
	return findings, targets
}

func runSessionsList(cmd *cobra.Command, args []string) error {
	store, err := getSessionStore()
	if err != nil {
		return err
	}
	sessions, err := store.List()
	if err != nil {
		return err
	}

	type row struct {
		id, status, name, dir string
		findings, targets     int
	}
	var rows []row
	hidden := 0
	for _, s := range sessions {
		f, t := engagementStats(s.Dir)
		// By default hide stopped, empty sessions (e.g. automated verify runs);
		// --all shows everything.
		if !sessionsAll && s.Status != "active" && f == 0 {
			hidden++
			continue
		}
		name := s.Name
		if name == "" {
			name = "(unnamed)"
		}
		status := s.Status
		if status == "active" {
			status = "ACTIVE"
		}
		rows = append(rows, row{s.ID, status, name, s.Dir, f, t})
	}

	if len(rows) == 0 {
		if hidden > 0 {
			infof("No active or non-empty sessions. (%d empty session(s) hidden; use --all to show, `sessions prune` to remove.)", hidden)
		} else {
			infof("No sessions found. Start one with: %s", formatCommandExample("sessions start <name>"))
		}
		return nil
	}

	fmt.Printf("%-22s  %-7s  %-24s  %8s  %7s  %s\n", "ID", "STATUS", "NAME", "FINDINGS", "TARGETS", "ENGAGEMENT")
	for _, r := range rows {
		fmt.Printf("%-22s  %-7s  %-24s  %8d  %7d  %s\n", r.id, r.status, r.name, r.findings, r.targets, r.dir)
	}
	if hidden > 0 {
		infof("(%d empty session(s) hidden; --all to show, `sessions prune` to remove.)", hidden)
	}
	return nil
}

func runSessionsPrune(cmd *cobra.Command, args []string) error {
	store, err := getSessionStore()
	if err != nil {
		return err
	}
	sessions, err := store.List()
	if err != nil {
		return err
	}
	removed := 0
	for _, s := range sessions {
		if s.Status == "active" {
			continue
		}
		if f, _ := engagementStats(s.Dir); f > 0 {
			continue
		}
		if err := store.Delete(s.ID); err != nil {
			warnf("could not delete %s: %v", s.ID, err)
			continue
		}
		removed++
	}
	infof("Pruned %d empty, stopped session(s).", removed)
	return nil
}

func runSessionsShow(cmd *cobra.Command, args []string) error {
	store, err := getSessionStore()
	if err != nil {
		return err
	}

	id := strings.TrimSpace(sessionID)
	if id == "" {
		active, _ := store.Active()
		if active == nil {
			return fmt.Errorf("no active session; specify --id")
		}
		id = active.ID
	}

	sess, err := store.Get(id)
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(sess, "", "  ")
	fmt.Println(string(data))
	return nil
}

func runSessionsExport(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(sessionExportFile) == "" {
		return fmt.Errorf("--findings-file is required")
	}

	store, err := getSessionStore()
	if err != nil {
		return err
	}

	id := strings.TrimSpace(sessionID)
	if id == "" {
		active, _ := store.Active()
		if active == nil {
			return fmt.Errorf("no active session; specify --id")
		}
		id = active.ID
	}

	// Verify session exists.
	sess, err := store.Get(id)
	if err != nil {
		return fmt.Errorf("loading session: %w", err)
	}

	// Load findings from the engagement file.
	collection, err := loadFindingCollection(sessionExportFile)
	if err != nil {
		return err
	}

	// Filter findings by session ID.
	filtered := filterFindingsBySession(collection.Findings, id)

	// Deduplicate: group by (target, template_id, source), keep highest severity.
	deduped := deduplicateSessionFindings(filtered)

	infof("Session %s: %d findings (from %d total, %d after dedup)", id, len(filtered), len(collection.Findings), len(deduped))

	format := strings.ToLower(strings.TrimSpace(sessionExportFormat))

	switch format {
	case "json":
		exportCollection := report.FindingCollection{
			EngagementID: collection.EngagementID,
			StartTime:    sess.StartTime,
			EndTime:      sess.EndTime,
			Findings:     deduped,
		}
		data, err := json.MarshalIndent(exportCollection, "", "  ")
		if err != nil {
			return fmt.Errorf("serializing findings: %w", err)
		}
		return writeExportOutput(data)

	case "jsonl":
		var lines []byte
		for _, f := range deduped {
			line, err := json.Marshal(f)
			if err != nil {
				warnf("serializing finding %s: %v", f.ID, err)
				continue
			}
			lines = append(lines, line...)
			lines = append(lines, '\n')
		}
		return writeExportOutput(lines)

	case "html":
		exportCollection := report.FindingCollection{
			EngagementID: collection.EngagementID,
			StartTime:    sess.StartTime,
			EndTime:      sess.EndTime,
			Findings:     deduped,
		}
		r := reportgen.Generate(exportCollection)
		output := reportgen.RenderHTML(r)
		return writeExportOutput([]byte(output))

	case "markdown", "md":
		exportCollection := report.FindingCollection{
			EngagementID: collection.EngagementID,
			StartTime:    sess.StartTime,
			EndTime:      sess.EndTime,
			Findings:     deduped,
		}
		r := reportgen.Generate(exportCollection)
		output := reportgen.RenderMarkdown(r)
		return writeExportOutput([]byte(output))

	default:
		return fmt.Errorf("unsupported export format %q (valid: json, jsonl, html, markdown)", format)
	}
}

func runSessionsNotes(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(sessionNotesText) == "" {
		return fmt.Errorf("--text is required")
	}

	store, err := getSessionStore()
	if err != nil {
		return err
	}

	id := strings.TrimSpace(sessionID)
	if id == "" {
		active, _ := store.Active()
		if active == nil {
			return fmt.Errorf("no active session; specify --id")
		}
		id = active.ID
	}

	if sessionNotesAppend {
		if err := store.AppendNotes(id, sessionNotesText); err != nil {
			return fmt.Errorf("appending notes: %w", err)
		}
		infof("Notes appended to session %s", id)
	} else {
		if err := store.SetNotes(id, sessionNotesText); err != nil {
			return fmt.Errorf("setting notes: %w", err)
		}
		infof("Notes set on session %s", id)
	}
	return nil
}

func filterFindingsBySession(findings []report.Finding, sessionID string) []report.Finding {
	var result []report.Finding
	for _, f := range findings {
		if sid, ok := f.Metadata["session_id"].(string); ok && sid == sessionID {
			result = append(result, f)
		}
	}
	return result
}

func deduplicateSessionFindings(findings []report.Finding) []report.Finding {
	type dedupKey struct {
		Target     string
		TemplateID string
		Source     string
	}

	severityRank := map[string]int{
		report.SeverityCritical: 4,
		report.SeverityHigh:     3,
		report.SeverityMedium:   2,
		report.SeverityLow:      1,
		report.SeverityInfo:     0,
	}

	best := make(map[dedupKey]report.Finding)
	order := make([]dedupKey, 0)

	for _, f := range findings {
		key := dedupKey{
			Target:     f.Target,
			TemplateID: f.TemplateID,
			Source:     f.Source,
		}
		// If no template_id, use title so non-template findings still dedup.
		if key.TemplateID == "" {
			key.TemplateID = f.Title
		}
		existing, exists := best[key]
		if !exists {
			best[key] = f
			order = append(order, key)
		} else if severityRank[f.Severity] > severityRank[existing.Severity] {
			best[key] = f
		}
	}

	result := make([]report.Finding, 0, len(best))
	for _, key := range order {
		result = append(result, best[key])
	}
	return result
}

func writeExportOutput(data []byte) error {
	if cfg.OutputFile != "" && cfg.OutputFile != "-" {
		if err := os.WriteFile(cfg.OutputFile, data, 0o600); err != nil {
			return fmt.Errorf("writing export: %w", err)
		}
		infof("Export written to %s", cfg.OutputFile)
		return nil
	}
	_, err := os.Stdout.Write(data)
	return err
}
