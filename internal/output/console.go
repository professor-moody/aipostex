package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"golang.org/x/term"

	"github.com/professor-moody/aipostex/internal/assessment"
	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

// Package-level console presentation state, set once from CLI flags before commands
// run (see the root PersistentPreRunE). Kept package-level so the many console-writer
// creation sites don't each need the flag threaded through.
var (
	forcedWidth   int  // --width N (0 = auto-detect)
	noBanner      bool // --no-banner / --quiet
	defaultWidth  = 100
	maxAutoWidth  = 100 // ceiling for auto-detected width (see capAutoWidth)
	minFieldAvail = 24
)

// SetConsoleWidth pins the console framing width (0 = auto-detect from the terminal).
func SetConsoleWidth(w int) { forcedWidth = w }

// SetNoBanner suppresses the startup banner when true.
func SetNoBanner(b bool) { noBanner = b }

// resolveWidth picks the framing width: an explicit --width, else the terminal size
// of w (when it's a TTY), else $COLUMNS, else a readable default. Auto-detected widths
// are ceilinged by capAutoWidth so a very wide terminal doesn't stretch prose/dividers.
func resolveWidth(w io.Writer) int { return resolveWidthMode(w, true) }

// resolveWidthUncapped is resolveWidth without the auto-width ceiling — used for tables,
// which should use the full terminal so wide columns (e.g. VERSION) aren't truncated.
func resolveWidthUncapped(w io.Writer) int { return resolveWidthMode(w, false) }

func resolveWidthMode(w io.Writer, capped bool) int {
	if forcedWidth > 0 {
		return forcedWidth
	}
	apply := func(n int) int {
		if capped {
			return capAutoWidth(n)
		}
		return n
	}
	if f, ok := w.(*os.File); ok {
		if width, _, err := term.GetSize(int(f.Fd())); err == nil && width > 0 {
			return apply(width)
		}
	}
	if c := os.Getenv("COLUMNS"); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n > 0 {
			return apply(n)
		}
	}
	return defaultWidth
}

// capAutoWidth ceilings an auto-detected terminal width at maxAutoWidth so a very wide
// terminal doesn't stretch the section dividers, the footer rule, and finding content
// edge-to-edge — the layout stays in a readable column. An explicit --width bypasses
// this (handled by the forcedWidth short-circuit in resolveWidth) for operators who want
// the full width, e.g. for the discovery table.
func capAutoWidth(w int) int {
	if w > maxAutoWidth {
		return maxAutoWidth
	}
	return w
}

// FrameWidth resolves the framing width for plain-text printers that render outside a
// ConsoleWriter (the cmd-package module summaries, Next Actions, and evidence hint,
// which print to stderr). It uses the same precedence as the console writer — an
// explicit --width, else stderr's terminal size, else $COLUMNS, else the default — so
// those lines wrap to the same frame as the finding blocks instead of breaking mid-word.
func FrameWidth() int { return resolveWidth(os.Stderr) }

// TableWidth is the width for standalone column tables (discovery). Unlike FrameWidth
// it is NOT ceilinged at maxAutoWidth, so a table uses the full terminal and wide columns
// like VERSION stay intact on a wide terminal; an explicit --width still overrides. The
// report view instead caps its table at FrameWidth so it lines up with the framed
// Evidence/Credentials sections beneath it.
func TableWidth() int { return resolveWidthUncapped(os.Stderr) }

// underGutter computes the layout for a hang-indented, labeled line: the column where
// the value begins (leading indent + label + a trailing space when labeled), the full
// first-line prefix, and the continuation pad.
func underGutter(indent int, label string) (gutter int, prefix, hang string) {
	gutter = indent + stringutil.VisibleWidth(label)
	prefix = strings.Repeat(" ", indent) + label
	if label != "" {
		gutter++
		prefix += " "
	}
	return gutter, prefix, strings.Repeat(" ", gutter)
}

// underAvail is the width left for a value after the gutter, floored so a deep indent
// never collapses wrapping to nothing.
func underAvail(gutter int) int {
	if a := FrameWidth() - gutter; a >= minFieldAvail {
		return a
	}
	return minFieldAvail
}

func assembleUnder(prefix, hang string, body []string) []string {
	if len(body) == 0 {
		body = []string{""}
	}
	out := make([]string, 0, len(body))
	out = append(out, prefix+body[0])
	for _, ln := range body[1:] {
		out = append(out, hang+ln)
	}
	return out
}

// WrapUnder frames one labeled line for plain-text printers: value is word-wrapped to
// the frame and continuation lines hang under the value column. Pass label "" for an
// unlabeled line indented by indent spaces. Returned lines carry no trailing newline.
func WrapUnder(indent int, label, value string) []string {
	gutter, prefix, hang := underGutter(indent, label)
	return assembleUnder(prefix, hang, stringutil.WrapWords(value, underAvail(gutter)))
}

// PackUnder is WrapUnder for pre-formed parts (e.g. svc=N pairs, "a | b | c" segments)
// that must never split across a line boundary: parts are packed onto frame-width lines
// joined by sep, hang-indented under the value column.
func PackUnder(indent int, label string, parts []string, sep string) []string {
	gutter, prefix, hang := underGutter(indent, label)
	return assembleUnder(prefix, hang, stringutil.PackParts(parts, sep, underAvail(gutter)))
}

// Writer interface for all output formatters
type Writer interface {
	WriteFinding(f report.Finding) error
	WriteHeader() error
	WriteFooter(stats map[string]int) error
	Close() error
}

// ConsoleWriter writes color-coded findings to terminal
type ConsoleWriter struct {
	w                   io.Writer
	verbose             bool
	showBanner          bool
	grouped             bool
	suppressNextActions bool
	width               int
	findings            []report.Finding
	hostNext            map[string]HostNextSteps
}

// HostNextSteps is the curated "start here" guidance the caller folds into a host's
// grouped findings block: one read-only command per service on the host, plus a count
// of the remaining commands available under -v.
type HostNextSteps struct {
	Commands  []string
	MoreCount int
}

func NewConsoleWriter(verbose bool) *ConsoleWriter {
	showBanner := isInteractiveStream(os.Stdout)
	return newConsoleWriter(os.Stdout, verbose, showBanner)
}

func NewConsoleWriterTo(w io.Writer, verbose bool) *ConsoleWriter {
	return newConsoleWriter(w, verbose, isInteractiveWriter(w))
}

// NewGroupedConsoleWriter returns a console writer that buffers findings
// and emits them grouped by host in WriteFooter.
func NewGroupedConsoleWriter(verbose bool) *ConsoleWriter {
	showBanner := isInteractiveStream(os.Stdout)
	cw := newConsoleWriter(os.Stdout, verbose, showBanner)
	cw.grouped = true
	cw.suppressNextActions = true
	return cw
}

func NewGroupedConsoleWriterTo(w io.Writer, verbose bool) *ConsoleWriter {
	cw := newConsoleWriter(w, verbose, isInteractiveWriter(w))
	cw.grouped = true
	cw.suppressNextActions = true
	return cw
}

func newConsoleWriter(w io.Writer, verbose, showBanner bool) *ConsoleWriter {
	return &ConsoleWriter{w: w, verbose: verbose, showBanner: showBanner, width: resolveWidth(w)}
}

func (cw *ConsoleWriter) SetSuppressNextActions(suppress bool) {
	cw.suppressNextActions = suppress
}

// SetHostNextSteps registers the per-host "next step" commands to fold into each
// grouped findings block (keyed by the same host key as groupFindingsByHost). Only
// rendered in the non-verbose grouped view; -v keeps the full separate catalog.
func (cw *ConsoleWriter) SetHostNextSteps(next map[string]HostNextSteps) {
	cw.hostNext = next
}

func (cw *ConsoleWriter) WriteHeader() error {
	if noBanner || !cw.showBanner {
		return nil
	}
	banner := `
  █████╗ ██╗██████╗  ██████╗ ███████╗████████╗███████╗██╗  ██╗
 ██╔══██╗██║██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝██╔════╝╚██╗██╔╝
 ███████║██║██████╔╝██║   ██║███████╗   ██║   █████╗   ╚███╔╝
 ██╔══██║██║██╔═══╝ ██║   ██║╚════██║   ██║   ██╔══╝   ██╔██╗
 ██║  ██║██║██║     ╚██████╔╝███████║   ██║   ███████╗██╔╝ ██╗
 ╚═╝  ╚═╝╚═╝╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
 ░░   ░░ ░░ ░░        ░░░░░   ░░░░░░     ░░    ░░░░░░  ░░   ░░
             AI Infrastructure Offensive Security

`
	_, err := fmt.Fprint(cw.w, color.CyanString(banner))
	return err
}

func (cw *ConsoleWriter) WriteFinding(f report.Finding) error {
	if cw.grouped {
		cw.findings = append(cw.findings, f)
		return nil
	}
	return cw.writeFindingFlat(f)
}

// fieldGutter is the column where a labeled field's value (and its wrapped
// continuation lines) begins: two-space indent + the label + one space.
func (cw *ConsoleWriter) fieldGutter(labelPlain string) int {
	return 2 + stringutil.VisibleWidth(labelPlain) + 1
}

// fieldAvail is the width available for a field's value after the gutter.
func (cw *ConsoleWriter) fieldAvail(labelPlain string) int {
	a := cw.width - cw.fieldGutter(labelPlain)
	if a < minFieldAvail {
		a = minFieldAvail
	}
	return a
}

// emitField prints "  <label> <line0>" and hang-indents any continuation lines
// under the value column. Lines are pre-wrapped by the caller.
func (cw *ConsoleWriter) emitField(labelPlain string, lines []string) error {
	if len(lines) == 0 {
		lines = []string{""}
	}
	if _, err := fmt.Fprintf(cw.w, "  %s %s\n", color.HiBlackString(labelPlain), lines[0]); err != nil {
		return err
	}
	if len(lines) == 1 {
		return nil
	}
	pad := strings.Repeat(" ", cw.fieldGutter(labelPlain))
	for _, ln := range lines[1:] {
		if _, err := fmt.Fprintf(cw.w, "%s%s\n", pad, ln); err != nil {
			return err
		}
	}
	return nil
}

// writeField wraps a plain value to the frame and emits it under labelPlain.
func (cw *ConsoleWriter) writeField(labelPlain, value string) error {
	return cw.emitField(labelPlain, stringutil.WrapWords(value, cw.fieldAvail(labelPlain)))
}

// writeTitle prints the badge + source + title line, wrapping a long title with a
// hanging indent aligned under the title column.
func (cw *ConsoleWriter) writeTitle(f report.Finding) error {
	badge := FormatSeverity(f.Severity)
	source := color.HiBlackString("[%s]", f.Source)
	prefix := stringutil.VisibleWidth(badge) + 1 + stringutil.VisibleWidth(source) + 1
	avail := cw.width - prefix
	if avail < minFieldAvail {
		avail = minFieldAvail
	}
	lines := stringutil.WrapWords(f.Title, avail)
	if _, err := fmt.Fprintf(cw.w, "%s %s %s\n", badge, source, lines[0]); err != nil {
		return err
	}
	pad := strings.Repeat(" ", prefix)
	for _, ln := range lines[1:] {
		if _, err := fmt.Fprintf(cw.w, "%s%s\n", pad, ln); err != nil {
			return err
		}
	}
	return nil
}

func (cw *ConsoleWriter) writeFindingFlat(f report.Finding) error {
	// --- header: what, and where ---
	if err := cw.writeTitle(f); err != nil {
		return err
	}
	if err := cw.writeField("target:", f.Target); err != nil {
		return err
	}
	if f.TemplateID != "" {
		if err := cw.writeField("template:", f.TemplateID); err != nil {
			return err
		}
	}
	// context: keep every populated key=value pair, wrapping only at pair
	// boundaries so a pair is never split across lines.
	if parts := metadataSummaryParts(f); len(parts) > 0 {
		if err := cw.emitField("context:", stringutil.PackParts(parts, "  ", cw.fieldAvail("context:"))); err != nil {
			return err
		}
	}

	// A blank line sets each following section off from the header (and each other) so a
	// finding block reads as grouped fields, not one dense wall.
	blank := func() error { _, err := fmt.Fprintln(cw.w); return err }

	// --- loot: the structured credentials a finding carries (k8s secrets, wandb/ray/
	// kubeflow/jupyter/mlflow secrets). Rendered aligned and in full — never truncated —
	// so the operator can read and copy them straight off the terminal. ---
	creds := findingCredentials(f)
	if len(creds) > 0 {
		if err := blank(); err != nil {
			return err
		}
		if err := cw.writeCredentials(creds); err != nil {
			return err
		}
	}

	// --- actions: dedupe note + per-finding follow-on commands (suppressed when the run
	// prints an aggregate Next Actions section). ---
	dedupe := dedupeSummary(f)
	var nexts []string
	if !cw.suppressNextActions {
		nexts = workflowDisplay(f)
	}
	if dedupe != "" || len(nexts) > 0 {
		if err := blank(); err != nil {
			return err
		}
		if dedupe != "" {
			if err := cw.writeField("dedupe:", dedupe); err != nil {
				return err
			}
		}
		for _, next := range nexts {
			// Wrap long commands with hanging indentation so they don't overflow the
			// terminal. The continuation is indented under "next:", so it can't read as a
			// separate command; long single args (e.g. a --system-prompt) stay whole.
			if err := cw.emitField("next:", stringutil.WrapWordsKeepLong(next, cw.fieldAvail("next:"))); err != nil {
				return err
			}
		}
	}

	// --- detail: description (-v) and evidence. Evidence is hidden when it just repeats a
	// value already in the creds: block (don't show the same secret twice), and in the
	// default view when a creds: block is present (the block is the readable form); -v
	// shows the full raw evidence for its provenance. ---
	showDesc := cw.verbose && f.Description != ""
	verboseEvidence := cw.verbose || metadataFlag(f, "evidence_full")
	evidence := evidenceForDisplay(f)
	showEvidence := evidence != "" && !evidenceDupesCredentials(f, creds) && (verboseEvidence || len(creds) == 0)
	if showDesc || showEvidence {
		if err := blank(); err != nil {
			return err
		}
		if showDesc {
			if err := cw.writeField("desc:", stringutil.BoundedPreview(f.Description, 260)); err != nil {
				return err
			}
		}
		if showEvidence {
			if verboseEvidence {
				if err := cw.writeFullEvidence(f); err != nil {
					return err
				}
			} else if err := cw.writeEvidencePreview(evidence); err != nil {
				return err
			}
		}
	}

	if len(f.Tags) > 0 {
		if err := blank(); err != nil {
			return err
		}
		if err := cw.writeField("tags:", strings.Join(f.Tags, ", ")); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(cw.w)
	return err
}

// evidenceDupesCredentials reports whether a finding's raw evidence is just a credential
// value already shown in the creds: block (e.g. a mined notebook key whose Evidence is
// the key itself), so the same secret isn't printed twice — in either view.
func evidenceDupesCredentials(f report.Finding, creds []extractedCredential) bool {
	e := strings.TrimSpace(f.Evidence)
	if e == "" || len(creds) == 0 {
		return false
	}
	for _, c := range creds {
		if strings.TrimSpace(c.value) == e {
			return true
		}
	}
	return false
}

// extractedCredential is one name/value pair surfaced in the console creds: block.
type extractedCredential struct {
	name  string
	value string
}

// findingCredentials returns the structured credentials a finding carries in
// metadata["extracted_credentials"], accepting both the in-process
// []map[string]interface{} form and the []interface{} form findings take after a JSON
// round-trip. Entries without a value are skipped; a nameless entry falls back to its
// type so it still renders.
func findingCredentials(f report.Finding) []extractedCredential {
	if len(f.Metadata) == 0 {
		return nil
	}
	raw, ok := f.Metadata["extracted_credentials"]
	if !ok {
		return nil
	}
	var items []interface{}
	switch v := raw.(type) {
	case []interface{}:
		items = v
	case []map[string]interface{}:
		items = make([]interface{}, 0, len(v))
		for _, m := range v {
			items = append(items, m)
		}
	default:
		return nil
	}
	creds := make([]extractedCredential, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		value := credMapString(m, "value")
		if value == "" {
			continue
		}
		name := credMapString(m, "name")
		if name == "" {
			name = credMapString(m, "type")
		}
		if name == "" {
			name = "credential"
		}
		creds = append(creds, extractedCredential{name: name, value: value})
	}
	return creds
}

func credMapString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// writeCredentials renders the creds: block as aligned "NAME = VALUE" rows: names are
// left-padded to the longest so the values line up in a column. Each value is emitted on
// one line, intact — a credential is never wrapped or truncated, so it stays
// copy-complete; a long value (e.g. a connection string) overflows the frame rather than
// breaking mid-token, and the terminal soft-wraps it if the window is narrow.
func (cw *ConsoleWriter) writeCredentials(creds []extractedCredential) error {
	nameW := 0
	for _, c := range creds {
		if w := stringutil.VisibleWidth(c.name); w > nameW {
			nameW = w
		}
	}
	var lines []string
	for _, c := range creds {
		head := c.name + strings.Repeat(" ", nameW-stringutil.VisibleWidth(c.name)) + " = "
		lines = append(lines, head+c.value)
	}
	return cw.emitField("creds:", lines)
}

// previewEvidenceLineCap bounds how many wrapped evidence lines the default (non-verbose)
// view shows before pointing at -v, keeping a large blob skimmable without the mangled
// single-line run-on the old bounded preview produced.
const previewEvidenceLineCap = 8

// maybeIndentJSON pretty-prints s for console display when it is a single-line JSON
// object or array (e.g. a raw notebook blob), so it reads as structured JSON instead of
// one long run-on. Anything else — plain text, an already multi-line blob, a
// summary-prefixed preview — is returned unchanged. Display only: the finding's stored
// Evidence and the -o json/jsonl output keep the exact raw value.
func maybeIndentJSON(s string) string {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 2 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return s
	}
	if strings.ContainsRune(trimmed, '\n') {
		return s // already multi-line; leave existing formatting alone
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(trimmed), "", "  "); err != nil {
		return s
	}
	return buf.String()
}

// IndentJSON pretty-prints a single-line JSON object/array for display; non-JSON or
// already-multiline input is returned unchanged. Exported for the `request` command's
// default body rendering (its --raw flag bypasses this).
func IndentJSON(s string) string { return maybeIndentJSON(s) }

// ReflowEvidence pretty-prints single-line JSON and word-wraps evidence to width,
// preserving the source line structure. When maxLines > 0 it caps the output at
// maxLines with a "… (N more)" footer; maxLines <= 0 returns every line (the full
// evidence, e.g. for `report view --evidence`). This is the single evidence renderer
// shared by the module console output and the report-view command so both frame and
// reflow identically. Display only — the stored Evidence and -o json/jsonl keep the
// exact raw value.
func ReflowEvidence(evidence string, width, maxLines int) []string {
	evidence = maybeIndentJSON(evidence)
	if width < 1 {
		width = 1
	}
	var wrapped []string
	for _, src := range strings.Split(strings.TrimRight(evidence, "\n"), "\n") {
		if strings.TrimSpace(src) == "" {
			wrapped = append(wrapped, "")
			continue
		}
		// Pretty-print a JSON blob that sits on a single line WITHIN the evidence (e.g.
		// the body after a "=== RESPONSE (200) ===" header) so it renders as indented
		// JSON instead of a mid-token-wrapped run-on. A line that fits is kept exactly
		// (preserving JSON indentation); only an over-wide line is wrapped, KeepLong so a
		// URL/DSN/credential overflows whole rather than being chopped mid-token.
		for _, jline := range strings.Split(maybeIndentJSON(src), "\n") {
			if stringutil.VisibleWidth(jline) <= width {
				wrapped = append(wrapped, jline)
			} else {
				wrapped = append(wrapped, stringutil.WrapWordsKeepLong(jline, width)...)
			}
		}
	}
	for len(wrapped) > 0 && wrapped[len(wrapped)-1] == "" {
		wrapped = wrapped[:len(wrapped)-1]
	}
	if maxLines > 0 && len(wrapped) > maxLines {
		more := len(wrapped) - maxLines
		wrapped = append(wrapped[:maxLines:maxLines],
			color.HiBlackString("… (%d more line(s) — re-run with -v for full evidence)", more))
	}
	return wrapped
}

// writeEvidencePreview renders evidence for the default view: reflowed to the frame
// and capped at previewEvidenceLineCap lines with a "… (N more, -v)" footer.
func (cw *ConsoleWriter) writeEvidencePreview(evidence string) error {
	return cw.emitField("evidence:", ReflowEvidence(evidence, cw.fieldAvail("evidence:"), previewEvidenceLineCap))
}

func (cw *ConsoleWriter) WriteFooter(stats map[string]int) error {
	if cw.grouped {
		return cw.writeGroupedFindings(stats)
	}
	return cw.writeFlatFooter(stats)
}

// writeFlatFooter is intentionally a no-op: the severity tally and total that used to
// live here (with a full-width "────" rule above them) now lead the framed "── Summary ──"
// block that each command prints (see printSummaryHeader), so the findings and the summary
// read as one flowing block instead of a rule + tally + a separate summary divider.
func (cw *ConsoleWriter) writeFlatFooter(stats map[string]int) error {
	_ = stats
	return nil
}

func (cw *ConsoleWriter) writeGroupedFindings(stats map[string]int) error {
	groups := groupFindingsByHost(cw.findings)
	for _, group := range groups {
		services := extractConfirmedServiceNames(group.findings)
		suspected := extractSuspectedServiceNames(group.findings)
		warnings := extractFingerprintWarnings(group.findings)
		header := fmt.Sprintf("── %s", group.host)
		if len(services) > 0 {
			header += fmt.Sprintf(" (%s)", strings.Join(services, ", "))
		}
		header += " " + strings.Repeat("─", max(1, cw.width-stringutil.VisibleWidth(header)-1))
		fmt.Fprintln(cw.w, color.CyanString(header))
		fmt.Fprintln(cw.w)
		if len(suspected) > 0 {
			fmt.Fprintf(cw.w, "  %s %s\n", color.HiBlackString("suspected:"), strings.Join(suspected, ", "))
		}
		for _, warning := range warnings {
			fmt.Fprintf(cw.w, "  %s %s\n", color.YellowString("warning:"), warning)
		}
		if len(suspected) > 0 || len(warnings) > 0 {
			fmt.Fprintln(cw.w)
		}

		for _, f := range group.findings {
			if f.Source == report.SourceFingerprint {
				continue
			}
			port := extractPort(f.Target)
			portSuffix := ""
			if port != "" {
				portSuffix = color.HiBlackString("  :%s", port)
			}
			fmt.Fprintf(cw.w, " %s  %s%s\n", FormatSeverity(f.Severity), f.Title, portSuffix)
		}
		cw.writeHostNextSteps(group.host)
		fmt.Fprintln(cw.w)
	}

	return cw.writeFlatFooter(stats)
}

// writeHostNextSteps folds the curated "start here" commands into a host's block.
// Only shown in the non-verbose grouped view; under -v the full Next Actions catalog
// prints separately, so the fold is skipped to avoid duplication.
func (cw *ConsoleWriter) writeHostNextSteps(host string) {
	if cw.verbose {
		return
	}
	next, ok := cw.hostNext[host]
	if !ok || len(next.Commands) == 0 {
		return
	}
	fmt.Fprintf(cw.w, "  %s\n", color.HiBlackString("→ next:"))
	for _, cmd := range next.Commands {
		fmt.Fprintf(cw.w, "      %s\n", cmd)
	}
	if next.MoreCount > 0 {
		fmt.Fprintf(cw.w, "      %s\n", color.HiBlackString("+%d more (-v)", next.MoreCount))
	}
}

type hostGroup struct {
	host     string
	findings []report.Finding
}

func groupFindingsByHost(findings []report.Finding) []hostGroup {
	hostMap := make(map[string][]report.Finding)
	for _, f := range findings {
		host := hostGroupKey(f)
		hostMap[host] = append(hostMap[host], f)
	}

	hosts := make([]string, 0, len(hostMap))
	for host := range hostMap {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	groups := make([]hostGroup, 0, len(hosts))
	for _, host := range hosts {
		sorted := sortBySeverity(hostMap[host])
		groups = append(groups, hostGroup{host: host, findings: sorted})
	}
	return groups
}

func sortBySeverity(findings []report.Finding) []report.Finding {
	sorted := append([]report.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri := severityRank(sorted[i].Severity)
		rj := severityRank(sorted[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return sorted[i].Title < sorted[j].Title
	})
	return sorted
}

func severityRank(sev string) int {
	switch sev {
	case report.SeverityCritical:
		return 0
	case report.SeverityHigh:
		return 1
	case report.SeverityMedium:
		return 2
	case report.SeverityLow:
		return 3
	case report.SeverityInfo:
		return 4
	default:
		return 5
	}
}

func hostGroupKey(f report.Finding) string {
	return assessment.TargetGroupKey(f.Source, f.Target)
}

func extractPort(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return parsed.Port()
}

func extractConfirmedServiceNames(findings []report.Finding) []string {
	seen := make(map[string]struct{})
	var services []string
	for _, f := range findings {
		if f.Source != report.SourceFingerprint {
			continue
		}
		if kind, _ := f.Metadata["match_kind"].(string); kind != "" && kind != "confirmed" {
			continue
		}
		if svc, ok := f.Metadata["service"].(string); ok {
			if _, exists := seen[svc]; !exists {
				seen[svc] = struct{}{}
				services = append(services, svc)
			}
		}
	}
	sort.Strings(services)
	return services
}

func extractSuspectedServiceNames(findings []report.Finding) []string {
	seen := make(map[string]struct{})
	var services []string
	for _, f := range findings {
		if f.Source != report.SourceFingerprint {
			continue
		}
		kind, _ := f.Metadata["match_kind"].(string)
		if kind == "" || kind == "confirmed" {
			continue
		}
		if svc, ok := f.Metadata["service"].(string); ok {
			if _, exists := seen[svc]; !exists {
				seen[svc] = struct{}{}
				services = append(services, svc)
			}
		}
	}
	sort.Strings(services)
	return services
}

func extractFingerprintWarnings(findings []report.Finding) []string {
	type warningState struct {
		services map[string]struct{}
		reason   string
	}

	warnings := make(map[string]*warningState)
	for _, f := range findings {
		if f.Source != report.SourceFingerprint {
			continue
		}
		port := extractPort(f.Target)
		if port == "" {
			port = "?"
		}
		state, ok := warnings[port]
		if !ok {
			state = &warningState{services: make(map[string]struct{})}
			warnings[port] = state
		}
		if svc, ok := f.Metadata["service"].(string); ok && svc != "" {
			state.services[svc] = struct{}{}
		}
		if proxyLikely, _ := f.Metadata["proxy_likely"].(bool); proxyLikely {
			state.reason = "reverse proxy likely"
			continue
		}
		if reason, ok := f.Metadata["ambiguity_reason"].(string); ok && reason != "" && state.reason == "" {
			state.reason = reason
		}
	}

	var ports []string
	for port := range warnings {
		ports = append(ports, port)
	}
	sort.Strings(ports)

	var out []string
	for _, port := range ports {
		state := warnings[port]
		if state.reason == "" {
			continue
		}
		var services []string
		for svc := range state.services {
			services = append(services, svc)
		}
		sort.Strings(services)
		out = append(out, fmt.Sprintf("port %s: %s (%s)", port, strings.ReplaceAll(state.reason, "_", " "), strings.Join(services, ", ")))
	}
	return out
}

func (cw *ConsoleWriter) Close() error {
	return nil
}

// metadataSummaryParts returns the ordered key=value pairs shown on the context:
// line — module-declared display keys first, else up to 4 arbitrary keys.
func metadataSummaryParts(f report.Finding) []string {
	if len(f.Metadata) == 0 {
		return nil
	}

	var parts []string
	appendPart := func(key string) {
		if value, ok := f.Metadata[key]; ok && displayMetadataValue(value) {
			parts = append(parts, key+"="+fmt.Sprint(value))
		}
	}

	for _, key := range report.DisplayKeysForSource(f.Source) {
		appendPart(key)
	}

	if len(parts) > 0 {
		return parts
	}

	keys := make([]string, 0, len(f.Metadata))
	for key := range f.Metadata {
		if key == "dedupe_count" || key == "workflow" || key == "extracted" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !displayMetadataValue(f.Metadata[key]) {
			continue
		}
		parts = append(parts, key+"="+fmt.Sprint(f.Metadata[key]))
		if len(parts) == 4 {
			break
		}
	}
	return parts
}

// metadataSummary joins the context pairs on a single line (used by non-console
// formatters and tests).
func metadataSummary(f report.Finding) string {
	return strings.Join(metadataSummaryParts(f), "  ")
}

func displayMetadataValue(value interface{}) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(v) != ""
	case bool:
		return v
	default:
		return fmt.Sprint(value) != ""
	}
}

func dedupeSummary(f report.Finding) string {
	if len(f.Metadata) == 0 {
		return ""
	}
	value, ok := f.Metadata["dedupe_count"]
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s duplicate finding(s) collapsed", fmt.Sprint(value))
}

// metadataFlag reports whether a boolean metadata key is set truthy. Handles both
// in-process bool values and the string form findings take after a JSON round-trip.
func metadataFlag(f report.Finding, key string) bool {
	if len(f.Metadata) == 0 {
		return false
	}
	switch v := f.Metadata[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// fullEvidenceRuneCap bounds full-evidence console output so a pathological blob
// (e.g. a large file-download finding) can't flood the terminal. ~4 KB of ASCII.
const fullEvidenceRuneCap = 4000

// writeFullEvidence prints a finding's complete evidence multi-line and indented,
// bypassing the bounded preview. It caps the output at fullEvidenceRuneCap runes and,
// when it does, points the operator at the lossless outputs.
func (cw *ConsoleWriter) writeFullEvidence(f report.Finding) error {
	full := maybeIndentJSON(strings.TrimRight(fullEvidenceForDisplay(f), "\n"))
	truncated := false
	if r := []rune(full); len(r) > fullEvidenceRuneCap {
		full = strings.TrimRight(string(r[:fullEvidenceRuneCap]), "\n")
		truncated = true
	}
	avail := cw.fieldAvail("evidence:")
	var wrapped []string
	for _, src := range strings.Split(full, "\n") {
		if strings.TrimSpace(src) == "" {
			wrapped = append(wrapped, "")
			continue
		}
		wrapped = append(wrapped, stringutil.WrapWords(src, avail)...)
	}
	if err := cw.emitField("evidence:", wrapped); err != nil {
		return err
	}
	if truncated {
		hint := fmt.Sprintf("… evidence truncated at %d chars — use -o jsonl or `report view --id %s --evidence` for the full value", fullEvidenceRuneCap, f.ID)
		pad := strings.Repeat(" ", cw.fieldGutter("evidence:"))
		for _, ln := range stringutil.WrapWords(hint, avail) {
			if _, err := fmt.Fprintf(cw.w, "%s%s\n", pad, color.HiBlackString(ln)); err != nil {
				return err
			}
		}
	}
	return nil
}

// fullEvidenceForDisplay returns the complete, untruncated evidence for findings
// that opt into inline display — the redacted console_evidence when present,
// otherwise the raw Evidence — skipping the bounded preview.
func fullEvidenceForDisplay(f report.Finding) string {
	if len(f.Metadata) > 0 {
		if value, ok := f.Metadata["console_evidence"].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return f.Evidence
}

func evidenceForDisplay(f report.Finding) string {
	if len(f.Metadata) > 0 {
		if evidence, ok := f.Metadata["evidence"].(map[string]interface{}); ok {
			if preview, ok := evidence["preview"].(string); ok && strings.TrimSpace(preview) != "" {
				return preview
			}
		}
		if value, ok := f.Metadata["console_evidence"].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return f.Evidence
}

func workflowDisplay(f report.Finding) []string {
	if len(f.Metadata) == 0 {
		return nil
	}
	workflow, ok := f.Metadata["workflow"].(map[string]interface{})
	if !ok {
		return nil
	}
	var entries []map[string]interface{}
	switch raw := workflow["recommendations"].(type) {
	case []map[string]interface{}:
		entries = raw
	case []interface{}:
		for _, entry := range raw {
			rec, ok := entry.(map[string]interface{})
			if ok {
				entries = append(entries, rec)
			}
		}
	}
	if len(entries) == 0 {
		return nil
	}

	out := make([]string, 0, len(entries))
	for _, rec := range entries {
		command, _ := rec["command"].(string)
		if strings.TrimSpace(command) == "" {
			continue
		}
		label := "[read]"
		if gated, ok := rec["gated"].(bool); ok && gated {
			label = "[gated]"
		}
		out = append(out, label+" "+command)
	}
	return out
}

func isInteractiveStream(file *os.File) bool {
	return isatty.IsTerminal(file.Fd()) || isatty.IsCygwinTerminal(file.Fd())
}

func isInteractiveWriter(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isInteractiveStream(file)
}

// FormatSeverity returns a color-coded severity badge for terminal output.
func FormatSeverity(sev string) string {
	switch sev {
	case report.SeverityCritical:
		return color.New(color.BgRed, color.FgWhite, color.Bold).Sprint(" CRIT ")
	case report.SeverityHigh:
		return color.New(color.BgHiRed, color.FgWhite).Sprint(" HIGH ")
	case report.SeverityMedium:
		return color.New(color.BgYellow, color.FgBlack).Sprint(" MED  ")
	case report.SeverityLow:
		return color.New(color.BgBlue, color.FgWhite).Sprint(" LOW  ")
	case report.SeverityInfo:
		return color.New(color.BgHiBlack, color.FgWhite).Sprint(" INFO ")
	default:
		return fmt.Sprintf("[%s]", sev)
	}
}
