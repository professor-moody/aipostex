package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/professor-moody/aipostex/pkg/stringutil"
)

// tableMinColWidth floors how far a flex column may shrink, so a table squeezed into a
// narrow frame never collapses a column to nothing.
const tableMinColWidth = 8

// Align controls a column's justification.
type Align int

const (
	AlignLeft Align = iota
	AlignRight
)

// Column describes one table column. Flex columns are the ones shrunk (largest first)
// and truncated when the table must fit a narrow frame; only plain-text columns should
// be Flex, since truncating a pre-colored cell would corrupt its ANSI escapes. NoTrunc
// columns are never shrunk — used for values that must stay copy-complete (credentials).
type Column struct {
	Header  string
	Align   Align
	Flex    bool
	NoTrunc bool
}

// cell caches a value's visible width so all layout math ignores ANSI escapes (a
// severity badge measures as its 6 visible columns, not its byte length).
type cell struct {
	text  string
	width int
}

// Table is a borderless, space-separated, width-aware aligned table with a gray header
// row. It reproduces the discovery-table aesthetic as a single reusable primitive so
// every columnar listing in the tool renders identically. Width is measured with
// stringutil.VisibleWidth (rune count), so double-width CJK glyphs would misalign by a
// column — acceptable, as every table field in this tool is ASCII.
type Table struct {
	cols   []Column
	rows   [][]cell
	indent int
	gap    int
}

// NewTable builds a table with the default 2-space indent and 2-space inter-column gap.
func NewTable(cols ...Column) *Table {
	return &Table{cols: cols, indent: 2, gap: 2}
}

func (t *Table) WithIndent(n int) *Table { t.indent = n; return t }
func (t *Table) WithGap(n int) *Table    { t.gap = n; return t }

// AddRow appends a row. Extra cells are ignored and short rows are padded with empties,
// so callers can't panic on a column-count mismatch.
func (t *Table) AddRow(cells ...string) *Table {
	row := make([]cell, len(t.cols))
	for i := range t.cols {
		s := ""
		if i < len(cells) {
			s = cells[i]
		}
		row[i] = cell{text: s, width: stringutil.VisibleWidth(s)}
	}
	t.rows = append(t.rows, row)
	return t
}

// Render lays the table out to fit width, returning one string per line (header first,
// no trailing newline, no trailing padding). Columns size to their content, then flex
// columns shrink largest-first to fit; if the non-flex columns alone exceed width the
// table overflows gracefully rather than mangling a structural column.
func (t *Table) Render(width int) []string {
	n := len(t.cols)
	if n == 0 {
		return nil
	}
	colW := make([]int, n)
	for i := range t.cols {
		colW[i] = stringutil.VisibleWidth(t.cols[i].Header)
	}
	for _, row := range t.rows {
		for i := 0; i < n; i++ {
			if row[i].width > colW[i] {
				colW[i] = row[i].width
			}
		}
	}
	for t.naturalWidth(colW) > width {
		widest := -1
		for i := range t.cols {
			if !t.cols[i].Flex || t.cols[i].NoTrunc || colW[i] <= tableMinColWidth {
				continue
			}
			if widest == -1 || colW[i] > colW[widest] {
				widest = i
			}
		}
		if widest == -1 {
			break // nothing left to shrink; graceful overflow
		}
		colW[widest]--
	}

	lines := make([]string, 0, len(t.rows)+1)
	lines = append(lines, t.renderHeader(colW))
	for _, row := range t.rows {
		lines = append(lines, t.renderRow(row, colW))
	}
	return lines
}

// Fprint renders the table to w at the given width, one line per Fprintln.
func (t *Table) Fprint(w io.Writer, width int) error {
	for _, line := range t.Render(width) {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func (t *Table) naturalWidth(colW []int) int {
	total := t.indent + t.gap*(len(colW)-1)
	for _, w := range colW {
		total += w
	}
	return total
}

func (t *Table) renderHeader(colW []int) string {
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", t.indent))
	for i := range t.cols {
		text := t.cols[i].Header
		vis := stringutil.VisibleWidth(text)
		if vis > colW[i] {
			text = stringutil.BoundedPreview(text, colW[i])
			vis = stringutil.VisibleWidth(text)
		}
		b.WriteString(padTo(color.HiBlackString(text), vis, colW[i], t.cols[i].Align))
		if i < len(t.cols)-1 {
			b.WriteString(strings.Repeat(" ", t.gap))
		}
	}
	return strings.TrimRight(b.String(), " ")
}

func (t *Table) renderRow(row []cell, colW []int) string {
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", t.indent))
	for i := range t.cols {
		text := row[i].text
		vis := row[i].width
		// Only shrunk flex cells (never NoTrunc, never colored) exceed their column
		// here, since non-flex columns are sized to their widest cell.
		if !t.cols[i].NoTrunc && vis > colW[i] {
			text = stringutil.BoundedPreview(text, colW[i])
			vis = stringutil.VisibleWidth(text)
		}
		b.WriteString(padTo(text, vis, colW[i], t.cols[i].Align))
		if i < len(t.cols)-1 {
			b.WriteString(strings.Repeat(" ", t.gap))
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// padTo pads a rendered cell (which may contain ANSI) to colW columns using its visible
// width, on the right for left-aligned cells and on the left for right-aligned.
func padTo(rendered string, vis, colW int, align Align) string {
	if vis >= colW {
		return rendered
	}
	pad := strings.Repeat(" ", colW-vis)
	if align == AlignRight {
		return pad + rendered
	}
	return rendered + pad
}

// NormalizeCell collapses internal whitespace/newlines to single spaces and renders an
// empty value as "-", the shared behavior the per-table cell helpers used to duplicate.
// Do not pass credential values through this — they must keep their exact content.
func NormalizeCell(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "-"
	}
	return strings.Join(fields, " ")
}
