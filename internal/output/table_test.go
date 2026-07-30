package output

import (
	"regexp"
	"strings"
	"testing"

	"github.com/professor-moody/aipostex/pkg/report"
	"github.com/professor-moody/aipostex/pkg/stringutil"
)

var ansiStrip = regexp.MustCompile("\x1b\\[[0-9;]*m")

func plain(s string) string { return ansiStrip.ReplaceAllString(s, "") }

// splitCells splits a rendered line back into its cells on the 2+-space gaps.
func splitCells(line string) []string {
	return regexp.MustCompile(` {2,}`).Split(strings.TrimSpace(plain(line)), -1)
}

func TestTableStructureAndWidthInvariant(t *testing.T) {
	for _, width := range []int{200, 80, 40} {
		tbl := NewTable(
			Column{Header: "PORT"},
			Column{Header: "IDENTITY"},
			Column{Header: "NOTES", Flex: true},
		)
		tbl.AddRow("8265/tcp", "ray-dashboard", "auth disabled; jobs api open")
		tbl.AddRow("11434/tcp", "ollama", "model list readable")
		lines := tbl.Render(width)
		if len(lines) != 3 {
			t.Fatalf("width %d: expected header+2 rows, got %d", width, len(lines))
		}
		for _, ln := range lines {
			if cells := splitCells(ln); len(cells) != 3 {
				t.Fatalf("width %d: line split into %d cells, want 3: %q", width, len(cells), plain(ln))
			}
			// The flex NOTES column absorbs shrink, so the whole table fits every width.
			if stringutil.VisibleWidth(ln) > width {
				t.Fatalf("width %d: line exceeds frame (%d): %q", width, stringutil.VisibleWidth(ln), plain(ln))
			}
		}
	}
}

func TestTableColumnsAlignOnVisibleWidth(t *testing.T) {
	tbl := NewTable(Column{Header: "A"}, Column{Header: "COL1"})
	tbl.AddRow("x", "ZZ")
	tbl.AddRow("xxxxx", "ZZ")
	tbl.AddRow("xxxxxxxxxx", "ZZ")
	lines := tbl.Render(200)
	// Column 1 must start at the same offset on every line regardless of column 0's
	// content width.
	want := strings.Index(plain(lines[0]), "COL1")
	if want < 0 {
		t.Fatalf("header COL1 not found: %q", plain(lines[0]))
	}
	for _, ln := range lines[1:] {
		if got := strings.Index(plain(ln), "ZZ"); got != want {
			t.Fatalf("column 1 misaligned: want offset %d, got %d in %q", want, got, plain(ln))
		}
	}
}

func TestTableBadgeCellDoesNotInflatePadding(t *testing.T) {
	// A colored severity badge (ANSI) and a plain string of the same VISIBLE width must
	// leave the next column starting at the same offset — proving layout uses visible
	// width, not byte length (the %-*s bug this primitive avoids).
	badge := FormatSeverity(report.SeverityCritical)
	if w := stringutil.VisibleWidth(badge); w != 6 {
		t.Fatalf("assumption broken: severity badge visible width = %d, want 6", w)
	}
	tbl := NewTable(Column{Header: "SEV"}, Column{Header: "TAIL"})
	tbl.AddRow(badge, "tail")
	tbl.AddRow("PLAIN6", "tail") // 6 visible cols, same as the badge
	lines := tbl.Render(200)
	a := strings.Index(plain(lines[1]), "tail")
	b := strings.Index(plain(lines[2]), "tail")
	if a != b || a < 0 {
		t.Fatalf("badge inflated padding: tail offsets %d vs %d", a, b)
	}
}

func TestTableFlexColumnTruncatesAndNeighborIntact(t *testing.T) {
	tbl := NewTable(
		Column{Header: "PORT"},
		Column{Header: "NOTES", Flex: true},
	)
	long := "this is a very long notes column that must be truncated to fit a narrow frame"
	tbl.AddRow("8265/tcp", long)
	lines := tbl.Render(40)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "…") {
		t.Fatalf("expected the flex column to truncate with an ellipsis:\n%s", plain(joined))
	}
	if strings.Contains(plain(joined), long) {
		t.Fatalf("expected the long value to be truncated, but it appears in full")
	}
	if !strings.Contains(plain(joined), "8265/tcp") {
		t.Fatalf("expected the non-flex neighbor to stay intact:\n%s", plain(joined))
	}
}

func TestTableNoTruncColumnKeepsValueComplete(t *testing.T) {
	token := strings.Repeat("A", 120)
	tbl := NewTable(
		Column{Header: "NAME"},
		Column{Header: "VALUE", NoTrunc: true},
	)
	tbl.AddRow("HF_TOKEN", token)
	joined := strings.Join(tbl.Render(48), "\n")
	if !strings.Contains(plain(joined), token) {
		t.Fatalf("NoTrunc column must never truncate its value:\n%s", plain(joined))
	}
}

func TestTableHeaderLongerThanCellSetsWidth(t *testing.T) {
	tbl := NewTable(Column{Header: "CONFIDENCE"}, Column{Header: "X"})
	tbl.AddRow("hi", "yo")
	lines := tbl.Render(200)
	// Column 1 starts at indent(2) + len("CONFIDENCE")(10) + gap(2) = 14.
	if got := strings.Index(plain(lines[1]), "yo"); got != 14 {
		t.Fatalf("expected column 1 at offset 14 (header sets width), got %d: %q", got, plain(lines[1]))
	}
}

func TestTableZeroRowsRendersHeaderOnly(t *testing.T) {
	lines := NewTable(Column{Header: "A"}, Column{Header: "B"}).Render(200)
	if len(lines) != 1 {
		t.Fatalf("expected header-only render, got %d lines", len(lines))
	}
	if !strings.Contains(plain(lines[0]), "A") || !strings.Contains(plain(lines[0]), "B") {
		t.Fatalf("header line missing columns: %q", plain(lines[0]))
	}
}

func TestTableSingleWideColumnOverflowsGracefully(t *testing.T) {
	wide := strings.Repeat("Z", 300)
	tbl := NewTable(Column{Header: "BLOB"}) // non-flex, can't shrink
	tbl.AddRow(wide)
	lines := tbl.Render(40)
	if !strings.Contains(lines[1], wide) {
		t.Fatalf("expected structural column to render in full (graceful overflow)")
	}
	if stringutil.VisibleWidth(lines[1]) <= 40 {
		t.Fatalf("expected the wide line to exceed the frame, got width %d", stringutil.VisibleWidth(lines[1]))
	}
}

func TestNormalizeCell(t *testing.T) {
	cases := map[string]string{
		"":                 "-",
		"   ":              "-",
		"ollama":           "ollama",
		"a\nb\tc":          "a b c",
		"  spaced   out  ": "spaced out",
	}
	for in, want := range cases {
		if got := NormalizeCell(in); got != want {
			t.Fatalf("NormalizeCell(%q) = %q, want %q", in, got, want)
		}
	}
}
