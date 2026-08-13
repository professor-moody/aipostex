package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// These tests bind every place that declares module identity back to Registry, so
// adding a source without wiring up its schema entry, documentation, display keys,
// or CLI command fails the build instead of shipping as silent drift.
//
// Several of them read repository files. Go runs a test with its package directory
// as the working directory, so repoRoot walks up from pkg/report.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	return root
}

// declaredSourceConstants parses the Source* constants out of finding.go. Go cannot
// enumerate constants at runtime, so the declaration is read directly — which is
// exactly what makes "a new constant was added but never registered" detectable.
func declaredSourceConstants(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile("finding.go")
	if err != nil {
		t.Fatalf("reading finding.go: %v", err)
	}
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`\b(Source[A-Za-z0-9]+)\s*=\s*"([^"]+)"`).FindAllStringSubmatch(string(data), -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatal("parsed zero Source constants from finding.go — the parser is broken, not the code")
	}
	return out
}

func TestRegistryCoversEverySourceConstant(t *testing.T) {
	consts := declaredSourceConstants(t)
	registered := map[string]bool{}
	for _, info := range Registry {
		registered[info.Source] = true
	}
	for name, value := range consts {
		if !registered[value] {
			t.Errorf("%s (%q) is declared but not in Registry — add it so the consistency tests cover it", name, value)
		}
	}
	values := map[string]bool{}
	for _, v := range consts {
		values[v] = true
	}
	for _, info := range Registry {
		if !values[info.Source] {
			t.Errorf("Registry lists %q, which is not a declared Source constant", info.Source)
		}
	}
}

func TestRegistryEntriesAreUniqueAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, info := range Registry {
		if info.Source == "" {
			t.Error("registry entry with an empty Source")
			continue
		}
		if seen[info.Source] {
			t.Errorf("duplicate registry entry for %q", info.Source)
		}
		seen[info.Source] = true

		switch info.Kind {
		case KindModule:
			if info.Command != info.Source {
				t.Errorf("%q: a module's Command (%q) must equal its Source", info.Source, info.Command)
			}
			if info.DocPage == "" {
				t.Errorf("%q: a module must name its docs/modules page", info.Source)
			}
			if info.MatrixLabel == "" {
				t.Errorf("%q: a module must name its capability-matrix label", info.Source)
			}
		case KindOperator:
			if info.Command == "" {
				t.Errorf("%q: an operator source must name the command that emits it", info.Source)
			}
			if info.DocPage != "" {
				t.Errorf("%q: only modules carry a docs/modules page", info.Source)
			}
		case KindInfrastructure:
			if info.Command != "" || info.DocPage != "" {
				t.Errorf("%q: infrastructure sources have no command or module page", info.Source)
			}
		default:
			t.Errorf("%q: unknown kind %q", info.Source, info.Kind)
		}
	}
}

func TestPublishedSchemaEnumMatchesRegistry(t *testing.T) {
	path := filepath.Join(repoRoot(t), "docs", "schema", "finding-schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var schema struct {
		Properties struct {
			Source struct {
				Enum []string `json:"enum"`
			} `json:"source"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parsing finding-schema.json: %v", err)
	}
	got := append([]string(nil), schema.Properties.Source.Enum...)
	want := AllSources()
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("schema enum has %d sources, registry has %d\n schema:   %v\n registry: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("schema enum and registry disagree: schema has %q where registry has %q", got[i], want[i])
		}
	}
}

func TestEveryModuleHasItsDocumentationPage(t *testing.T) {
	root := repoRoot(t)
	for _, info := range Registry {
		if info.Kind != KindModule {
			continue
		}
		path := filepath.Join(root, "docs", "modules", info.DocPage+".md")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("module %q declares doc page %q but docs/modules/%s.md is missing", info.Source, info.DocPage, info.DocPage)
		}
	}
}

func TestEveryModuleHasDisplayKeys(t *testing.T) {
	for _, info := range Registry {
		if info.Kind != KindModule {
			continue
		}
		keys, ok := moduleDisplayKeys[info.Source]
		if !ok {
			t.Errorf("module %q has no moduleDisplayKeys entry, so its findings render with the generic fallback", info.Source)
			continue
		}
		// Every module finding carries these, and operators rely on seeing them.
		for _, required := range []string{"module", "action", "stage", "landed"} {
			found := false
			for _, k := range keys {
				if k == required {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("module %q display keys omit %q", info.Source, required)
			}
		}
	}
}

func TestEveryModuleHasATopLevelCommand(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "cmd", "aipostex"))
	if err != nil {
		t.Fatalf("reading cmd/aipostex: %v", err)
	}
	// Collect the Use: value of every command registered on rootCmd.
	varUse := map[string]string{}
	registeredVars := map[string]bool{}
	blockRe := regexp.MustCompile(`(\w+)\s*=\s*&cobra\.Command\{`)
	useRe := regexp.MustCompile(`Use:\s*"([^"\s]+)`)
	addRe := regexp.MustCompile(`rootCmd\.AddCommand\(([^)]*)\)`)
	varRe := regexp.MustCompile(`\w+Cmd`)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, "cmd", "aipostex", e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		src := string(data)
		for _, m := range blockRe.FindAllStringSubmatchIndex(src, -1) {
			name := src[m[2]:m[3]]
			depth, i := 1, m[1]
			for i < len(src) && depth > 0 {
				switch src[i] {
				case '{':
					depth++
				case '}':
					depth--
				}
				i++
			}
			if u := useRe.FindStringSubmatch(src[m[1]:i]); u != nil {
				varUse[name] = u[1]
			}
		}
		for _, m := range addRe.FindAllStringSubmatch(src, -1) {
			for _, v := range varRe.FindAllString(m[1], -1) {
				registeredVars[v] = true
			}
		}
	}
	topLevel := map[string]bool{}
	for v := range registeredVars {
		if use, ok := varUse[v]; ok {
			topLevel[use] = true
		}
	}
	if len(topLevel) == 0 {
		t.Fatal("parsed zero top-level commands — the parser is broken, not the code")
	}
	for _, info := range Registry {
		if info.Command == "" {
			continue
		}
		if !topLevel[info.Command] {
			t.Errorf("registry says %q is emitted by the %q command, but no such top-level command is registered",
				info.Source, info.Command)
		}
	}
}

func TestEveryModuleAppearsInTheCapabilityMatrix(t *testing.T) {
	// The capability matrix is the page a reader consults to learn what the tool
	// covers, and it is the site that drifted worst: eight modules had shipped
	// without ever being listed. This binds it to the registry.
	path := filepath.Join(repoRoot(t), "docs", "development", "coverage.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	rows := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\|\s*\*\*([^*]+)\*\*`).FindAllStringSubmatch(string(data), -1) {
		rows[m[1]] = true
	}
	if len(rows) == 0 {
		t.Fatal("parsed zero matrix rows — the parser is broken, not the docs")
	}
	for _, info := range Registry {
		if info.Kind != KindModule {
			continue
		}
		if !rows[info.MatrixLabel] {
			t.Errorf("module %q is missing from the capability matrix (expected a row labelled %q in docs/development/coverage.md)",
				info.Source, info.MatrixLabel)
		}
	}
}

func TestLookupAndAccessors(t *testing.T) {
	info, ok := LookupSource(SourceMCP)
	if !ok || info.Kind != KindModule || info.Command != "mcp" {
		t.Fatalf("unexpected lookup for mcp: %#v (ok=%v)", info, ok)
	}
	if _, ok := LookupSource("not-a-source"); ok {
		t.Error("LookupSource should not resolve an unregistered value")
	}
	mods := ModuleSources()
	if len(mods) == 0 || len(mods) >= len(AllSources()) {
		t.Errorf("ModuleSources (%d) should be a non-empty subset of AllSources (%d)", len(mods), len(AllSources()))
	}
	for _, m := range mods {
		if info, _ := LookupSource(m); info.Kind != KindModule {
			t.Errorf("ModuleSources returned non-module %q", m)
		}
	}
}
