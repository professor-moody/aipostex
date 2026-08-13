package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The skill at .claude/skills/aipostex/ is what an AI reads before driving this tool, and its
// verb reference claims to be complete. A stale reference is worse than none: it would tell a
// model that a verb does not exist, or — far worse — that a gated verb is read-only and safe
// to run unprompted.
//
// Gating is declared on the command itself (the "aipostex.gated" annotation) rather than
// inferred from help text, which proved unreliable: eleven gated verbs never mentioned
// --force-exploit in their documentation at all.
//
// Regenerate the reference after adding or changing a verb:
//
//	AIPOSTEX_UPDATE_SKILL=1 go test ./cmd/aipostex/ -run TestSkillReference

const gatedAnnotation = "aipostex.gated"

func isGated(cmd *cobra.Command) bool {
	return cmd.Annotations[gatedAnnotation] == "true"
}

// gatingLabel renders how a verb is gated. `request` is "conditional": safe HTTP
// methods run read-only while unsafe ones require --force-exploit.
func gatingLabel(cmd *cobra.Command) string {
	switch cmd.Annotations[gatedAnnotation] {
	case "true":
		return "**yes**"
	case "conditional":
		return "conditional"
	default:
		return "no"
	}
}

func repoRootFromCmd(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	return root
}

func skillReferencePath(t *testing.T) string {
	return filepath.Join(repoRootFromCmd(t), ".claude", "skills", "aipostex", "reference", "verbs.md")
}

// commandGroups returns every non-hidden top-level group that has subcommands, mapped to its
// subcommands — the authoritative shape of the CLI.
func commandGroups() map[string]map[string]*cobra.Command {
	out := map[string]map[string]*cobra.Command{}
	for _, group := range rootCmd.Commands() {
		// cobra adds `completion` (and `help`) to the tree lazily, the first time a
		// command is executed — so they appear only when other tests in this package
		// have run first. Excluding them keeps the reference independent of test order.
		if group.Hidden || group.Name() == "completion" || group.Name() == "help" {
			continue
		}
		name := strings.Fields(group.Use)[0]
		for _, sub := range group.Commands() {
			if sub.Hidden || sub.Name() == "help" {
				continue
			}
			if out[name] == nil {
				out[name] = map[string]*cobra.Command{}
			}
			out[name][strings.Fields(sub.Use)[0]] = sub
		}
	}
	return out
}

func renderSkillReference() string {
	groups := commandGroups()
	names := make([]string, 0, len(groups))
	total, gated := 0, 0
	for n, subs := range groups {
		names = append(names, n)
		total += len(subs)
		for _, c := range subs {
			if isGated(c) {
				gated++
			}
		}
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("# aipostex verb reference\n\n")
	b.WriteString("The complete command inventory, generated from the command tree and held in step\n")
	b.WriteString("with it by a test. **Gated** verbs mutate a target or drive execution and refuse to\n")
	b.WriteString("run without `--force-exploit`; everything else is read-only.\n\n")
	b.WriteString("Regenerate with `AIPOSTEX_UPDATE_SKILL=1 go test ./cmd/aipostex/ -run TestSkillReference`.\n\n")
	fmt.Fprintf(&b, "**%d command groups · %d verbs · %d gated**\n\n", len(groups), total, gated)

	for _, name := range names {
		group, _, err := rootCmd.Find([]string{name})
		fmt.Fprintf(&b, "## `%s`\n\n", name)
		if err == nil && group != nil && group.Short != "" {
			fmt.Fprintf(&b, "%s\n\n", group.Short)
		}
		b.WriteString("| Verb | Gated | What it does |\n|---|---|---|\n")
		verbs := make([]string, 0, len(groups[name]))
		for v := range groups[name] {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)
		for _, v := range verbs {
			cmd := groups[name][v]
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", v, gatingLabel(cmd), cmd.Short)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func TestSkillReferenceMatchesCommandTree(t *testing.T) {
	path := skillReferencePath(t)
	want := renderSkillReference()

	if os.Getenv("AIPOSTEX_UPDATE_SKILL") == "1" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatalf("writing the skill reference: %v", err)
		}
		t.Log("regenerated the skill verb reference")
		return
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the skill verb reference: %v", err)
	}
	if string(got) != want {
		t.Errorf("the skill verb reference is out of date with the command tree.\n" +
			"Regenerate it: AIPOSTEX_UPDATE_SKILL=1 go test ./cmd/aipostex/ -run TestSkillReference")
	}
}

// TestGatedCommandsDocumentTheirGating is operator-facing: a verb that refuses without
// --force-exploit should say so, and eleven did not before gating became declarative.
func TestGatedCommandsDocumentTheirGating(t *testing.T) {
	for group, subs := range commandGroups() {
		for verb, cmd := range subs {
			if !isGated(cmd) {
				continue
			}
			text := strings.ToLower(cmd.Short + "\n" + cmd.Long)
			if !strings.Contains(text, "force-exploit") {
				t.Errorf("%s %s is gated but neither its Short nor its Long mentions --force-exploit",
					group, verb)
			}
		}
	}
}

// TestUngatedCommandsDoNotClaimToBeGated catches the inverse mistake: documentation that
// tells an operator a read-only verb needs --force-exploit.
func TestUngatedCommandsDoNotClaimToBeGated(t *testing.T) {
	claim := regexp.MustCompile(`(?i)requires? --force-exploit`)
	for group, subs := range commandGroups() {
		for verb, cmd := range subs {
			// A "conditional" verb (request: unsafe HTTP methods only) legitimately
			// discusses --force-exploit without being unconditionally gated.
			if cmd.Annotations[gatedAnnotation] != "" {
				continue
			}
			if claim.MatchString(cmd.Short + "\n" + cmd.Long) {
				t.Errorf("%s %s is not gated but its documentation says it requires --force-exploit",
					group, verb)
			}
		}
	}
}

// TestSkillQuotesAccurateCounts keeps the numbers in the prose honest — they were wrong
// once already, quoting an earlier parse that had missed 14 verbs.
func TestSkillQuotesAccurateCounts(t *testing.T) {
	groups := commandGroups()
	total, gated := 0, 0
	for _, subs := range groups {
		total += len(subs)
		for _, c := range subs {
			if isGated(c) {
				gated++
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(repoRootFromCmd(t), ".claude", "skills", "aipostex", "SKILL.md"))
	if err != nil {
		t.Fatalf("reading SKILL.md: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		fmt.Sprintf("%d verbs across %d command groups", total, len(groups)),
		fmt.Sprintf("%d of the %d verbs refuse to run without", gated, total),
	} {
		if !strings.Contains(s, want) {
			t.Errorf("SKILL.md should state %q but does not — the counts have drifted from the command tree", want)
		}
	}
}

func TestSkillFileCarriesItsDoctrine(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRootFromCmd(t), ".claude", "skills", "aipostex", "SKILL.md"))
	if err != nil {
		t.Fatalf("reading SKILL.md: %v", err)
	}
	s := string(data)
	if !strings.HasPrefix(s, "---\n") {
		t.Fatal("SKILL.md must start with YAML frontmatter")
	}
	end := strings.Index(s[4:], "---")
	if end < 0 {
		t.Fatal("SKILL.md frontmatter is not terminated")
	}
	front := s[:end+4]
	for _, field := range []string{"name:", "description:"} {
		if !strings.Contains(front, field) {
			t.Errorf("SKILL.md frontmatter is missing %s", field)
		}
	}
	// Without these the skill is a command list, not doctrine — and the honesty rules are
	// the whole reason it exists.
	for _, must := range []string{"landed", "reachable", "--force-exploit", "Authorization", "read-confirmed"} {
		if !strings.Contains(s, must) {
			t.Errorf("SKILL.md no longer mentions %q, which is core doctrine", must)
		}
	}
}
