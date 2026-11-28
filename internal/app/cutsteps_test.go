package app

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/rules"
)

// Every step of every cut says what to change (a policy) or what decides it
// (a resolve command), and no change is listed twice for one edge: two
// edges into the same head that break with one change are one unit
// (DESIGN.md §9.1).
func TestCutStepsNameTheirChangeOnce(t *testing.T) {
	variants, err := filepath.Glob(filepath.Join(repoRoot(t), "tests", "fixtures", "*", "*", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range variants {
		dir := filepath.Dir(file)
		name := filepath.Base(filepath.Dir(dir)) + "/" + filepath.Base(dir)
		a := analyzeVariant(t, name, nil)
		for i := range a.Findings {
			f := &a.Findings[i]
			for _, list := range [][]rules.FixStep{f.Fix, f.OtherSideFix, f.AlternativeDetail} {
				checkSteps(t, name, f, list)
			}
		}
	}
}

func checkSteps(t *testing.T, name string, f *rules.Finding, steps []rules.FixStep) {
	t.Helper()
	seen := map[string]string{}
	for _, s := range steps {
		if s.Policy == "" && s.Resolve == "" {
			t.Errorf("%s %s %s -> %s: step %s %s on %q names no policy and no resolve command", name, f.Rule, f.Entry, f.Jewel, s.Side, s.Kind, s.Edge)
		}
		// The same change on the same edge text: two edges into one head
		// that should have been one unit. Into different heads a change is
		// listed per edge (priced once, as a detach is).
		key := strings.Join([]string{s.Edge, s.Side, s.Kind, s.Policy, s.Resolve}, "|")
		if seen[key] != "" {
			t.Errorf("%s %s %s -> %s: the change %s is listed twice", name, f.Rule, f.Entry, f.Jewel, key)
		}
		seen[key] = s.Edge
	}
}
