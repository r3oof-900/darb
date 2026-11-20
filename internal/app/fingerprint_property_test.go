package app

import (
	"context"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/graph"
)

// A fingerprint names the problem, not its fix (DESIGN.md §8): whatever the
// cut costs, every finding of every fixture keeps its fingerprint. The weight
// table drawn here is remediation.cut_costs, the one users can set; it moves
// the cut, which the test checks really happens, so the property is not
// vacuous.
func TestFingerprintsIgnoreWeights(t *testing.T) {
	type loaded struct {
		name   string
		l      *Loaded
		cfg    *config.Config
		prints []string
		cuts   map[string]string
	}
	variants, err := filepath.Glob(filepath.Join(repoRoot(t), "tests", "fixtures", "*", "*", "expected.json"))
	if err != nil || len(variants) == 0 {
		t.Fatalf("fixtures: %v", err)
	}
	var all []loaded
	for _, file := range variants {
		dir := copyTree(t, filepath.Dir(file))
		in := scansFor(t, dir)["normalized.golden.json"]
		l, err := Load(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(l, in.Config, DefaultFailOn)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Findings) == 0 {
			continue
		}
		prints, cuts := summary(a)
		all = append(all, loaded{filepath.Base(filepath.Dir(filepath.Dir(file))), l, in.Config, prints, cuts})
	}
	kinds := []graph.Kind{
		graph.RunsAs, graph.CanEscalate, graph.Assumes, graph.MapsTo, graph.NodeRole,
		graph.CanRead, graph.CanDecrypt, graph.CanReadPlaintext, graph.ExposedTo, graph.Protects,
	}
	moved := 0
	rapid.Check(t, func(rt *rapid.T) {
		costs := map[string]int{}
		for _, k := range kinds {
			if rapid.Bool().Draw(rt, "set "+string(k)) {
				costs[string(k)] = rapid.IntRange(1, 1000).Draw(rt, string(k))
			}
		}
		for _, v := range all {
			cfg := *v.cfg
			cfg.Remediation.CutCosts = maps.Clone(costs)
			a, err := Analyze(v.l, &cfg, DefaultFailOn)
			if err != nil {
				rt.Fatal(err)
			}
			prints, cuts := summary(a)
			if !slices.Equal(prints, v.prints) {
				rt.Fatalf("%s: fingerprints changed with cut costs %v:\n%v\n%v", v.name, costs, v.prints, prints)
			}
			if !maps.Equal(cuts, v.cuts) {
				moved++
			}
		}
	})
	if moved == 0 {
		t.Fatal("no drawn weight table moved any cut: the property tested nothing")
	}
}

// summary: the sorted fingerprints, and each path finding's cut by fingerprint.
func summary(a *Analysis) (prints []string, cuts map[string]string) {
	cuts = map[string]string{}
	for i := range a.Findings {
		f := &a.Findings[i]
		prints = append(prints, f.Fingerprint)
		cuts[f.Fingerprint] = strings.Join(f.Chokepoints, "; ")
	}
	slices.Sort(prints)
	return prints, cuts
}
