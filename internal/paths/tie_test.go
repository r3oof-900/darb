package paths

import (
	"slices"
	"testing"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
)

// Two cuts of resolve steps only, each of two steps: {a1, a2} needs two
// commands (X and Y), {b1, b2} one (Z). The cut closest to the entry would be
// {a1, a2}; the tie rule takes the one with fewer distinct commands, the
// user runs commands, not steps (SCORING.md 4.3). With one command each, the
// cut with fewer steps wins.
func TestResolveTieFewestCommandsThenSteps(t *testing.T) {
	resolve := func(cmd string) []graph.Fix {
		return []graph.Fix{{Side: graph.SideIdentity, Kind: graph.FixResolve, Policy: "p-" + cmd, Resolve: []graph.Resolution{{Policy: "p-" + cmd, Command: cmd}}}}
	}
	x := newTG()
	edge := func(from, to string, kind graph.Kind, cmd string) {
		x.b.Edge(&graph.Edge{From: x.n(from), To: x.n(to), Kind: kind, Sub: "sts", For: graph.NoNode, Verdict: eval.Unknown, Fixes: resolve(cmd)})
	}
	edge("s", "m1", graph.Assumes, "X")
	edge("s", "m2", graph.Assumes, "Y")
	edge("m1", "j", graph.CanReadPlaintext, "Z")
	edge("m2", "j", graph.CanReadPlaintext, "Z")
	g := x.b.Build()
	opts := &Options{Cost: func(graph.EdgeID) int64 { return Default }}
	r := CutFor(g, lookup(g, "s"), lookup(g, "j"), &Select{}, opts)
	var kinds []graph.Kind
	var cmds []string
	for _, s := range r.Steps {
		kinds = append(kinds, g.Edge(s.Edge).Kind)
		if !slices.Contains(cmds, s.Resolve) {
			cmds = append(cmds, s.Resolve)
		}
	}
	if !r.Finite || r.Cost != 0 || !r.Pending || len(r.Steps) != 2 || !slices.Equal(cmds, []string{"Z"}) ||
		!slices.Equal(kinds, []graph.Kind{graph.CanReadPlaintext, graph.CanReadPlaintext}) {
		t.Fatalf("one command (Z) beats two (X, Y) at equal steps: %+v", r.Steps)
	}

	// One command each: {b} (one step) beats {a1, a2} (two steps, closer).
	y := newTG()
	edgeY := func(from, to, sub string, kind graph.Kind, cmd string) {
		y.b.Edge(&graph.Edge{From: y.n(from), To: y.n(to), Kind: kind, Sub: sub, For: graph.NoNode, Verdict: eval.Unknown, Fixes: resolve(cmd)})
	}
	edgeY("s", "m", "sts", graph.Assumes, "X")
	edgeY("s", "m", "irsa", graph.Assumes, "X")
	edgeY("m", "j", "", graph.CanReadPlaintext, "Z")
	g = y.b.Build()
	r = CutFor(g, lookup(g, "s"), lookup(g, "j"), &Select{}, opts)
	if len(r.Steps) != 1 || r.Steps[0].Resolve != "Z" {
		t.Fatalf("one command each: the fewer steps win: %+v", r.Steps)
	}
}
