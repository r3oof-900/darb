package paths

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
)

// Random graphs whose edges share changes (one policy statement may grant
// several edges, into the same head or not): (a) the cut counts no change
// twice, and (b) making the chosen changes breaks every path of the pair
// (DESIGN.md 9.1, shared changes).
func TestSharedChangesCountOnceAndBreakEverything(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		x := newTG()
		n := rapid.IntRange(2, 6).Draw(rt, "nodes")
		name := func(i int) string { return fmt.Sprintf("n%d", i) }
		for i := range n {
			x.n(name(i))
		}
		x.n("jewel")
		policies := rapid.IntRange(1, 3).Draw(rt, "policies")
		cost := map[int]int64{}
		for p := range policies {
			cost[p] = int64(rapid.IntRange(1, 5).Draw(rt, fmt.Sprintf("cost%d", p)))
		}
		edges := rapid.IntRange(1, 12).Draw(rt, "edges")
		for i := range edges {
			from := rapid.IntRange(0, n-1).Draw(rt, fmt.Sprintf("from%d", i))
			to := rapid.IntRange(0, n).Draw(rt, fmt.Sprintf("to%d", i)) // n: the jewel
			if from == to {
				continue
			}
			p := rapid.IntRange(0, policies-1).Draw(rt, fmt.Sprintf("policy%d", i))
			kind, target := graph.Assumes, name(to)
			if to == n {
				kind, target = graph.CanReadPlaintext, "jewel"
			}
			fx := graph.Fix{
				Side: graph.SideIdentity, Kind: graph.FixNarrow, Policy: fmt.Sprintf("p%d", p), Cost: cost[p],
				Grants: []graph.Grant{{Policy: fmt.Sprintf("p%d", p)}},
			}
			x.b.Edge(&graph.Edge{
				From: x.n(name(from)), To: x.n(target), Kind: kind, Sub: "sts", For: graph.NoNode,
				Verdict: eval.Allow, Confidence: graph.High, Fixes: []graph.Fix{fx},
			})
		}
		g := x.b.Build()
		entry, jewel := lookup(g, name(0)), lookup(g, "jewel")
		sel := &Select{}
		if !Selected(g, entry, jewel, sel) {
			return
		}
		r := CutFor(g, entry, jewel, sel, &Options{Cost: func(graph.EdgeID) int64 { return Default }})
		if !r.Finite {
			rt.Fatalf("every edge has a fix: the cut is finite")
		}
		chosen := map[string]bool{}
		var distinct int64
		for _, w := range r.Ways {
			p := g.Edge(w.Edge).Fixes[w.Fix].Policy
			if !chosen[p] {
				chosen[p] = true
				distinct += w.Known
			}
		}
		if r.Cost > distinct {
			rt.Fatalf("(a) a change counted twice: cost %d, distinct changes %d (%v)", r.Cost, distinct, chosen)
		}
		broken := map[graph.EdgeID]bool{}
		for id := range g.NumEdges() {
			e := g.Edge(graph.EdgeID(id))
			if len(e.Fixes) > 0 && chosen[e.Fixes[0].Policy] {
				broken[graph.EdgeID(id)] = true
			}
		}
		if !Breaks(g, entry, jewel, sel, broken) {
			rt.Fatalf("(b) a path survives the chosen changes %v", chosen)
		}
	})
}
