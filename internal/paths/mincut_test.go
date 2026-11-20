package paths

import (
	"testing"

	"pgregory.net/rapid"
)

// connected reports whether t is reachable from s without the removed edges.
func connected(n int, edges []FlowEdge, removed map[int]bool, s, t int) bool {
	seen := make([]bool, n)
	seen[s] = true
	stack := []int{s}
	for len(stack) > 0 {
		u := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for i, e := range edges {
			if e.From == u && !removed[i] && !seen[e.To] {
				seen[e.To] = true
				stack = append(stack, e.To)
			}
		}
	}
	return seen[t]
}

// bruteForce tries every set of cuttable edges: the cheapest one that
// separates s from t, or ok=false when none does.
func bruteForce(n int, edges []FlowEdge, s, t int) (cost int64, ok bool) {
	var cuttable []int
	for i, e := range edges {
		if e.Cost != Uncuttable {
			cuttable = append(cuttable, i)
		}
	}
	for mask := range 1 << len(cuttable) {
		removed := map[int]bool{}
		var c int64
		for b, i := range cuttable {
			if mask&(1<<b) != 0 {
				removed[i] = true
				c += edges[i].Cost
			}
		}
		if !connected(n, edges, removed, s, t) && (!ok || c < cost) {
			cost, ok = c, true
		}
	}
	return cost, ok
}

// Random graphs of at most 8 nodes: Dinic finds the same minimum cost as
// brute force, and removing the edges it chose really separates s from t.
func TestMinCutMatchesBruteForce(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 8).Draw(t, "nodes")
		m := rapid.IntRange(0, 14).Draw(t, "edges")
		edges := make([]FlowEdge, m)
		for i := range edges {
			cost := rapid.SampledFrom([]int64{0, 1, 1, 2, 3, 5, 8, 20, 100, Uncuttable}).Draw(t, "cost")
			edges[i] = FlowEdge{From: rapid.IntRange(0, n-1).Draw(t, "from"), To: rapid.IntRange(0, n-1).Draw(t, "to"), Cost: cost}
		}
		s := rapid.IntRange(0, n-1).Draw(t, "s")
		dst := rapid.IntRange(0, n-1).Filter(func(v int) bool { return v != s }).Draw(t, "t")

		cut := MinCut(n, edges, s, dst)
		want, ok := bruteForce(n, edges, s, dst)
		if cut.Finite != ok {
			t.Fatalf("finite = %v, brute force finds a cut = %v (%+v)", cut.Finite, ok, edges)
		}
		if !ok {
			return
		}
		if cut.Cost != want {
			t.Fatalf("cost %d, brute force %d (%+v)", cut.Cost, want, edges)
		}
		removed := map[int]bool{}
		var sum int64
		for _, i := range cut.Edges {
			if edges[i].Cost == Uncuttable {
				t.Fatalf("an uncuttable edge was cut: %d", i)
			}
			removed[i] = true
			sum += edges[i].Cost
		}
		if sum != cut.Cost {
			t.Fatalf("cut edges cost %d, reported %d", sum, cut.Cost)
		}
		if connected(n, edges, removed, s, dst) {
			t.Fatalf("cutting %v leaves a path from %d to %d (%+v)", cut.Edges, s, dst, edges)
		}
	})
}

// Fixture-01 shape: RUNS_AS (100) -> ASSUMES (5) -> CAN_DECRYPT (1) and
// CAN_READ (1) in series under the derived read: the cheapest edge is cut,
// never the workload's own identity.
func TestMinCutPrefersCheapFix(t *testing.T) {
	edges := []FlowEdge{
		{0, 1, 100}, // workload -RUNS_AS-> service account
		{1, 2, 5},   // service account -ASSUMES-> role
		{2, 3, 1},   // role -CAN_DECRYPT[for jewel]-> (read + decrypt) -> jewel
	}
	cut := MinCut(4, edges, 0, 3)
	if !cut.Finite || cut.Cost != 1 || len(cut.Edges) != 1 || cut.Edges[0] != 2 {
		t.Fatalf("cut %+v", cut)
	}
	edges[2].Cost, edges[1].Cost = Uncuttable, Uncuttable // intended access, uncuttable trust
	if cut := MinCut(4, edges, 0, 3); !cut.Finite || cut.Edges[0] != 0 || cut.Cost != 100 {
		t.Fatalf("only RUNS_AS is left: %+v", cut)
	}
	edges[0].Cost = Uncuttable
	if cut := MinCut(4, edges, 0, 3); cut.Finite {
		t.Fatalf("no fix within constraints: %+v", cut)
	}
	if cut := MinCut(4, edges, 1, 1); cut.Finite {
		t.Fatal("s == t has no cut")
	}
}

// Of two equal-cost cuts, the one closest to the source is returned.
func TestMinCutClosestToSource(t *testing.T) {
	edges := []FlowEdge{{0, 1, 1}, {1, 2, 1}}
	if cut := MinCut(3, edges, 0, 2); len(cut.Edges) != 1 || cut.Edges[0] != 0 {
		t.Fatalf("cut %+v", cut)
	}
}
