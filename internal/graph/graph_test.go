package graph

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/model"
)

// Build orders nodes by canonical ID and edges by (from, kind, to, sub,
// for): the same content in any insertion order gives the same graph.
func TestBuildIsDeterministic(t *testing.T) {
	build := func(reverse bool) *Graph {
		b := NewBuilder()
		names := []string{"c", "a", "b"}
		if reverse {
			names = []string{"b", "a", "c"}
		}
		ids := map[string]NodeID{}
		for _, n := range names {
			ids[n] = b.Node(model.ID(n), "k", "id-"+n)
		}
		if again := b.Node("a", "k", "ignored"); again != ids["a"] {
			t.Fatal("Node must return the existing node")
		}
		edges := []*Edge{
			{From: ids["a"], To: ids["c"], Kind: CanRead, For: NoNode, Verdict: eval.Allow},
			{From: ids["a"], To: ids["b"], Kind: Assumes, For: NoNode, Verdict: eval.Allow},
			{From: ids["b"], To: ids["c"], Kind: CanDecrypt, For: ids["a"], Verdict: eval.Unknown},
		}
		if reverse {
			edges[0], edges[2] = edges[2], edges[0]
		}
		var under []EdgeID
		for _, e := range edges {
			under = append(under, b.Edge(e))
		}
		b.Edge(&Edge{From: ids["b"], To: ids["c"], Kind: CanReadPlaintext, For: NoNode, Under: under[:1]})
		if _, ok := b.Lookup("a"); !ok {
			t.Fatal("Lookup")
		}
		return b.Build()
	}
	g1, g2 := build(false), build(true)
	if g1.NumNodes() != 3 || g1.NumEdges() != 4 {
		t.Fatalf("%d nodes %d edges", g1.NumNodes(), g1.NumEdges())
	}
	for i := range g1.NumEdges() {
		if g1.Describe(EdgeID(i)) != g2.Describe(EdgeID(i)) {
			t.Errorf("edge %d: %s vs %s", i, g1.Describe(EdgeID(i)), g2.Describe(EdgeID(i)))
		}
	}
	a, _ := g1.Lookup("a")
	if g1.Node(a).Identity != "id-a" || len(g1.Out(a)) != 2 || g1.Edge(g1.Out(a)[0]).Kind != Assumes {
		t.Errorf("out edges of a: %v", g1.Out(a))
	}
	if d := g1.Describe(g1.Out(1)[0]); d != "CAN_DECRYPT[for id-a] id-b -> id-c" {
		t.Errorf("Describe: %s", d)
	}
	// The derived edge's Under is remapped to the final edge IDs.
	for i := range g1.NumEdges() {
		if e := g1.Edge(EdgeID(i)); e.Kind == CanReadPlaintext {
			if g1.Edge(e.Under[0]).Kind != CanRead && g1.Edge(e.Under[0]).Kind != CanDecrypt {
				t.Errorf("under: %v", g1.Edge(e.Under[0]))
			}
		}
	}
	if High.String() != "high" || Medium.String() != "medium" || Low.String() != "low" {
		t.Error("Confidence.String")
	}
}
