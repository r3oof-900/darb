package paths

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

type tg struct {
	b     *graph.Builder
	nodes map[string]graph.NodeID
}

func newTG() *tg { return &tg{b: graph.NewBuilder(), nodes: map[string]graph.NodeID{}} }

func (t *tg) n(name string) graph.NodeID {
	if id, ok := t.nodes[name]; ok {
		return id
	}
	id := t.b.Node(model.ID(name), "k", name)
	t.nodes[name] = id
	return id
}

func (t *tg) e(from, to string, kind graph.Kind, sub string) graph.EdgeID {
	return t.b.Edge(&graph.Edge{From: t.n(from), To: t.n(to), Kind: kind, Sub: sub, For: graph.NoNode, Verdict: eval.Allow, Confidence: graph.High})
}

func lookup(g *graph.Graph, name string) graph.NodeID {
	n, _ := g.Lookup(model.ID(name))
	return n
}

func cost(g *graph.Graph) func(graph.EdgeID) int64 {
	costs := map[graph.Kind]int64{graph.RunsAs: 100, graph.CanDecrypt: 1, graph.CanRead: 1}
	return func(id graph.EdgeID) int64 {
		if c, ok := costs[g.Edge(id).Kind]; ok {
			return c
		}
		return 5
	}
}

// After RUNS_AS a pod has its cloud identity, not its Kubernetes token:
// RBAC escalation needs CAN_ESCALATE[k8s-token]; after the token, only RBAC
// edges follow (DESIGN.md §7.2).
func TestModes(t *testing.T) {
	x := newTG()
	x.e("w", "sa", graph.RunsAs, "")
	x.e("sa", "other", graph.CanEscalate, "rbac")
	x.e("other", "role", graph.Assumes, "irsa")
	x.e("role", "jewel", graph.CanReadPlaintext, "")
	g := x.b.Build()
	pairs := Analyze(g, []graph.NodeID{lookup(g, "w")}, []graph.NodeID{lookup(g, "jewel")}, Options{Cost: cost(g)})
	if len(pairs) != 0 {
		t.Fatalf("RBAC after RUNS_AS: %+v", pairs)
	}
	y := newTG()
	y.e("w", "sa", graph.RunsAs, "")
	y.e("w", "sa", graph.CanEscalate, "k8s-token")
	y.e("sa", "other", graph.CanEscalate, "rbac")
	y.e("sa", "role", graph.Assumes, "irsa")
	y.e("other", "role2", graph.Assumes, "irsa")
	y.e("role2", "jewel", graph.CanReadPlaintext, "")
	g = y.b.Build()
	w, jewel, role := lookup(g, "w"), lookup(g, "jewel"), lookup(g, "role")
	pairs = Analyze(g, []graph.NodeID{w}, []graph.NodeID{jewel, role}, Options{Cost: cost(g)})
	if len(pairs) != 2 {
		t.Fatalf("pairs: %+v", pairs)
	}
	for _, p := range pairs {
		if p.Jewel == jewel && (len(p.Paths) != 1 || len(p.Paths[0]) != 4 || g.Edge(p.Paths[0][0]).Sub != "k8s-token") {
			t.Errorf("token -> rbac -> irsa -> read: %+v", p.Paths)
		}
		if p.Jewel == role && (len(p.Paths) != 1 || g.Edge(p.Paths[0][0]).Kind != graph.RunsAs) {
			t.Errorf("only RUNS_AS reaches the IRSA role directly: %+v", p.Paths)
		}
	}
	if !Reachable(g, w)[jewel] {
		t.Error("Reachable")
	}
}

func TestEnumerationCaps(t *testing.T) {
	x := newTG()
	for _, mid := range []string{"a", "b", "c"} {
		x.e("w", mid, graph.Assumes, "sts")
		x.e(mid, "jewel", graph.CanReadPlaintext, "")
	}
	g := x.b.Build()
	pairs := Analyze(g, []graph.NodeID{lookup(g, "w")}, []graph.NodeID{lookup(g, "jewel")}, Options{MaxPaths: 2, Cost: cost(g)})
	if len(pairs) != 1 || len(pairs[0].Paths) != 2 || !pairs[0].Truncated {
		t.Fatalf("path cap: %+v", pairs)
	}
	pairs = Analyze(g, []graph.NodeID{lookup(g, "w")}, []graph.NodeID{lookup(g, "jewel")}, Options{MaxDepth: 1, Cost: cost(g)})
	if len(pairs[0].Paths) != 0 || !pairs[0].Truncated {
		t.Fatalf("depth cap: %+v", pairs)
	}
}

// The derived read costs its cheapest underlying edge; CAN_DECRYPT is cut
// only on a tie; the other cuttable underlying edge, at any cost, is the
// alternative.
func TestDerivedEdgeCut(t *testing.T) {
	x := newTG()
	x.e("w", "role", graph.Assumes, "irsa")
	read := x.e("role", "jewel", graph.CanRead, "")
	dec := x.b.Edge(&graph.Edge{From: x.n("role"), To: x.n("key"), Kind: graph.CanDecrypt, For: x.n("jewel"), Verdict: eval.Allow})
	x.b.Edge(&graph.Edge{From: x.n("role"), To: x.n("jewel"), Kind: graph.CanReadPlaintext, For: graph.NoNode, Verdict: eval.Allow, Under: []graph.EdgeID{read, dec}})
	g := x.b.Build()
	pairs := Analyze(g, []graph.NodeID{lookup(g, "w")}, []graph.NodeID{lookup(g, "jewel")}, Options{Cost: cost(g)})
	p := pairs[0]
	if !p.Cut.Finite || p.Cut.Cost != 1 || len(p.Cut.Edges) != 1 || g.Edge(cutEdge(&p)).Kind != graph.CanDecrypt ||
		len(p.Alternative) != 1 || g.Edge(p.Alternative[0]).Kind != graph.CanRead {
		t.Fatalf("cut %+v alternative %v", p.Cut, p.Alternative)
	}
	expensiveRead := func(id graph.EdgeID) int64 {
		if g.Edge(id).Kind == graph.CanRead {
			return 9
		}
		return cost(g)(id)
	}
	p = Analyze(g, []graph.NodeID{lookup(g, "w")}, []graph.NodeID{lookup(g, "jewel")}, Options{Cost: expensiveRead})[0]
	if len(p.Alternative) != 1 || g.Edge(p.Alternative[0]).Kind != graph.CanRead || g.Edge(cutEdge(&p)).Kind != graph.CanDecrypt {
		t.Fatalf("the dearer read is still the alternative: %+v %v", p.Cut, p.Alternative)
	}
	expensiveDecrypt := func(id graph.EdgeID) int64 {
		if g.Edge(id).Kind == graph.CanDecrypt {
			return 9
		}
		return cost(g)(id)
	}
	p = Analyze(g, []graph.NodeID{lookup(g, "w")}, []graph.NodeID{lookup(g, "jewel")}, Options{Cost: expensiveDecrypt})[0]
	if p.Cut.Cost != 1 || g.Edge(cutEdge(&p)).Kind != graph.CanRead || len(p.Alternative) != 1 || g.Edge(p.Alternative[0]).Kind != graph.CanDecrypt {
		t.Fatalf("a cheaper read is cut, no tie rule: %+v %v", p.Cut, p.Alternative)
	}
	uncuttableRead := func(id graph.EdgeID) int64 {
		if g.Edge(id).Kind == graph.CanRead {
			return Uncuttable
		}
		return cost(g)(id)
	}
	p = Analyze(g, []graph.NodeID{lookup(g, "w")}, []graph.NodeID{lookup(g, "jewel")}, Options{Cost: uncuttableRead})[0]
	if len(p.Alternative) != 0 || g.Edge(cutEdge(&p)).Kind != graph.CanDecrypt {
		t.Fatalf("an uncuttable read is no alternative: %+v %v", p.Cut, p.Alternative)
	}
	uncuttable := func(graph.EdgeID) int64 { return Uncuttable }
	p = Analyze(g, []graph.NodeID{lookup(g, "w")}, []graph.NodeID{lookup(g, "jewel")}, Options{Cost: uncuttable})[0]
	if p.Cut.Finite {
		t.Fatalf("no fix within constraints: %+v", p.Cut)
	}
}

func cutEdge(p *Pair) graph.EdgeID {
	return graph.EdgeID(p.Cut.Edges[0]) //nolint:gosec // G115: small test graphs
}

// A Kubernetes Secret read is RBAC: never with the cloud identity alone.
func TestSecretReadNeedsKubernetesCredentials(t *testing.T) {
	read := &graph.Edge{Kind: graph.CanReadPlaintext, Sub: "k8s"}
	if allowed(identity, read) || !allowed(k8s, read) || !allowed(full, read) {
		t.Fatal("CAN_READ_PLAINTEXT[k8s] follows the token or an RBAC escalation only")
	}
	if !allowed(identity, &graph.Edge{Kind: graph.CanReadPlaintext}) {
		t.Fatal("an AWS read follows the cloud identity")
	}
}
