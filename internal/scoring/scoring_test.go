package scoring

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

func TestFactorTables(t *testing.T) {
	for edges, want := range map[int]int{1: 1000, 2: 900, 3: 810, 4: 729, 5: 656} {
		if got := Hops(edges); got != want {
			t.Errorf("Hops(%d) = %d, want %d", edges, got, want)
		}
	}
	for n, want := range map[int]int{0: 1000, 1: 1000, 2: 1100, 3: 1100, 4: 1200, 32: 1500, 1 << 20: 1500} {
		if got := BlastRadius(n); got != want {
			t.Errorf("BlastRadius(%d) = %d, want %d", n, got, want)
		}
	}
	for score, want := range map[int]string{1000: "critical", 700: "critical", 699: "high", 450: "high", 449: "medium", 250: "medium", 249: "low", 100: "low", 99: "info"} {
		if got := Severity(score); got != want {
			t.Errorf("Severity(%d) = %s, want %s", score, got, want)
		}
	}
	for class, want := range map[string]int{"secret": 1000, "PCI": 1000, "phi": 1000, "pii": 900, "confidential": 700, "internal": 400, "sensitive": 600} {
		if got := Classification(class); got != want {
			t.Errorf("Classification(%s) = %d", class, got)
		}
	}
	exposures := []struct {
		reason string
		public model.Tri
		want   int
	}{
		{"anonymous", model.True, 1000},
		{"assume-compromised", model.Unknown, 400},
		{"exposed:Service/LoadBalancer", model.True, 1000},
		{"exposed:Service/LoadBalancer", model.False, 500},
		{"exposed:Service/LoadBalancer", model.Unknown, 1000},
		{"exposed:Service/NodePort", model.Unknown, 800},
		{"exposed:Ingress", model.True, 1000},
	}
	for _, e := range exposures {
		if got := Exposure(e.reason, e.public); got != e.want {
			t.Errorf("Exposure(%s, %s) = %d, want %d", e.reason, e.public, got, e.want)
		}
	}
	for c, want := range map[graph.Confidence]int{graph.High: 1000, graph.Medium: 700, graph.Low: 400} {
		if ConfidenceWeight(c) != want {
			t.Errorf("ConfidenceWeight(%s)", c)
		}
	}
}

func TestFixCosts(t *testing.T) {
	n, r := graph.FixNarrow, graph.FixRevoke
	cases := []struct {
		kind         graph.Kind
		sub, side, k string
		want         int64
	}{
		{graph.Assumes, "sts", graph.SideIdentity, n, 1},
		{graph.Assumes, "sts", graph.SideIdentity, r, 3},
		{graph.Assumes, "sts", graph.SideTrust, n, 5},
		{graph.Assumes, "irsa", graph.SideTrust, r, 7},
		{graph.CanRead, "", graph.SideIdentity, n, 1},
		{graph.CanRead, "", graph.SideIdentity, r, 3},
		{graph.CanRead, "public", graph.SideResource, n, 2},
		{graph.CanRead, "", graph.SideResource, r, 4},
		{graph.CanDecrypt, "", graph.SideIdentity, n, 1},
		{graph.CanDecrypt, "", graph.SideResource, n, 2},
		{graph.CanEscalate, "iam:passrole:lambda", graph.SideIdentity, n, 2},
		{graph.CanEscalate, "iam:passrole:lambda", graph.SideIdentity, r, 4},
		// Fact sides have a fixed cost whatever their kind.
		{graph.CanEscalate, "k8s-token", graph.SideWorkload, n, 3},
		{graph.RunsAs, "", graph.SideWorkload, r, 100},
		{graph.CanEscalate, "rbac", graph.SideRBAC, r, 5},
		{graph.MapsTo, "Group", graph.SideMapping, r, 8},
		{graph.NodeRole, "", graph.SideNode, n, 3},
		{graph.Protects, "", "none", n, -1},
	}
	for _, c := range cases {
		if got := FixCost(c.kind, c.sub, c.side, c.k); got != c.want {
			t.Errorf("%s/%s %s %s = %d, want %d", c.kind, c.sub, c.side, c.k, got, c.want)
		}
	}
}

// SCORING.md §1.4: public LoadBalancer, 3 edges, all high, one pii jewel = 729.
func TestWorkedExample(t *testing.T) {
	b := graph.NewBuilder()
	n := func(s string) graph.NodeID { return b.Node(model.ID(s), "k", s) }
	w, sa, role, jewel := n("w"), n("sa"), n("role"), n("jewel")
	ids := []graph.EdgeID{
		b.Edge(&graph.Edge{From: w, To: sa, Kind: graph.RunsAs, For: graph.NoNode, Verdict: eval.Allow, Confidence: graph.High}),
		b.Edge(&graph.Edge{From: sa, To: role, Kind: graph.Assumes, For: graph.NoNode, Verdict: eval.Allow, Confidence: graph.High}),
		b.Edge(&graph.Edge{From: role, To: jewel, Kind: graph.CanReadPlaintext, For: graph.NoNode, Verdict: eval.Allow, Confidence: graph.High}),
	}
	g := b.Build()
	path := make([]graph.EdgeID, len(ids))
	for i := range ids {
		path[i] = graph.EdgeID(i) // Build sorts: here edges are already in from-order
	}
	f := Path(g, path, Exposure("exposed:Service/LoadBalancer", model.True), Classification("pii"), 1)
	if f.Likelihood != 810 || f.Impact != 900 || f.Score != 729 || f.Severity != "critical" {
		t.Fatalf("%+v", f)
	}
	f = Path(g, path, Exposure("assume-compromised", model.Unknown), Classification("pii"), 1)
	if f.Score != 291 || f.Severity != "medium" {
		t.Fatalf("not exposed: %+v", f)
	}
	unknown := graph.NewBuilder()
	a, c := unknown.Node("a", "k", "a"), unknown.Node("b", "k", "b")
	unknown.Edge(&graph.Edge{
		From: a, To: c, Kind: graph.NodeRole, For: graph.NoNode, Confidence: graph.Low,
		Precondition: &graph.Precondition{State: model.Unknown},
	})
	f = Path(unknown.Build(), []graph.EdgeID{0}, 1000, 900, 1)
	if f.Preconditions != 500 || f.Confidence != 400 || f.Likelihood != 200 {
		t.Fatalf("unknown precondition: %+v", f)
	}
	if s, sev := Posture(BaseHigh, graph.High); s != 600 || sev != "high" {
		t.Errorf("posture high: %d %s", s, sev)
	}
	if s, sev := Posture(BaseMedium, graph.Medium); s != 245 || sev != "low" {
		t.Errorf("posture medium/medium: %d %s", s, sev)
	}
}
