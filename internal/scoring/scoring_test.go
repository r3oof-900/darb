package scoring

import (
	"fmt"
	"testing"

	"pgregory.net/rapid"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
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
		{graph.RunsAs, "k8s-token", graph.SideWorkload, n, 3},
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
	// Worst case (SCORING.md 1): the unknown precondition counts as
	// satisfied (900); the low confidence is reported, not multiplied.
	if f.Preconditions != 900 || f.Confidence != 400 || f.Likelihood != 900 || f.Score != 810 || f.Severity != "critical" {
		t.Fatalf("unknown precondition: %+v", f)
	}
	if s, sev := Posture(BaseHigh, graph.High); s != 600 || sev != "high" {
		t.Errorf("posture high: %d %s", s, sev)
	}
	if s, sev := Posture(BaseMedium, graph.Medium); s != 245 || sev != "low" {
		t.Errorf("posture medium/medium: %d %s", s, sev)
	}
}

// Every resolution of a path's unknowns (each UNKNOWN edge allowed or
// denied, each UNKNOWN precondition satisfied or not) scores at most what
// is reported: the reported score is the worst case (SCORING.md 1).
func TestPropertyEveryResolutionScoresAtMostTheReported(t *testing.T) {
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 6).Draw(t, "edges")
		type spec struct {
			unknown bool
			pre     model.Tri // model.Unknown is used as "no precondition" below when hasPre is false
			hasPre  bool
			conf    graph.Confidence
		}
		specs := make([]spec, n)
		for i := range specs {
			specs[i] = spec{
				unknown: rapid.Bool().Draw(t, "unknown"), hasPre: rapid.Bool().Draw(t, "precondition"),
				pre:  rapid.SampledFrom([]model.Tri{model.True, model.Unknown}).Draw(t, "pre-state"),
				conf: rapid.SampledFrom([]graph.Confidence{graph.Low, graph.Medium, graph.High}).Draw(t, "confidence"),
			}
		}
		exposure := rapid.SampledFrom([]int{1000, 800, 500, 400}).Draw(t, "exposure")
		class := rapid.SampledFrom([]int{1000, 900, 700, 600, 400}).Draw(t, "classification")
		build := func(resolve func(i int, s spec) (eval.Verdict, model.Tri, graph.Confidence)) (*graph.Graph, []graph.EdgeID) {
			b := graph.NewBuilder()
			var ids []graph.EdgeID
			prev := b.Node("n0", "k", "n0")
			for i, s := range specs {
				next := b.Node(model.ID(fmt.Sprintf("n%d", i+1)), "k", fmt.Sprintf("n%d", i+1))
				v, pre, conf := resolve(i, s)
				e := &graph.Edge{From: prev, To: next, Kind: graph.Assumes, For: graph.NoNode, Verdict: v, Confidence: conf}
				if s.hasPre {
					e.Precondition = &graph.Precondition{State: pre}
				}
				ids = append(ids, b.Edge(e))
				prev = next
			}
			return b.Build(), ids
		}
		g, path := build(func(_ int, s spec) (eval.Verdict, model.Tri, graph.Confidence) {
			if s.unknown {
				return eval.Unknown, s.pre, graph.Low
			}
			return eval.Allow, s.pre, s.conf
		})
		reported := Path(g, path, exposure, class, 1)
		gone := false
		// A resolved unknown is a decided edge: high confidence.
		g2, path2 := build(func(i int, s spec) (eval.Verdict, model.Tri, graph.Confidence) {
			v, pre, conf := eval.Allow, s.pre, s.conf
			if s.unknown {
				conf = graph.High
			}
			if s.unknown && !rapid.Bool().Draw(t, fmt.Sprintf("edge-%d-allowed", i)) {
				gone = true
			}
			if s.hasPre && s.pre == model.Unknown {
				if rapid.Bool().Draw(t, fmt.Sprintf("pre-%d-satisfied", i)) {
					pre = model.True
				} else {
					gone = true
				}
			}
			return v, pre, conf
		})
		if gone {
			return // that resolution has no path: nothing is reported for it
		}
		resolved := Path(g2, path2, exposure, class, 1)
		if resolved.Score > reported.Score || rank[resolved.Severity] > rank[reported.Severity] {
			t.Fatalf("a resolution scores %d (%s), above the reported %d (%s)", resolved.Score, resolved.Severity, reported.Score, reported.Severity)
		}
	})
}
