package pathrules

import (
	"slices"
	"testing"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/rules"
)

// fixSides names the chosen side of each cut edge, the other sides, and a
// resource whose policy alone breaks two or more cut edges (SCORING.md §4.3).
func TestFixSides(t *testing.T) {
	const bucket = "arn:aws:s3:::b"
	b := graph.NewBuilder()
	node := func(kind model.NodeKind, identity string) graph.NodeID {
		return b.Node(model.NewID(kind, identity), kind, identity)
	}
	r1 := node(model.KindIAMRole, "arn:aws:iam::1:role/r1")
	r2 := node(model.KindIAMRole, "arn:aws:iam::1:role/r2")
	r3 := node(model.KindIAMRole, "arn:aws:iam::1:role/r3")
	j := node(model.KindS3Bucket, bucket)
	other := node(model.KindS3Bucket, "arn:aws:s3:::other")
	read := func(from, to graph.NodeID, resource string) graph.EdgeID {
		return b.Edge(&graph.Edge{From: from, To: to, Kind: graph.CanRead, Fixes: []graph.Fix{
			{Side: graph.SideIdentity, Policy: "p", Cost: 1},
			{Side: graph.SideResource, Policy: resource + " bucket policy", Resource: resource, Cost: 2},
		}})
	}
	e1, e2 := read(r1, j, bucket), read(r2, j, bucket)
	e3 := read(r3, other, "arn:aws:s3:::other")
	g := b.Build()

	f := &rules.Finding{ChokepointEdge: []graph.EdgeID{e1, e2}}
	fixSides(g, f)
	if len(f.Fix) != 2 || f.Fix[0].Side != graph.SideIdentity || f.Fix[0].Cost != 1 {
		t.Fatalf("chosen sides: %+v", f.Fix)
	}
	if len(f.OtherSideFix) != 2 || f.OtherSideFix[0].Side != graph.SideResource || f.OtherSideFix[0].Policy != bucket+" bucket policy" {
		t.Fatalf("other sides: %+v", f.OtherSideFix)
	}
	if !slices.Equal(f.SharedFix, []string{bucket}) {
		t.Fatalf("one bucket policy breaks both cut edges: %v", f.SharedFix)
	}

	// Two cut edges on different buckets share no fix.
	f = &rules.Finding{ChokepointEdge: []graph.EdgeID{e1, e3}}
	fixSides(g, f)
	if len(f.SharedFix) != 0 {
		t.Fatalf("no shared fix across buckets: %v", f.SharedFix)
	}
	// A single cut edge shares nothing.
	f = &rules.Finding{ChokepointEdge: []graph.EdgeID{e1}}
	fixSides(g, f)
	if len(f.SharedFix) != 0 {
		t.Fatalf("one edge cannot share: %v", f.SharedFix)
	}
}
