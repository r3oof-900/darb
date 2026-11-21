package pathrules

import (
	"slices"
	"testing"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/paths"
)

// sharedFixes names every resource or policy one change to which breaks two
// or more cut edges (SCORING.md §4.3): a bucket policy, a principal's inline
// policy (by the principal), a managed policy (by its ARN).
func TestSharedFixes(t *testing.T) {
	const bucket = "arn:aws:s3:::b"
	const managed = "arn:aws:iam::1:policy/shared"
	b := graph.NewBuilder()
	node := func(kind model.NodeKind, identity string) graph.NodeID {
		return b.Node(model.NewID(kind, identity), kind, identity)
	}
	r1 := node(model.KindIAMRole, "arn:aws:iam::1:role/r1")
	r2 := node(model.KindIAMRole, "arn:aws:iam::1:role/r2")
	j := node(model.KindS3Bucket, bucket)
	other := node(model.KindS3Bucket, "arn:aws:s3:::other")
	key := node(model.KindKMSKey, "arn:aws:kms:us-east-1:1:key/k")
	read := func(from, to graph.NodeID, resource, policy string) {
		b.Edge(&graph.Edge{From: from, To: to, Kind: graph.CanRead, Fixes: []graph.Fix{
			{Side: graph.SideIdentity, Kind: graph.FixNarrow, Policy: policy, Cost: 1, Grants: []graph.Grant{{Policy: policy}}},
			{Side: graph.SideResource, Kind: graph.FixNarrow, Policy: resource + " bucket policy", Resource: resource, Cost: 2},
		}})
	}
	read(r1, j, bucket, "inline-1")
	read(r2, j, bucket, managed)
	read(r1, other, "arn:aws:s3:::other", "inline-1")
	b.Edge(&graph.Edge{From: r2, To: key, Kind: graph.CanDecrypt, Fixes: []graph.Fix{
		{Side: graph.SideIdentity, Kind: graph.FixNarrow, Policy: managed, Cost: 1, Grants: []graph.Grant{{Policy: managed}}},
	}})
	g := b.Build()
	// Build renumbers the edges: find them by what they join.
	find := func(from, to string) graph.EdgeID {
		for i := range g.NumEdges() {
			id := graph.EdgeID(i)
			if g.Node(g.Edge(id).From).Identity == from && g.Node(g.Edge(id).To).Identity == to {
				return id
			}
		}
		t.Fatalf("no edge %s -> %s", from, to)
		return 0
	}
	e1, e2 := find("arn:aws:iam::1:role/r1", bucket), find("arn:aws:iam::1:role/r2", bucket)
	e3, e4 := find("arn:aws:iam::1:role/r1", "arn:aws:s3:::other"), find("arn:aws:iam::1:role/r2", "arn:aws:kms:us-east-1:1:key/k")
	way := func(e graph.EdgeID, fix int) paths.Way { return paths.Way{Edge: e, Fix: fix, HasKnown: true} }
	cases := []struct {
		name string
		ways []paths.Way
		want []string
	}{
		{"one bucket policy breaks both", []paths.Way{way(e1, 1), way(e2, 1)}, []string{bucket}},
		{"one inline policy of r1 breaks both", []paths.Way{way(e1, 0), way(e3, 0)}, []string{"arn:aws:iam::1:role/r1"}},
		{"one managed policy breaks both", []paths.Way{way(e2, 0), way(e4, 0)}, []string{managed}},
		{"different buckets share nothing", []paths.Way{way(e1, 1), way(e3, 1)}, nil},
		{"one edge shares nothing", []paths.Way{way(e1, 1)}, nil},
	}
	for _, c := range cases {
		if got := sharedFixes(g, c.ways); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
