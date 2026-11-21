package app

import "github.com/r3oof-900/clapa/internal/graph"

// noEdges reports every edge between nodes the expected file forbids.
func noEdges(forbidden []expectedNoEdge, g *graph.Graph) []string {
	var out []string
	for _, ne := range forbidden {
		for i := range g.NumEdges() {
			id := graph.EdgeID(i)
			e := g.Edge(id)
			if g.Node(e.From).Identity == ne.From && g.Node(e.To).Identity == ne.To {
				out = append(out, "edge must not exist: "+g.Describe(id))
			}
		}
	}
	return out
}
