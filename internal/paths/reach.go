package paths

import (
	"slices"

	"github.com/r3oof-900/darb/internal/graph"
)

// Breaks reports whether no path of the selection is left once the broken edges are gone
// (a derived edge breaks with any of its underlying edges).
func Breaks(g *graph.Graph, entry, jewel graph.NodeID, sel *Select, broken map[graph.EdgeID]bool) bool {
	gone := func(id graph.EdgeID) bool {
		if broken[id] {
			return true
		}
		return slices.ContainsFunc(g.Edge(id).Under, func(u graph.EdgeID) bool { return broken[u] })
	}
	start := sel.start(entry)
	seen := map[pstate]bool{start: true}
	queue := []pstate{start}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if sel.sink(s, jewel) {
			return false
		}
		for _, id := range g.Out(s.node) {
			nx, ok := sel.next(s, id, g.Edge(id))
			if ok && !gone(id) && !seen[nx] {
				seen[nx] = true
				queue = append(queue, nx)
			}
		}
	}
	return true
}

// Selected reports whether the selection has any path between entry and jewel.
func Selected(g *graph.Graph, entry, jewel graph.NodeID, sel *Select) bool {
	return !Breaks(g, entry, jewel, sel, nil)
}

// ReachesDirect reports whether, from the source of path[k] (in the mode the path reaches
// it with), the jewel is reachable without any CAN_ESCALATE through edges ok
// accepts (DESIGN.md §8, dominated escalations).
func ReachesDirect(g *graph.Graph, path Path, k int, jewel graph.NodeID, ok func(graph.EdgeID) bool) bool {
	m := full
	if k > 0 {
		m = target(g.Edge(path[k-1]))
	}
	start := state{g.Edge(path[k]).From, m}
	seen := map[state]bool{start: true}
	queue := []state{start}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if s.node == jewel {
			return true
		}
		for _, id := range g.Out(s.node) {
			e := g.Edge(id)
			if !traversed(e) || !allowed(s.mode, e) || e.Kind == graph.CanEscalate || !ok(id) {
				continue
			}
			if next := (state{e.To, target(e)}); !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	return false
}
