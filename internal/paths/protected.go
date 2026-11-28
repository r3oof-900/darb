package paths

import "github.com/r3oof-900/darb/internal/graph"

// offRoute: a walk that is not (or no longer) on Select.Protected.
const offRoute = -1

// start is the state of a walk from entry: on the protected route, at its
// first edge, when the selection has one.
func (s *Select) start(entry graph.NodeID) pstate {
	route := offRoute
	if len(s.Protected) > 0 {
		route = 0
	}
	return pstate{entry, full, false, route}
}

// follow: the route position after taking edge id from position at. A walk
// stays on the route only while it takes the route's edges in order.
func (s *Select) follow(at int, id graph.EdgeID) int {
	if at == offRoute || at >= len(s.Protected) || s.Protected[at] != id {
		return offRoute
	}
	return at + 1
}

// protectedEnd: the walk took every edge of the protected route, so it
// reached the jewel the way the user declared, which is no finding.
func (s *Select) protectedEnd(at int) bool {
	return len(s.Protected) > 0 && at == len(s.Protected)
}

// OnRoute reports whether path is exactly the protected route.
func (s *Select) OnRoute(path Path) bool {
	if len(path) != len(s.Protected) || len(path) == 0 {
		return false
	}
	for i, id := range path {
		if s.Protected[i] != id {
			return false
		}
	}
	return true
}
