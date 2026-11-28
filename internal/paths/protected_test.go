package paths

import (
	"testing"

	"github.com/r3oof-900/darb/internal/graph"
)

// A pair reached by its declared route and by another one: the declared
// route is no way to the jewel, so the cut breaks only the other route,
// even where both share edges (RUNS_AS) and the declared one is
// uncuttable (DESIGN.md §9.1, scenario 28).
func TestProtectedRouteIsNotAWayToTheJewel(t *testing.T) {
	x := newTG()
	x.e("w", "sa", graph.RunsAs, "")
	x.e("sa", "own", graph.Assumes, "irsa")
	x.e("own", "jewel", graph.CanReadPlaintext, "")
	x.e("sa", "other", graph.Assumes, "irsa")
	x.e("other", "jewel", graph.CanReadPlaintext, "")
	g := x.b.Build()
	runs, own, ownRead := between(g, "w", "sa"), between(g, "sa", "own"), between(g, "own", "jewel")
	other, otherRead := between(g, "sa", "other"), between(g, "other", "jewel")
	w, jewel := lookup(g, "w"), lookup(g, "jewel")
	route := Path{runs, own, ownRead}
	base := cost(g)
	opts := &Options{Cost: func(id graph.EdgeID) int64 {
		if id == runs || id == own || id == ownRead {
			return Uncuttable
		}
		return base(id)
	}}

	if r := CutFor(g, w, jewel, &Select{}, opts); r.Finite {
		t.Fatalf("without the protected route the declared route blocks every cut: %+v", r)
	}
	sel := &Select{Protected: route}
	r := CutFor(g, w, jewel, sel, opts)
	// Both edges of the other route cost 5 here: the cut closest to the
	// entry is its trust, the read the alternative.
	if !r.Finite || len(r.Ways) != 1 || r.Ways[0].Edge != other || len(r.Alternative) != 1 || r.Alternative[0].Edge != otherRead {
		t.Fatalf("the cut is on the other route only: %+v", r)
	}
	if !Breaks(g, w, jewel, sel, map[graph.EdgeID]bool{otherRead: true}) {
		t.Error("cutting the other route leaves no path but the declared one")
	}
	if Breaks(g, w, jewel, &Select{}, map[graph.EdgeID]bool{otherRead: true}) {
		t.Error("without protection the declared route is still a path")
	}
	if !Breaks(g, w, jewel, sel, map[graph.EdgeID]bool{other: true}) {
		t.Error("cutting the other route's trust works too")
	}
	if !sel.OnRoute(route) || sel.OnRoute(Path{runs, other, otherRead}) || sel.OnRoute(Path{runs, own}) || (&Select{}).OnRoute(Path{}) {
		t.Error("OnRoute is exact equality with the protected route")
	}
}

// between: the built graph's edge from one named node to another (Build
// renumbers edges).
func between(g *graph.Graph, from, to string) graph.EdgeID {
	for _, id := range g.Out(lookup(g, from)) {
		if g.Edge(id).To == lookup(g, to) {
			return id
		}
	}
	panic(from + " -> " + to)
}

// Leaving the route and coming back to its edges is off the route: the
// walk is no longer the declared one.
func TestProtectedRouteLeftStaysLeft(t *testing.T) {
	sel := &Select{Protected: Path{1, 2, 3}}
	at := sel.follow(0, 1)
	at = sel.follow(at, 9)
	if at != offRoute || sel.follow(at, 2) != offRoute || sel.protectedEnd(sel.follow(at, 3)) {
		t.Errorf("a walk that left the route stays off it: %d", at)
	}
	if sel.follow(sel.follow(sel.follow(0, 1), 2), 3) != 3 || !sel.protectedEnd(3) {
		t.Error("the whole route ends on it")
	}
	if sel.follow(3, 4) != offRoute {
		t.Error("past the route's end is off it")
	}
	if (&Select{}).start(0).route != offRoute || sel.start(0).route != 0 {
		t.Error("start")
	}
}
