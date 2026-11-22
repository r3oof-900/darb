package paths

import (
	"slices"

	"github.com/r3oof-900/darb/internal/graph"
)

// The flow network of one finding's cut (chokepoint.go).

type ukey struct {
	edge graph.EdgeID
	esc  bool
}

type gkey struct {
	group string
	esc   bool
}

type unit struct {
	edge   graph.EdgeID
	in     int
	ways   []Way
	arcs   [][]int // per way: its known and resolve arcs
	groups [][]int // per way: its detach group arcs
}

type network struct {
	g      *graph.Graph
	opts   *Options
	sel    *Select
	ex     *exclude
	n      int
	source int
	arcs   []FlowEdge
	states map[pstate]int
	units  map[ukey]*unit
	order  []*unit
	group  map[gkey]int // group arc index
	sinks  []int
}

func newCutNetwork(g *graph.Graph, entry, jewel graph.NodeID, sel *Select, opts *Options, ex *exclude) *network {
	w := &network{g: g, opts: opts, sel: sel, ex: ex, states: map[pstate]int{}, units: map[ukey]*unit{}, group: map[gkey]int{}}
	start := pstate{entry, full, false}
	w.source = w.state(start)
	seen := map[pstate]bool{start: true}
	queue := []pstate{start}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if sel.sink(s, jewel) {
			w.sinks = append(w.sinks, w.state(s))
		}
		for _, id := range g.Out(s.node) {
			nx, ok := sel.next(s, g.Edge(id))
			if !ok {
				continue
			}
			u := w.unit(id, s.esc, nx)
			w.arcs = append(w.arcs, FlowEdge{From: w.state(s), To: u.in, Cost: Uncuttable})
			if !seen[nx] {
				seen[nx] = true
				queue = append(queue, nx)
			}
		}
	}
	return w
}

func (w *network) state(s pstate) int {
	if i, ok := w.states[s]; ok {
		return i
	}
	w.states[s] = w.node()
	return w.states[s]
}

func (w *network) node() int {
	w.n++
	return w.n - 1
}

func (w *network) arc(from, to int, cost int64) int {
	w.arcs = append(w.arcs, FlowEdge{From: from, To: to, Cost: cost})
	return len(w.arcs) - 1
}

// unit adds an edge's chain once per phase; its target depends only on the
// edge and the phase (target mode, escalated after a CAN_ESCALATE).
func (w *network) unit(id graph.EdgeID, esc bool, to pstate) *unit {
	k := ukey{id, esc}
	if u, ok := w.units[k]; ok {
		return u
	}
	u := &unit{edge: id, in: w.node()}
	w.units[k] = u
	w.order = append(w.order, u)
	for _, way := range ways(w.g, id, w.opts) {
		if !w.ex.skips(w.g, &way) {
			u.ways = append(u.ways, way)
		}
	}
	// Ways with a shared group first: a flow entering the group from another
	// edge of the same principal then skips no side of this one. Then
	// CAN_DECRYPT: among equal blocks the cut closest to the entry takes the
	// first, so a tie names the decrypt (DESIGN.md §8.1).
	slices.SortStableFunc(u.ways, func(a, b Way) int {
		if d := len(b.Detach) - len(a.Detach); d != 0 {
			return d
		}
		return w.rank(&b) - w.rank(&a)
	})
	cur := u.in
	if len(u.ways) == 0 {
		next := w.node()
		w.arc(cur, next, Uncuttable)
		cur = next
	}
	for _, way := range u.ways {
		end := w.node()
		var arcs, groups []int
		if way.HasKnown {
			arcs = append(arcs, w.arc(cur, end, way.Known*scale))
		}
		for range way.Resolve {
			arcs = append(arcs, w.arc(cur, end, 1))
		}
		for _, d := range way.Detach {
			gi := w.groupArc(d, esc)
			groups = append(groups, gi)
			w.arc(cur, w.arcs[gi].From, Uncuttable)
			w.arc(w.arcs[gi].To, end, Uncuttable)
		}
		u.arcs, u.groups = append(u.arcs, arcs), append(u.groups, groups)
		cur = end
	}
	w.arc(cur, w.state(to), Uncuttable)
	return u
}

// rank: CAN_DECRYPT ways first among equals.
func (w *network) rank(x *Way) int {
	if w.g.Edge(x.Edge).Kind == graph.CanDecrypt {
		return 1
	}
	return 0
}

func (w *network) groupArc(d graph.Detach, esc bool) int {
	k := gkey{d.Group, esc}
	if i, ok := w.group[k]; ok {
		return i
	}
	in := w.node()
	out := w.node()
	i := w.arc(in, out, d.Cost*scale)
	w.group[k] = i
	return i
}

// solve: the minimum cut, as the set of its arcs.
func (w *network) solve() (map[int]bool, bool) {
	sink := w.n
	arcs := slices.Clone(w.arcs)
	for _, s := range w.sinks {
		arcs = append(arcs, FlowEdge{From: s, To: sink, Cost: Uncuttable})
	}
	c := MinCut(w.n+1, arcs, w.source, sink)
	if !c.Finite || len(w.sinks) == 0 {
		return nil, false
	}
	cut := map[int]bool{}
	for _, i := range c.Edges {
		cut[i] = true
	}
	return cut, true
}

// chosen: the ways the cut breaks, one per unit (a derived edge names
// CAN_DECRYPT when both underlying edges break, DESIGN.md §8.1), each
// (edge, fix) once.
func (w *network) chosen(cut map[int]bool) []Way {
	var out []Way
	seen := map[[2]int]bool{}
	for _, u := range w.order {
		var broken []Way
		for i := range u.ways {
			all := len(u.arcs[i])+len(u.groups[i]) > 0
			for _, a := range slices.Concat(u.arcs[i], u.groups[i]) {
				all = all && cut[a]
			}
			if all {
				broken = append(broken, u.ways[i])
			}
		}
		if len(broken) == 0 {
			continue
		}
		pick := broken[0]
		for _, b := range broken {
			if w.g.Edge(b.Edge).Kind == graph.CanDecrypt {
				pick = b
				break
			}
		}
		if k := [2]int{int(pick.Edge), pick.Fix}; !seen[k] {
			seen[k] = true
			out = append(out, pick)
		}
	}
	return out
}
