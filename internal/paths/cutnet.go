package paths

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

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

// skey: units merged because they are one change on edges into one state
// (sameChange).
type skey struct {
	sig string
	to  int
}

type unit struct {
	// members: the ways of the other edges merged into this unit (one
	// change into one head), in the order of ways.
	members [][]Way
	edge    graph.EdgeID
	in      int
	ways    []Way
	arcs    [][]int // per way: its known and resolve arcs
	groups  [][]int // per way: its detach group arcs
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
	bySig  map[skey]*unit
	order  []*unit
	group  map[gkey]int // group arc index
	sinks  []int
	jewel  graph.NodeID
}

func newCutNetwork(g *graph.Graph, entry, jewel graph.NodeID, sel *Select, opts *Options, ex *exclude) *network {
	w := &network{g: g, opts: opts, sel: sel, ex: ex, states: map[pstate]int{}, units: map[ukey]*unit{}, bySig: map[skey]*unit{}, group: map[gkey]int{}, jewel: jewel}
	start := sel.start(entry)
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
			nx, ok := sel.next(s, id, g.Edge(id))
			if !ok {
				continue
			}
			if nx.route != offRoute {
				// A step along the protected route: never cut on it (its
				// edges are uncuttable for every finding, app.intendedEdges),
				// and a unit, shared per edge and phase, would lead an
				// off-route walk onto the route's states.
				w.arcs = append(w.arcs, FlowEdge{From: w.state(s), To: w.state(nx), Cost: Uncuttable})
			} else {
				u := w.unit(id, s.esc, nx)
				w.arcs = append(w.arcs, FlowEdge{From: w.state(s), To: u.in, Cost: Uncuttable})
			}
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
	var kept []Way
	for _, way := range ways(w.g, id, w.opts) {
		if !w.ex.skips(w.g, &way) {
			kept = append(kept, way)
		}
	}
	// Two edges into the same head that break with exactly the same
	// changes (a synthetic principal's edge and its principal's, DESIGN.md
	// §9.1) are one unit: the change has one capacity, and every edge into
	// the unit still needs it, so the cut stays exact. Every sink state is
	// one head: flow into any of them reaches the sink (two phases of the
	// search, with and without an escalation taken, end at the same jewel).
	sk := skey{sameChange(w.g, kept), w.head(to)}
	if sk.sig != "" {
		if u, ok := w.bySig[sk]; ok {
			w.units[k] = u
			u.members = append(u.members, kept)
			return u
		}
	}
	u := &unit{edge: id, in: w.node(), ways: kept}
	w.units[k] = u
	if sk.sig != "" {
		w.bySig[sk] = u
	}
	w.order = append(w.order, u)
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

// head: the state a unit leads to, for merging; -1 for every sink state.
func (w *network) head(to pstate) int {
	if w.sel.sink(to, w.jewel) {
		return -1
	}
	return w.state(to)
}

// sameChange: the signature of a unit's ways, the changes that break it
// (side, kind, granting statements, detaches, resolve steps, cost); "" when
// a way is priced by Options.Cost alone (no statement to compare).
func sameChange(g *graph.Graph, ws []Way) string {
	if len(ws) == 0 {
		return ""
	}
	var b strings.Builder
	for _, w := range ws {
		if w.Fix < 0 {
			return ""
		}
		fx := &g.Edge(w.Edge).Fixes[w.Fix]
		fmt.Fprintf(&b, "%s|%s|%d|%v|", fx.Side, fx.Kind, w.Known, w.HasKnown)
		grants := slices.Clone(fx.Grants)
		slices.SortFunc(grants, func(a, c graph.Grant) int {
			return cmp.Or(strings.Compare(a.Policy, c.Policy), a.Statement-c.Statement)
		})
		for _, gr := range grants {
			fmt.Fprintf(&b, "g:%s#%d|", gr.Policy, gr.Statement)
		}
		for _, d := range w.Detach {
			fmt.Fprintf(&b, "d:%s|", d.Group)
		}
		for _, r := range w.Resolve {
			fmt.Fprintf(&b, "r:%s:%s|", r.Policy, r.Command)
		}
		b.WriteString(";")
	}
	return b.String()
}

// shared: the edges of merged units that the chosen ways' changes break
// too (one change, one unit): a cut breaks them with the chosen edges.
func (w *network) shared(chosen []Way) []graph.EdgeID {
	var out []graph.EdgeID
	for _, c := range chosen {
		for _, u := range w.order {
			i := slices.IndexFunc(u.ways, func(x Way) bool { return x.Edge == c.Edge && x.Fix == c.Fix })
			if i < 0 {
				continue
			}
			for _, m := range u.members {
				if i < len(m) && !slices.Contains(out, m[i].Edge) {
					out = append(out, m[i].Edge)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}
