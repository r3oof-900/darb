package paths

import (
	"slices"

	"github.com/r3oof-900/darb/internal/graph"
)

// The cut of one finding (DESIGN.md §7.4, §8; SCORING.md §4).
//
// The flow network is expanded by (node, mode, escalated): the mode decides
// which edges may follow (paths.go), and "escalated" whether the walk has
// taken a CAN_ESCALATE yet, so a selection of paths can be cut exactly:
// the paths of DARB-PATH-001 with the dominated escalations merged into
// them, or the escalations that are not dominated. Each graph edge is one
// unit per phase: a series chain of its sides (any side breaks it), each
// side the parallel set of its parts (every part must change): its own
// statements, each resolve step, each detach. A detach is a shared group
// arc, one change for every edge its attachment grants. Costs are scaled so
// that a resolve step (0) still counts: the cheapest cut has the fewest
// resolve steps among equals, then is the one closest to the entry.

// Default (Options.Cost): price the edge from its fixes (graph.Edge.Fixes).
const Default int64 = -2

const scale = 1000

// Select chooses the paths of one finding. Escalation: the paths must take
// a CAN_ESCALATE whose source is not Dominated (DARB-PATH-002); otherwise
// the paths take none, or only from a Dominated source (DARB-PATH-001 and
// the escalations it dominates, DESIGN.md §8).
type Select struct {
	Escalation bool
	Dominated  func(graph.NodeID) bool
}

func (s *Select) dominated(n graph.NodeID) bool { return s.Dominated != nil && s.Dominated(n) }

type pstate struct {
	node graph.NodeID
	mode mode
	esc  bool
}

// next: whether e may follow s under the selection, and where it leads.
func (s *Select) next(st pstate, e *graph.Edge) (pstate, bool) {
	if !traversed(e) || !allowed(st.mode, e) {
		return pstate{}, false
	}
	esc := st.esc
	if e.Kind == graph.CanEscalate && !esc {
		if s.dominated(e.From) == s.Escalation {
			return pstate{}, false
		}
		esc = true
	}
	return pstate{e.To, target(e), esc}, true
}

func (s *Select) sink(st pstate, jewel graph.NodeID) bool {
	return st.node == jewel && (!s.Escalation || st.esc)
}

// Way is one side of an edge: every part must change for it to break.
type Way struct {
	Edge     graph.EdgeID // the edge it breaks (a derived edge's underlying edge)
	Fix      int          // its index in the edge's Fixes; -1: priced by Options.Cost
	Known    int64        // the side's own statements (HasKnown)
	HasKnown bool
	Detach   []graph.Detach
	Resolve  []graph.Resolution
}

func (w *Way) pending() bool { return len(w.Resolve) > 0 }

// ways: an edge's sides, cheapest first (a derived edge: its underlying
// edges'). Uncuttable: none.
func ways(g *graph.Graph, id graph.EdgeID, opts *Options) []Way {
	e := g.Edge(id)
	if e.Kind == graph.CanReadPlaintext && len(e.Under) > 0 {
		var out []Way
		for _, u := range e.Under {
			out = append(out, ways(g, u, opts)...)
		}
		return out
	}
	c := opts.Cost(id)
	switch {
	case c == Uncuttable:
		return nil
	case c != Default || len(e.Fixes) == 0:
		if c == Default {
			return nil
		}
		return []Way{{Edge: id, Fix: -1, Known: c, HasKnown: true}}
	}
	out := make([]Way, 0, len(e.Fixes))
	for i := range e.Fixes {
		fx := &e.Fixes[i]
		known := fx.Kind == graph.FixNarrow || fx.Kind == graph.FixRevoke
		out = append(out, Way{Edge: id, Fix: i, Known: fx.Cost, HasKnown: known, Detach: fx.Detach, Resolve: fx.Resolve})
	}
	return out
}

// exclude: what the alternative may not use (SCORING.md §4.3).
// exclude: what a cut may not use. For the alternative (SCORING.md §4.3):
// the chosen cut's edges and detaches, RUNS_AS and fact sides of 100 or
// more, and resolve steps when the chosen cut has one. commands, when set:
// only resolve steps with these commands (the tie rule, fewestCommands).
type exclude struct {
	alternative bool
	edges       map[graph.EdgeID]bool
	groups      map[string]bool
	pending     bool
	commands    map[string]bool
}

func (x *exclude) skips(g *graph.Graph, w *Way) bool {
	if x == nil {
		return false
	}
	if x.commands != nil && slices.ContainsFunc(w.Resolve, func(r graph.Resolution) bool { return !x.commands[r.Command] }) {
		return true
	}
	if !x.alternative {
		return false
	}
	e := g.Edge(w.Edge)
	if x.edges[w.Edge] || x.pending && w.pending() || e.Kind == graph.RunsAs && e.Sub == "" || w.HasKnown && w.Known >= 100 {
		return true
	}
	return slices.ContainsFunc(w.Detach, func(d graph.Detach) bool { return x.groups[d.Group] })
}

// Step is one part of one way: what to change, or (resolve) what to decide.
type Step struct {
	Edge    graph.EdgeID
	Fix     int
	Side    string
	Kind    string
	Policy  string
	Resolve string
	Cost    int64
}

// Result is the cut of one finding and its alternative.
type Result struct {
	Finite bool
	Cost   int64
	// Ways: the chosen side of each chokepoint edge; Steps: their parts;
	// Other: the other sides of those edges.
	Ways        []Way
	Steps       []Step
	Other       []Step
	Alternative []Way
	AltSteps    []Step
	// Uncuttable: underlying edges of a cut derived read that no change breaks.
	Uncuttable []graph.EdgeID
	Pending    bool
}

// CutFor solves the cut of one selection of paths between entry and jewel,
// and the cheapest complete cut sharing no edge with it (SCORING.md §4.3).
func CutFor(g *graph.Graph, entry, jewel graph.NodeID, sel *Select, opts *Options) Result {
	w := newCutNetwork(g, entry, jewel, sel, opts, nil)
	cut, ok := w.solve()
	if !ok {
		return Result{}
	}
	r := Result{Finite: true, Ways: w.chosen(cut)}
	r.Cost, r.Steps, r.Pending = price(g, r.Ways)
	if r.Pending {
		r.Ways = fewestCommands(g, entry, jewel, sel, opts, w, r.Cost, r.Ways)
		r.Cost, r.Steps, r.Pending = price(g, r.Ways)
	}
	ex := &exclude{alternative: true, edges: map[graph.EdgeID]bool{}, groups: map[string]bool{}, pending: r.Pending}
	for _, way := range r.Ways {
		ex.edges[way.Edge] = true
		for _, d := range way.Detach {
			ex.groups[d.Group] = true
		}
		r.Other = append(r.Other, others(g, &way, opts)...)
	}
	r.Uncuttable = uncuttable(g, w, r.Ways, opts)
	alt := newCutNetwork(g, entry, jewel, sel, opts, ex)
	if acut, ok := alt.solve(); ok {
		r.Alternative = alt.chosen(acut)
		_, r.AltSteps, _ = price(g, r.Alternative)
		if subsetOfResolves(r.AltSteps, r.Steps) {
			r.Alternative, r.AltSteps = nil, nil
		}
	}
	return r
}

// price: the steps of the chosen ways and what they cost together (a
// detach shared by several edges counts once; a resolve step costs 0).
func price(g *graph.Graph, ws []Way) (cost int64, steps []Step, pending bool) {
	groups := map[string]bool{}
	for i := range ws {
		way := &ws[i]
		side := ""
		if way.Fix >= 0 {
			side = g.Edge(way.Edge).Fixes[way.Fix].Side
		}
		if way.HasKnown {
			s := Step{Edge: way.Edge, Fix: way.Fix, Side: side, Cost: way.Known}
			if way.Fix >= 0 {
				fx := &g.Edge(way.Edge).Fixes[way.Fix]
				s.Kind, s.Policy = fx.Kind, fx.Policy
			}
			steps = append(steps, s)
			cost += way.Known
		}
		for _, d := range way.Detach {
			steps = append(steps, Step{Edge: way.Edge, Fix: way.Fix, Side: side, Kind: graph.FixRevoke, Policy: d.Policy, Cost: d.Cost})
			if !groups[d.Group] {
				groups[d.Group] = true
				cost += d.Cost
			}
		}
		for _, r := range way.Resolve {
			steps = append(steps, Step{Edge: way.Edge, Fix: way.Fix, Side: side, Kind: graph.FixResolve, Policy: r.Policy, Resolve: r.Command})
			pending = true
		}
	}
	return cost, steps, pending
}

// others: the other sides of a chosen way's edge.
func others(g *graph.Graph, way *Way, opts *Options) []Step {
	var out []Step
	for _, o := range ways(g, way.Edge, opts) {
		if o.Fix != way.Fix {
			_, s, _ := price(g, []Way{o})
			out = append(out, s...)
		}
	}
	return out
}

// uncuttable: the underlying edges with no side of every cut derived edge.
func uncuttable(g *graph.Graph, w *network, chosen []Way, opts *Options) []graph.EdgeID {
	var out []graph.EdgeID
	for _, u := range w.order {
		e := g.Edge(u.edge)
		if len(e.Under) == 0 || !slices.ContainsFunc(chosen, func(c Way) bool { return slices.Contains(e.Under, c.Edge) }) {
			continue
		}
		for _, x := range e.Under {
			if len(ways(g, x, opts)) == 0 && !slices.Contains(out, x) {
				out = append(out, x)
			}
		}
	}
	slices.Sort(out)
	return out
}

// subsetOfResolves: an alternative of resolve steps only, whose commands
// the chosen cut already names, is never offered (SCORING.md §4.3).
func subsetOfResolves(alt, chosen []Step) bool {
	if len(alt) == 0 {
		return false
	}
	for _, a := range alt {
		if a.Kind != graph.FixResolve || !slices.ContainsFunc(chosen, func(c Step) bool { return c.Kind == graph.FixResolve && c.Resolve == a.Resolve }) {
			return false
		}
	}
	return true
}

// maxCommands bounds the tie rule's search (2^n cuts): beyond it the cut
// with the fewest resolve steps stands.
const maxCommands = 8

// fewestCommands: among the cuts as cheap in known changes as the chosen
// one, the one with the fewest distinct resolving commands, then the fewest
// steps, then the closest to the entry (SCORING.md §4.3: the user runs
// commands, not steps). The network prices each resolve step, not each
// command, so the commands are searched: for k = 1, 2, ..., the cuts that
// may use only k of them; the first k with a cut of the same known cost
// wins, and among its cuts the fewest steps (the first set on a tie, in
// sorted order; each cut is the one closest to the entry).
func fewestCommands(g *graph.Graph, entry, jewel graph.NodeID, sel *Select, opts *Options, w *network, known int64, chosen []Way) []Way {
	cmds := commandsOf(w)
	if len(cmds) > maxCommands {
		return chosen
	}
	for k := 1; k <= len(cmds); k++ {
		var best []Way
		bestSteps := -1
		for _, set := range subsets(cmds, k) {
			ws, steps, ok := cutWithin(g, entry, jewel, sel, opts, set, known)
			if ok && (bestSteps < 0 || steps < bestSteps) {
				best, bestSteps = ws, steps
			}
		}
		if best != nil {
			return best
		}
	}
	return chosen
}

// commandsOf: the distinct resolving commands of a network, sorted.
func commandsOf(w *network) []string {
	var cmds []string
	for _, u := range w.order {
		for _, way := range u.ways {
			for _, r := range way.Resolve {
				if !slices.Contains(cmds, r.Command) {
					cmds = append(cmds, r.Command)
				}
			}
		}
	}
	slices.Sort(cmds)
	return cmds
}

// cutWithin: the cut that may resolve only with these commands, if it is as
// cheap in known changes as known, and its number of steps.
func cutWithin(g *graph.Graph, entry, jewel graph.NodeID, sel *Select, opts *Options, set []string, known int64) ([]Way, int, bool) {
	allowed := map[string]bool{}
	for _, c := range set {
		allowed[c] = true
	}
	net := newCutNetwork(g, entry, jewel, sel, opts, &exclude{commands: allowed})
	cut, ok := net.solve()
	if !ok {
		return nil, 0, false
	}
	ws := net.chosen(cut)
	cost, steps, _ := price(g, ws)
	return ws, len(steps), cost == known
}

// subsets: the k-element subsets of xs, in order.
func subsets(xs []string, k int) [][]string {
	if k == 0 {
		return [][]string{{}}
	}
	var out [][]string
	for i := range xs {
		for _, rest := range subsets(xs[i+1:], k-1) {
			out = append(out, append([]string{xs[i]}, rest...))
		}
	}
	return out
}
