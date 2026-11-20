package paths

import (
	"slices"

	"github.com/r3oof-900/clapa/internal/graph"
)

// network is the mode-expanded flow network of one entry (DESIGN.md §7.4).
// Each graph edge is one capacity-carrying arc (in -> out, its cut cost)
// shared by all of its mode copies, so cutting an edge cuts it everywhere: a
// copy's target mode depends only on the edge, so sharing the arc cannot
// join two copies into a path the modes forbid. It is built once per entry;
// each jewel only adds arcs from its states to the sink.
//
// A derived CAN_READ_PLAINTEXT costs its cheapest underlying edge; the cut
// names that edge, CAN_DECRYPT only on a tie (DESIGN.md §8.1, decision 3),
// and the other cuttable underlying edge, at whatever cost, is the
// alternative.
type network struct {
	g        *graph.Graph
	opts     *Options
	n        int
	source   int
	states   map[state]int
	edges    map[graph.EdgeID]int // graph edge -> its "in" node; "out" is in+1
	capacity map[int]graph.EdgeID // arc index of each capacity arc
	arcs     []FlowEdge
}

func newNetwork(g *graph.Graph, entry graph.NodeID, opts *Options) *network {
	w := &network{g: g, opts: opts, states: map[state]int{}, edges: map[graph.EdgeID]int{}, capacity: map[int]graph.EdgeID{}}
	w.source = w.state(state{entry, full})
	w.expand(state{entry, full})
	return w
}

// cut solves the minimum cut between the entry and one jewel.
func (w *network) cut(jewel graph.NodeID) (cut Cut, alternative []graph.EdgeID) {
	sink := w.n
	arcs := slices.Clone(w.arcs)
	for s, i := range w.states {
		if s.node == jewel {
			arcs = append(arcs, FlowEdge{From: i, To: sink, Cost: Uncuttable})
		}
	}
	flow := MinCut(w.n+1, arcs, w.source, sink)
	cut = Cut{Finite: flow.Finite, Cost: flow.Cost}
	for _, i := range flow.Edges {
		id, ok := w.capacity[i]
		if !ok {
			continue // only capacity arcs are finite
		}
		chosen, alt := underlying(w.g, id, w.opts)
		cut.Edges = append(cut.Edges, int(chosen))
		alternative = append(alternative, alt...)
	}
	return cut, alternative
}

func (w *network) state(s state) int {
	if i, ok := w.states[s]; ok {
		return i
	}
	w.states[s] = w.n
	w.n++
	return w.n - 1
}

// expand adds, breadth-first from the entry, every usable edge: an
// uncuttable arc from the state into the edge, its capacity arc, and an
// uncuttable arc out to the target state.
func (w *network) expand(start state) {
	seen := map[state]bool{start: true}
	queue := []state{start}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for _, id := range w.g.Out(s.node) {
			e := w.g.Edge(id)
			if !traversed(e) || !allowed(s.mode, e) {
				continue
			}
			in, ok := w.edges[id]
			if !ok {
				in = w.addEdge(id, e)
				if next := (state{e.To, target(e)}); !seen[next] {
					seen[next] = true
					queue = append(queue, next)
				}
			}
			w.arcs = append(w.arcs, FlowEdge{From: w.state(s), To: in, Cost: Uncuttable})
		}
	}
}

func (w *network) addEdge(id graph.EdgeID, e *graph.Edge) int {
	in := w.n
	w.n += 2
	w.edges[id] = in
	w.capacity[len(w.arcs)] = id
	to := w.state(state{e.To, target(e)})
	w.arcs = append(w.arcs,
		FlowEdge{From: in, To: in + 1, Cost: costOf(w.g, id, w.opts)},
		FlowEdge{From: in + 1, To: to, Cost: Uncuttable})
	return in
}

// costOf: a derived edge costs its cheapest underlying edge.
func costOf(g *graph.Graph, id graph.EdgeID, opts *Options) int64 {
	e := g.Edge(id)
	if e.Kind != graph.CanReadPlaintext || len(e.Under) == 0 {
		return opts.Cost(id)
	}
	best := Uncuttable
	for _, u := range e.Under {
		if c := opts.Cost(u); c != Uncuttable && (best == Uncuttable || c < best) {
			best = c
		}
	}
	return best
}

// underlying maps a cut derived edge to the underlying edge that is cut
// (cheapest; CAN_DECRYPT on a tie) and the other cuttable underlying edges.
func underlying(g *graph.Graph, id graph.EdgeID, opts *Options) (chosen graph.EdgeID, alternatives []graph.EdgeID) {
	e := g.Edge(id)
	if e.Kind != graph.CanReadPlaintext || len(e.Under) == 0 {
		return id, nil
	}
	best := costOf(g, id, opts)
	var cands []graph.EdgeID
	for _, u := range e.Under {
		if opts.Cost(u) == best {
			cands = append(cands, u)
		}
	}
	chosen = cands[0]
	for _, c := range cands {
		if g.Edge(c).Kind == graph.CanDecrypt {
			chosen = c
		}
	}
	for _, u := range e.Under {
		if u != chosen && opts.Cost(u) != Uncuttable {
			alternatives = append(alternatives, u)
		}
	}
	return chosen, alternatives
}
