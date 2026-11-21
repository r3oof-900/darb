package paths

import (
	"slices"

	"github.com/r3oof-900/clapa/internal/graph"
)

// How a node was reached decides which edges may follow (DESIGN.md §7.2):
// after RUNS_AS a pod holds its cloud identity, not its Kubernetes token;
// after RUNS_AS[k8s-token] it holds only the token (RBAC); after
// creating a pod (RBAC) it holds both.
type mode uint8

const (
	full mode = iota
	identity
	k8s
	modes
)

func target(e *graph.Edge) mode {
	switch {
	case e.Kind == graph.RunsAs && e.Sub == "k8s-token", e.Kind == graph.MapsTo:
		return k8s // Kubernetes API access as that subject
	case e.Kind == graph.RunsAs:
		return identity
	}
	return full
}

// allowed: with the cloud identity only (identity), neither RBAC nor
// minting a token is possible; with the account's own Kubernetes token
// (k8s), RBAC is, and minting when the account itself holds that right
// ("minted-self"); after an RBAC escalation (full), everything is.
func allowed(m mode, e *graph.Edge) bool {
	// A Kubernetes Secret read (CAN_READ_PLAINTEXT[k8s]) is RBAC too.
	rbac := e.Kind == graph.CanEscalate && e.Sub == "rbac" || e.Kind == graph.CanReadPlaintext && e.Sub == "k8s"
	mint := e.Kind == graph.Assumes && (e.Sub == "minted" || e.Sub == "minted-self")
	switch m {
	case identity:
		return !rbac && !mint
	case k8s:
		return rbac || e.Kind == graph.Assumes && e.Sub == "minted-self"
	case full, modes:
	}
	return true
}

// traversed: the read and decrypt edges are reached only through the
// derived CAN_READ_PLAINTEXT, which needs both.
func traversed(e *graph.Edge) bool { return e.Kind != graph.CanRead && e.Kind != graph.CanDecrypt }

type state struct {
	node graph.NodeID
	mode mode
}

// Options bound the search.
type Options struct {
	MaxDepth int // default 10
	MaxPaths int // per (entry, jewel); default 100
	// Cost is an edge's cut cost (>= 0) or Uncuttable.
	Cost func(graph.EdgeID) int64
}

// Path is a sequence of edges from an entry to a jewel.
type Path []graph.EdgeID

// Pair is what the search found between one entry and one jewel.
type Pair struct {
	Entry, Jewel graph.NodeID
	Paths        []Path // deterministic order; at most MaxPaths
	Truncated    bool   // more paths exist than MaxPaths, or deeper than MaxDepth
	Cut          Cut    // edge IDs of the graph (derived edges mapped to an underlying edge)
	Alternative  []graph.EdgeID
}

// Analyze finds, for every entry, the jewels it reaches, the paths (bounded)
// and the weighted minimum cut between them.
func Analyze(g *graph.Graph, entries, jewels []graph.NodeID, opts Options) []Pair {
	if opts.MaxDepth == 0 {
		opts.MaxDepth = 10
	}
	if opts.MaxPaths == 0 {
		opts.MaxPaths = 100
	}
	isJewel := map[graph.NodeID]bool{}
	for _, j := range jewels {
		isJewel[j] = true
	}
	var out []Pair
	for _, entry := range entries {
		reached := reach(g, entry)
		var found []graph.NodeID
		for j := range isJewel {
			if reached[j] && j != entry {
				found = append(found, j)
			}
		}
		if len(found) == 0 {
			continue
		}
		slices.Sort(found)
		// One walk and one flow network per entry, shared by its jewels.
		paths, truncated := enumerate(g, entry, found, &opts)
		net := newNetwork(g, entry, &opts)
		for _, j := range found {
			p := Pair{Entry: entry, Jewel: j, Paths: paths[j], Truncated: truncated[j]}
			p.Cut, p.Alternative = net.cut(j)
			out = append(out, p)
		}
	}
	return out
}

// Reachable returns the nodes reachable from entry (multi-mode BFS); exact
// and linear in the graph size.
func Reachable(g *graph.Graph, entry graph.NodeID) map[graph.NodeID]bool { return reach(g, entry) }

func reach(g *graph.Graph, entry graph.NodeID) map[graph.NodeID]bool {
	return reachFrom(g, state{entry, full})
}

func reachFrom(g *graph.Graph, start state) map[graph.NodeID]bool {
	seen := map[state]bool{start: true}
	nodes := map[graph.NodeID]bool{start.node: true}
	queue := []state{start}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for _, id := range g.Out(s.node) {
			e := g.Edge(id)
			if !traversed(e) || !allowed(s.mode, e) {
				continue
			}
			next := state{e.To, target(e)}
			if !seen[next] {
				seen[next] = true
				nodes[e.To] = true
				queue = append(queue, next)
			}
		}
	}
	return nodes
}

// enumerate lists simple paths depth-first, in edge order, from the entry
// to each jewel, up to MaxPaths per jewel and MaxDepth edges. A jewel is
// marked truncated when a further path exists past its cap (or the walk
// stopped once every cap was full, so more may exist), or when the depth cap
// stops a walk from which the jewel is still reachable.
func enumerate(g *graph.Graph, entry graph.NodeID, jewels []graph.NodeID, opts *Options) (paths map[graph.NodeID][]Path, truncated map[graph.NodeID]bool) {
	w := &walker{
		g: g, opts: opts, out: map[graph.NodeID][]Path{}, truncated: map[graph.NodeID]bool{},
		want: map[graph.NodeID]bool{}, onPath: map[graph.NodeID]bool{entry: true}, deep: map[state]map[graph.NodeID]bool{},
	}
	for _, j := range jewels {
		w.want[j] = true
	}
	w.walk(state{entry, full})
	if w.stopped {
		for _, j := range jewels {
			if len(w.out[j]) == opts.MaxPaths {
				w.truncated[j] = true
			}
		}
	}
	return w.out, w.truncated
}

type walker struct {
	g         *graph.Graph
	opts      *Options
	out       map[graph.NodeID][]Path
	truncated map[graph.NodeID]bool
	want      map[graph.NodeID]bool
	onPath    map[graph.NodeID]bool
	deep      map[state]map[graph.NodeID]bool // reach from a state, for the depth cap
	stack     Path
	filled    int
	stopped   bool
}

func (w *walker) walk(s state) {
	for _, id := range w.g.Out(s.node) {
		e := w.g.Edge(id)
		if !traversed(e) || !allowed(s.mode, e) || w.onPath[e.To] {
			continue
		}
		if w.filled == len(w.want) {
			w.stopped = true
			return
		}
		next := state{e.To, target(e)}
		if len(w.stack) >= w.opts.MaxDepth {
			w.depthCapped(next)
			continue
		}
		w.stack = append(w.stack, id)
		w.record(e.To)
		w.onPath[e.To] = true
		w.walk(next)
		delete(w.onPath, e.To)
		w.stack = w.stack[:len(w.stack)-1]
	}
}

func (w *walker) record(node graph.NodeID) {
	if !w.want[node] {
		return
	}
	if len(w.out[node]) >= w.opts.MaxPaths {
		w.truncated[node] = true
		return
	}
	w.out[node] = append(w.out[node], slices.Clone(w.stack))
	if len(w.out[node]) == w.opts.MaxPaths {
		w.filled++
	}
}

// depthCapped marks the jewels still reachable from a state the depth cap
// did not let the walk enter.
func (w *walker) depthCapped(s state) {
	reached, ok := w.deep[s]
	if !ok {
		reached = reachFrom(w.g, s)
		w.deep[s] = reached
	}
	for j := range reached {
		if w.want[j] {
			w.truncated[j] = true
		}
	}
}
