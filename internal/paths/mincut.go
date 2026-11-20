package paths

// Weighted minimum cut by Dinic's max-flow (DESIGN.md §7.4, SCORING.md §4).
//
// Capacities are cut costs; Uncuttable edges have infinite capacity. The cut
// returned is the canonical one closest to the source: the source side is
// every node still reachable from the source in the final residual graph, so
// the result depends only on the graph, never on iteration order.

// Uncuttable is the capacity of an edge that no fix may remove.
const Uncuttable int64 = -1

// FlowEdge is a directed edge with a cut cost (>= 0) or Uncuttable.
type FlowEdge struct {
	From, To int
	Cost     int64
}

// Cut is a minimum cut.
type Cut struct {
	// Finite is false when every separating set contains an Uncuttable edge
	// ("no fix within constraints"); Cost and Edges are then unset.
	Finite bool
	Cost   int64
	Edges  []int // indices into the input edges, ascending
}

type arc struct {
	to, rev int // rev: index of the reverse arc in adj[to]
	cap     int64
}

type flow struct {
	adj   [][]arc
	level []int
	next  []int
}

// MinCut returns the minimum-cost set of edges whose removal leaves no path
// from s to t among n nodes (0..n-1). s == t has no finite cut.
func MinCut(n int, edges []FlowEdge, s, t int) Cut {
	if s == t {
		return Cut{}
	}
	// Infinity is one more than every finite cost together, so a flow that
	// reaches it proves no finite cut exists, and sums never overflow.
	var inf int64 = 1
	for _, e := range edges {
		if e.Cost != Uncuttable {
			inf += e.Cost
		}
	}
	f := newFlow(n, edges, inf)
	if f.maxFlow(s, t, inf) >= inf {
		return Cut{}
	}
	source := f.reachable(s)
	cut := Cut{Finite: true}
	for i, e := range edges {
		if source[e.From] && !source[e.To] {
			cut.Edges = append(cut.Edges, i)
			cut.Cost += e.Cost
		}
	}
	return cut
}

// newFlow builds the residual graph: each edge and its reverse arc. A
// self-loop never carries flow (the level graph only goes forward).
func newFlow(n int, edges []FlowEdge, inf int64) *flow {
	f := &flow{adj: make([][]arc, n), level: make([]int, n), next: make([]int, n)}
	for _, e := range edges {
		c := e.Cost
		if c == Uncuttable {
			c = inf
		}
		f.adj[e.From] = append(f.adj[e.From], arc{to: e.To, rev: len(f.adj[e.To]), cap: c})
		f.adj[e.To] = append(f.adj[e.To], arc{to: e.From, rev: len(f.adj[e.From]) - 1})
	}
	return f
}

// maxFlow runs Dinic's phases until t is unreachable or the flow reaches inf.
func (f *flow) maxFlow(s, t int, inf int64) int64 {
	var total int64
	for total < inf && f.bfs(s, t) {
		clear(f.next)
		for pushed := f.dfs(s, t, inf); pushed > 0; pushed = f.dfs(s, t, inf) {
			total += pushed
		}
	}
	return total
}

// bfs builds the level graph; false when t is unreachable.
func (f *flow) bfs(s, t int) bool {
	for i := range f.level {
		f.level[i] = -1
	}
	f.level[s] = 0
	queue := []int{s}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, a := range f.adj[u] {
			if a.cap > 0 && f.level[a.to] < 0 {
				f.level[a.to] = f.level[u] + 1
				queue = append(queue, a.to)
			}
		}
	}
	return f.level[t] >= 0
}

// dfs pushes one blocking-flow augmentation of at most limit.
func (f *flow) dfs(u, t int, limit int64) int64 {
	if u == t {
		return limit
	}
	for ; f.next[u] < len(f.adj[u]); f.next[u]++ {
		a := &f.adj[u][f.next[u]]
		if a.cap <= 0 || f.level[a.to] != f.level[u]+1 {
			continue
		}
		if pushed := f.dfs(a.to, t, min(limit, a.cap)); pushed > 0 {
			a.cap -= pushed
			f.adj[a.to][a.rev].cap += pushed
			return pushed
		}
	}
	return 0
}

// reachable marks the nodes reachable from s in the residual graph.
func (f *flow) reachable(s int) []bool {
	seen := make([]bool, len(f.adj))
	seen[s] = true
	stack := []int{s}
	for len(stack) > 0 {
		u := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, a := range f.adj[u] {
			if a.cap > 0 && !seen[a.to] {
				seen[a.to] = true
				stack = append(stack, a.to)
			}
		}
	}
	return seen
}
