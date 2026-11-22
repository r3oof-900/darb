package graph

import (
	"cmp"
	"slices"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/model"
)

// NodeID indexes a node in a Graph.
type NodeID int32

// EdgeID indexes an edge in a Graph.
type EdgeID int32

// NoNode marks an absent node reference (e.g. an unqualified edge).
const NoNode NodeID = -1

// Kind is an edge kind (DESIGN.md §7.2).
type Kind string

// Edge kinds.
const (
	RunsAs           Kind = "RUNS_AS"
	Assumes          Kind = "ASSUMES"
	NodeRole         Kind = "NODE_ROLE"
	CanEscalate      Kind = "CAN_ESCALATE"
	CanRead          Kind = "CAN_READ"
	CanDecrypt       Kind = "CAN_DECRYPT"
	CanReadPlaintext Kind = "CAN_READ_PLAINTEXT"
	MapsTo           Kind = "MAPS_TO"
	ExposedTo        Kind = "EXPOSED_TO"
	Protects         Kind = "PROTECTS"
)

// Confidence of an edge or path.
type Confidence uint8

// Confidences, lowest first.
const (
	Low Confidence = iota
	Medium
	High
)

func (c Confidence) String() string {
	switch c {
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
	}
	return "low"
}

// Node is a graph node: a canonical model node.
type Node struct {
	ID       model.ID
	Kind     model.NodeKind
	Identity string
}

// Precondition gates an edge on a fact about the environment (NODE_ROLE:
// IMDS reachable). State is True when known satisfied, Unknown otherwise.
type Precondition struct {
	Reason string
	State  model.Tri
}

// Fix is one way to remove an edge: a change on one side (the principal's
// identity policy, the resource's policy, the role's trust, the workload,
// RBAC, the mapping, the node group) and what it costs (SCORING.md §4).
type Fix struct {
	Side string // identity, resource, trust, workload, rbac, mapping, node
	// Kind: FixNarrow (make a broad grant specific) or FixRevoke (remove an
	// explicit grant), SCORING.md §4.1.
	Kind   string
	Policy string // what to change: a policy ID or ARN, or a resource
	// Resource: for a resource or trust side, the ARN of the resource whose
	// policy changes (two cut edges on one resource policy can share a fix).
	Resource string
	Cost     int64
	// Grants: the statements that grant the edge on this side, the ones a
	// remediation narrows or revokes (empty for fact sides).
	Grants []Grant
	// Detach: AWS managed policies (in the snapshot) whose grants on this
	// side are fixed by detaching them; Resolve: unknown grants on this side,
	// fixed by deciding them (SCORING.md §4.1). Every part of a side must
	// change for the side to break; Kind is "" when the side has no
	// statement of its own to narrow or revoke.
	Detach  []Detach
	Resolve []Resolution
}

// Detach is one AWS managed policy attachment to remove: one change for
// every edge it grants (Group), priced at the dearest identity revoke among
// them (Cost).
type Detach struct {
	Policy string // the managed policy's ARN
	Group  string // the attachment: principal and policy
	Cost   int64
}

// Resolution is one unknown grant and the command that decides it.
type Resolution struct {
	Policy  string
	Command string
}

// Total is what breaking the edge on this side costs alone: its own
// statements, each detach and each resolve (0).
func (f *Fix) Total() int64 {
	c := int64(0)
	if f.Kind != "" {
		c = f.Cost
	}
	for _, d := range f.Detach {
		c += d.Cost
	}
	return c
}

// Pending reports whether the side rests on an unknown to resolve first.
func (f *Fix) Pending() bool { return len(f.Resolve) > 0 }

// Grant names one granting statement: its policy document's ID and index.
type Grant struct {
	Policy    string
	Statement int
}

// Fix kinds. FixResolve is not a change: an unknown to decide (cost 0, no
// patch).
const (
	FixNarrow  = "narrow"
	FixRevoke  = "revoke"
	FixResolve = "resolve"
)

// Fix sides.
const (
	SideIdentity = "identity"
	SideResource = "resource"
	SideTrust    = "trust"
	SideWorkload = "workload"
	SideRBAC     = "rbac"
	SideMapping  = "mapping"
	SideNode     = "node"
	SideExposure = "exposure"
)

// Edge is a typed, directed edge with its evaluator decision.
type Edge struct {
	From, To NodeID
	Kind     Kind
	Sub      string // k8s-token, rbac, irsa, pod-identity, sts, iam, public
	For      NodeID // CAN_DECRYPT: the protected resource; NoNode otherwise
	Verdict  eval.Verdict
	// Confidence is High for a decided edge; Low when it rests on UNKNOWN.
	Confidence   Confidence
	Precondition *Precondition
	// Under holds the edges a derived edge (CAN_READ_PLAINTEXT) stands for.
	Under    []EdgeID
	Evidence []string // policy statements and facts that justify the edge
	// Fixes are the changes that remove the edge, cheapest first. None: no
	// change breaks it on its own (it is uncuttable).
	Fixes    []Fix
	Defaults []string // documented defaults the edge relies on (model.DocumentedDefaults keys)
	// Unresolved: for an UNKNOWN edge, what the evaluator could not decide
	// (a remediation says what is missing instead of patching).
	Unresolved []Unknown
	// DenyOnly: an UNKNOWN edge whose allows all hold; only unknown Denies
	// may block it (eval.Decision.DenyOnly, DESIGN.md 6.2).
	DenyOnly bool
}

// Label is the edge's kind as reports print it: RUNS_AS[k8s-token] for the
// pod's own Kubernetes token (two RUNS_AS edges join a pod and its service
// account), otherwise the kind.
func Label(e *Edge) string {
	if e.Kind == RunsAs && e.Sub != "" || e.Kind == CanReadPlaintext && (e.Sub == SubMount || e.Sub == SubPodCreate) {
		return string(e.Kind) + "[" + e.Sub + "]"
	}
	return string(e.Kind)
}

// Unknown is one undecided element of a policy decision.
type Unknown struct {
	Policy, Element, Key, Reason string
}

// Graph is an immutable access graph in compressed-sparse-row form: the
// edges of node n are edges[start[n]:start[n+1]], sorted by (kind, to, sub, for).
type Graph struct {
	nodes []Node
	index map[model.ID]NodeID
	edges []Edge
	start []int32
}

// Builder accumulates nodes and edges.
type Builder struct {
	nodes []Node
	index map[model.ID]NodeID
	edges []Edge
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder { return &Builder{index: map[model.ID]NodeID{}} }

// Node returns the node for id, adding it when new.
func (b *Builder) Node(id model.ID, kind model.NodeKind, identity string) NodeID {
	if n, ok := b.index[id]; ok {
		return n
	}
	n := NodeID(len(b.nodes)) //nolint:gosec // G115: inputs are bounded far below 2^31 nodes (safeio limits)
	b.nodes = append(b.nodes, Node{ID: id, Kind: kind, Identity: identity})
	b.index[id] = n
	return n
}

// NodeOf returns a node added so far.
func (b *Builder) NodeOf(n NodeID) Node { return b.nodes[n] }

// Lookup returns the node for id.
func (b *Builder) Lookup(id model.ID) (NodeID, bool) {
	n, ok := b.index[id]
	return n, ok
}

// Edge adds an edge and returns its index in the builder (not the final
// graph: Build renumbers; Under refers to builder indices and is remapped).
func (b *Builder) Edge(e *Edge) EdgeID {
	b.edges = append(b.edges, *e)
	return EdgeID(len(b.edges) - 1) //nolint:gosec // G115: bounded as above
}

// EachFrom calls f on every edge added so far from node n (before Build).
func (b *Builder) EachFrom(n NodeID, f func(*Edge)) {
	for i := range b.edges {
		if b.edges[i].From == n {
			f(&b.edges[i])
		}
	}
}

// priceDetaches: one detach is one change for every edge its attachment
// grants, priced at the dearest identity revoke among them (SCORING.md
// §4.1: 3, or 4 when one is a CAN_ESCALATE).
func priceDetaches(edges []Edge) {
	price := map[string]int64{}
	for i := range edges {
		for j := range edges[i].Fixes {
			for _, d := range edges[i].Fixes[j].Detach {
				price[d.Group] = max(price[d.Group], d.Cost)
			}
		}
	}
	for i := range edges {
		for j := range edges[i].Fixes {
			fx := &edges[i].Fixes[j]
			fx.Detach = slices.Clone(fx.Detach)
			for k := range fx.Detach {
				fx.Detach[k].Cost = price[fx.Detach[k].Group]
			}
		}
	}
}

// Build sorts nodes by canonical ID and edges by (from, kind, to, sub, for),
// so iteration order depends only on the content.
func (b *Builder) Build() *Graph {
	order := make([]NodeID, len(b.nodes))
	for i := range order {
		order[i] = NodeID(i)
	}
	slices.SortFunc(order, func(x, y NodeID) int { return cmp.Compare(b.nodes[x].ID, b.nodes[y].ID) })
	renum := make([]NodeID, len(b.nodes))
	g := &Graph{index: map[model.ID]NodeID{}}
	for newID, old := range order {
		renum[old] = NodeID(newID)
		g.nodes = append(g.nodes, b.nodes[old])
		g.index[b.nodes[old].ID] = NodeID(newID)
	}
	priceDetaches(b.edges)
	edgeOrder := make([]int, len(b.edges))
	edges := make([]Edge, len(b.edges))
	for i := range b.edges {
		e := b.edges[i]
		edgeOrder[i] = i
		e.From, e.To = renum[e.From], renum[e.To]
		if e.For != NoNode {
			e.For = renum[e.For]
		}
		edges[i] = e
	}
	slices.SortStableFunc(edgeOrder, func(x, y int) int { return compareEdges(&edges[x], &edges[y]) })
	newEdge := make([]EdgeID, len(edges))
	for newID, old := range edgeOrder {
		newEdge[old] = EdgeID(newID)
	}
	g.edges = make([]Edge, len(edges))
	for newID, old := range edgeOrder {
		e := edges[old]
		under := make([]EdgeID, len(e.Under))
		for i, u := range e.Under {
			under[i] = newEdge[u]
		}
		e.Under = under
		g.edges[newID] = e
	}
	g.start = make([]int32, len(g.nodes)+1)
	for i := range g.edges {
		g.start[g.edges[i].From+1]++
	}
	for i := 1; i < len(g.start); i++ {
		g.start[i] += g.start[i-1]
	}
	return g
}

func compareEdges(a, b *Edge) int {
	return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.To, b.To),
		cmp.Compare(a.Sub, b.Sub), cmp.Compare(a.For, b.For))
}

// NumNodes returns the number of nodes.
func (g *Graph) NumNodes() int { return len(g.nodes) }

// NumEdges returns the number of edges.
func (g *Graph) NumEdges() int { return len(g.edges) }

// Node returns node n.
func (g *Graph) Node(n NodeID) *Node { return &g.nodes[n] }

// Lookup returns the node for a canonical ID.
func (g *Graph) Lookup(id model.ID) (NodeID, bool) {
	n, ok := g.index[id]
	return n, ok
}

// Edge returns edge e.
func (g *Graph) Edge(e EdgeID) *Edge { return &g.edges[e] }

// Out returns the IDs of the edges leaving n, in sorted order.
func (g *Graph) Out(n NodeID) []EdgeID {
	out := make([]EdgeID, 0, g.start[n+1]-g.start[n])
	for e := g.start[n]; e < g.start[n+1]; e++ {
		out = append(out, EdgeID(e))
	}
	return out
}

// Describe renders an edge as "KIND[sub][for J] from -> to" (the chokepoint
// and expected.json notation): an escalation names its kind, so two
// escalations between the same nodes stay distinct (SCORING.md §4.3).
func (g *Graph) Describe(e EdgeID) string {
	ed := &g.edges[e]
	kind := Label(ed)
	if ed.Kind == CanEscalate && ed.Sub != "" {
		kind += "[" + ed.Sub + "]"
	}
	if ed.For != NoNode {
		kind += "[for " + g.nodes[ed.For].Identity + "]"
	}
	return kind + " " + g.nodes[ed.From].Identity + " -> " + g.nodes[ed.To].Identity
}

// Without returns a copy of g without the given edges, nor any derived edge
// that stands for one of them: what the graph is once a cut is made. Nodes
// keep their IDs; edges are renumbered.
func (g *Graph) Without(remove map[EdgeID]bool) *Graph {
	b := NewBuilder()
	for i := range g.nodes {
		b.Node(g.nodes[i].ID, g.nodes[i].Kind, g.nodes[i].Identity)
	}
	ids := map[EdgeID]EdgeID{}
	for _, derived := range []bool{false, true} {
		for i := range g.edges {
			e := g.edges[i]
			if remove[EdgeID(i)] || (len(e.Under) > 0) != derived {
				continue
			}
			under := make([]EdgeID, 0, len(e.Under))
			for _, u := range e.Under {
				if n, ok := ids[u]; ok {
					under = append(under, n)
				}
			}
			if len(under) != len(e.Under) {
				continue // an edge it stands for is gone
			}
			e.Under = under
			ids[EdgeID(i)] = b.Edge(&e)
		}
	}
	return b.Build()
}
