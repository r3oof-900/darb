package pathrules

import (
	"cmp"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/paths"
	"github.com/r3oof-900/darb/internal/rules"
	"github.com/r3oof-900/darb/internal/scoring"
)

// One finding per (rule, entry, jewel) (DESIGN.md §8): the paths of a pair
// are split by rule; an escalation is dominated, and merged into the
// direct finding's cut, when its source reaches the jewel without an
// escalation at an equal or stronger status.

type built struct {
	f            rules.Finding
	entry, jewel graph.NodeID
	sel          paths.Select
}

// analyze builds every path finding of the input, with also_fixes.
func analyze(in *rules.Input) []rules.Finding {
	perEntry := map[graph.NodeID]int{} // classified jewels only (SCORING.md §1.2)
	for i := range in.Pairs {
		if class, _ := in.Jewels[in.Pairs[i].Jewel].Classification(); class != model.ClassUnclassified {
			perEntry[in.Pairs[i].Entry]++
		}
	}
	var all []built
	for i := range in.Pairs {
		p := &in.Pairs[i]
		if len(p.Paths) == 0 {
			continue
		}
		for _, s := range split(in.Graph, p) {
			b := built{entry: p.Entry, jewel: p.Jewel, sel: s.sel}
			b.f = build(in, p, &s, perEntry[p.Entry])
			all = append(all, b)
		}
	}
	alsoFixes(in.Graph, all)
	out := make([]rules.Finding, len(all))
	for i := range all {
		out[i] = all[i].f
	}
	return out
}

// selection is the paths of one rule for one pair.
type selection struct {
	rule  string
	paths []paths.Path
	sel   paths.Select
}

// split sorts a pair's paths by rule. An escalation path is dominated when
// the source X of its first CAN_ESCALATE reaches the jewel without one at a
// status at least as strong as the rest of the path from X; X's
// escalations go to the direct finding's cut when all of them are
// dominated (otherwise to the escalation finding's, all of them).
func split(g *graph.Graph, p *paths.Pair) []selection {
	if g.Node(p.Entry).ID == access.AnonymousID() {
		return []selection{{rule: PublicJewel, paths: p.Paths}}
	}
	var direct, esc, hidden []paths.Path
	dominated := map[graph.NodeID]bool{}
	open := map[graph.NodeID]bool{}
	for _, path := range p.Paths {
		k := slices.IndexFunc(path, func(id graph.EdgeID) bool { return g.Edge(id).Kind == graph.CanEscalate })
		if k < 0 {
			direct = append(direct, path)
			continue
		}
		x := g.Edge(path[k]).From
		if isDominated(g, path, k, p.Jewel) {
			dominated[x] = true
			hidden = append(hidden, path)
		} else {
			open[x] = true
			esc = append(esc, path)
		}
	}
	for x := range open {
		delete(dominated, x)
	}
	if len(direct) == 0 && len(hidden) > 0 {
		// The direct paths were not enumerated (caps): report the
		// escalations rather than hide them.
		esc, dominated = append(esc, hidden...), map[graph.NodeID]bool{}
	}
	sel := paths.Select{Dominated: func(n graph.NodeID) bool { return dominated[n] }, Protected: p.Protected}
	var out []selection
	if len(direct) > 0 {
		out = append(out, selection{rule: WorkloadReadsJewel, paths: direct, sel: sel})
	}
	if len(esc) > 0 {
		sel.Escalation = true
		out = append(out, selection{rule: EscalationToJewel, paths: esc, sel: sel})
	}
	return out
}

func isDominated(g *graph.Graph, path paths.Path, k int, jewel graph.NodeID) bool {
	suffix := rules.StatusConfirmed
	for _, id := range path[k:] {
		suffix = rules.Weaker(suffix, edgeStatus(g, id))
	}
	atLeast := func(id graph.EdgeID) bool { return rules.Weaker(edgeStatus(g, id), suffix) == suffix }
	return paths.ReachesDirect(g, path, k, jewel, atLeast)
}

func pathStatus(g *graph.Graph, path paths.Path) string {
	s := rules.StatusConfirmed
	for _, id := range path {
		s = rules.Weaker(s, edgeStatus(g, id))
	}
	return s
}

// build turns one rule's paths of a pair into a finding: the severity is
// the highest score among them, the status the strongest, the primary path
// the best of the strongest status; a less certain path that scores higher
// is the worst_case_path.
func build(in *rules.Input, p *paths.Pair, s *selection, jewels int) rules.Finding {
	g := in.Graph
	jewel := in.Jewels[p.Jewel]
	class, _ := jewel.Classification()
	exposure := in.Entries[p.Entry].Exposure
	score := func(path paths.Path) scoring.Factors {
		return scoring.Path(g, path, exposure, scoring.Classification(class), jewels)
	}
	strongest, primary, pf, worst, wf := pick(g, s.paths, score)
	f := rules.Finding{
		Entry: g.Node(p.Entry).Identity, Jewel: g.Node(p.Jewel).Identity, JewelClassification: class,
		EntryID: g.Node(p.Entry).ID, JewelID: g.Node(p.Jewel).ID,
		PathEdges: primary, Paths: len(s.paths), Truncated: p.Truncated, Factors: wf, Confirmed: true,
		Location: rules.SourceOf(in.Inventory, g.Node(p.Entry).ID), Rule: s.rule,
		AlsoFixes: []rules.FindingRef{}, Uncuttable: []rules.UncuttableEdge{},
	}
	if f.Location.IsZero() {
		f.Location = *jewel.Source()
	}
	describePath(g, primary, &f)
	if wf.Score > pf.Score && pathStatus(g, worst) != strongest {
		for _, id := range worst {
			f.WorstCasePath = append(f.WorstCasePath, graph.Label(g.Edge(id))+" "+g.Node(g.Edge(id).To).Identity)
		}
	}
	opts := in.Cuts
	if opts == nil {
		opts = &paths.Options{Cost: func(graph.EdgeID) int64 { return paths.Default }}
	}
	res := paths.CutFor(g, p.Entry, p.Jewel, &s.sel, opts)
	cut(g, res, &f)
	f.Hops = hops(g, primary, res.Ways)
	f.Branches = branches(g, primary, p.Jewel, res.Ways)
	if len(f.WorstCasePath) > 0 {
		f.WorstCaseHops = hops(g, worst, res.Ways)
	}
	return f
}

// hops: a path as its edges, each with both ends and whether the cut breaks
// it: "cut" (a change), "resolve" (only resolve steps), "" (not cut).
func hops(g *graph.Graph, path paths.Path, ways []paths.Way) []rules.Hop {
	out := make([]rules.Hop, 0, len(path))
	for _, id := range path {
		h := hop(g, id, ways)
		// A derived read is drawn as what it stands for: the read of the
		// data, the decrypt of its key, and the key protecting the data; the
		// marks sit on the edge the fix changes.
		e := g.Edge(id)
		for _, u := range e.Under {
			h.Parts = append(h.Parts, hop(g, u, ways))
			if ue := g.Edge(u); ue.Kind == graph.CanDecrypt && ue.For != graph.NoNode {
				h.Parts = append(h.Parts, rules.Hop{
					Kind: string(graph.Protects), From: g.Node(ue.To).Identity, To: g.Node(ue.For).Identity,
					FromKind: string(g.Node(ue.To).Kind), ToKind: string(g.Node(ue.For).Kind),
				})
			}
		}
		out = append(out, h)
	}
	return out
}

// branches: the cut edges that are not on the drawn path (an escalation of
// a dominated path, merged into this cut, DESIGN.md §8), each with the edge
// from its target to the jewel when there is one, so every fix step is
// drawn.
func branches(g *graph.Graph, path paths.Path, jewel graph.NodeID, ways []paths.Way) [][]rules.Hop {
	drawn := map[graph.EdgeID]bool{}
	for _, id := range path {
		drawn[id] = true
		for _, u := range g.Edge(id).Under {
			drawn[u] = true
		}
	}
	var out [][]rules.Hop
	for _, w := range ways {
		if drawn[w.Edge] {
			continue
		}
		drawn[w.Edge] = true
		b := []rules.Hop{hop(g, w.Edge, ways)}
		for _, next := range g.Out(g.Edge(w.Edge).To) {
			if g.Edge(next).To == jewel {
				b = append(b, hop(g, next, ways))
				break
			}
		}
		out = append(out, b)
	}
	return out
}

// hop: one edge, its ends, and how the cut treats it ("cut" when a chosen
// way of it, or of an edge it stands for, changes something, "resolve"
// when they only resolve).
func hop(g *graph.Graph, id graph.EdgeID, ways []paths.Way) rules.Hop {
	e := g.Edge(id)
	label := graph.Label(e)
	if e.Kind == graph.CanEscalate && e.Sub != "" {
		label += "[" + e.Sub + "]"
	}
	h := rules.Hop{
		Kind: label, From: g.Node(e.From).Identity, To: g.Node(e.To).Identity,
		FromKind: string(g.Node(e.From).Kind), ToKind: string(g.Node(e.To).Kind),
	}
	for _, w := range ways {
		if w.Edge != id && !slices.Contains(e.Under, w.Edge) {
			continue
		}
		switch {
		case w.HasKnown || len(w.Detach) > 0:
			h.Cut = rules.HopCut
		case h.Cut == "":
			h.Cut = rules.HopResolve
		}
	}
	return h
}

// pick: the strongest status among the paths, the best path of that status
// (primary) and the best path of all (worst case); ties: fewer edges.
func pick(g *graph.Graph, ps []paths.Path, score func(paths.Path) scoring.Factors) (
	strongest string, primary paths.Path, pf scoring.Factors, worst paths.Path, wf scoring.Factors,
) {
	better := func(a, b paths.Path, fa, fb scoring.Factors) bool {
		return fa.Score > fb.Score || fa.Score == fb.Score && len(a) < len(b)
	}
	strongest = rules.StatusUnconfirmed
	for _, path := range ps {
		if st := pathStatus(g, path); rules.Weaker(st, strongest) == strongest {
			strongest = st
		}
	}
	for _, path := range ps {
		f := score(path)
		if worst == nil || better(path, worst, f, wf) {
			worst, wf = path, f
		}
		if pathStatus(g, path) == strongest && (primary == nil || better(path, primary, f, pf)) {
			primary, pf = path, f
		}
	}
	return strongest, primary, pf, worst, wf
}

// cut fills the chokepoints, their fixes and other sides, the alternative,
// what no change breaks and the remediation status.
func cut(g *graph.Graph, r paths.Result, f *rules.Finding) { //nolint:gocritic // hugeParam: a result built once per finding
	if !r.Finite {
		f.NoFix = true
		return
	}
	f.CutCost = r.Cost
	for _, w := range r.Ways {
		f.ChokepointEdge = append(f.ChokepointEdge, w.Edge)
		f.ChokepointFix = append(f.ChokepointFix, w.Fix)
		if d := g.Describe(w.Edge); !slices.Contains(f.Chokepoints, d) {
			f.Chokepoints = append(f.Chokepoints, d)
		}
	}
	for _, w := range r.Alternative {
		if d := g.Describe(w.Edge); !slices.Contains(f.Alternative, d) {
			f.Alternative = append(f.Alternative, d)
		}
	}
	slices.Sort(f.Chokepoints)
	slices.Sort(f.Alternative)
	f.Fix, f.OtherSideFix, f.AlternativeDetail = steps(g, r.Steps), steps(g, r.Other), steps(g, r.AltSteps)
	for _, u := range r.Uncuttable {
		f.Uncuttable = append(f.Uncuttable, rules.UncuttableEdge{Edge: g.Describe(u), Reason: "no single change breaks it"})
	}
	f.RemediationStatus = rules.RemediationComplete
	if r.Pending {
		f.RemediationStatus = rules.RemediationPending
	}
	f.SharedFix = sharedFixes(g, r.Ways)
}

func steps(g *graph.Graph, ss []paths.Step) []rules.FixStep {
	out := make([]rules.FixStep, 0, len(ss))
	for _, s := range ss {
		out = append(out, rules.FixStep{Edge: g.Describe(s.Edge), Side: s.Side, Kind: s.Kind, Policy: s.Policy, Cost: s.Cost, Resolve: s.Resolve})
	}
	slices.SortStableFunc(out, func(a, b rules.FixStep) int { return strings.Compare(a.Edge, b.Edge) })
	return out
}

// sharedFixes: every resource or policy one change to which breaks two or
// more chokepoint edges: a resource (or trust) policy, an identity policy
// (an inline policy is named by its principal, a managed one by its ARN).
func sharedFixes(g *graph.Graph, ws []paths.Way) []string {
	edges := map[string]map[graph.EdgeID]bool{}
	add := func(key string, id graph.EdgeID) {
		if edges[key] == nil {
			edges[key] = map[graph.EdgeID]bool{}
		}
		edges[key][id] = true
	}
	for _, w := range ws {
		if w.Fix < 0 {
			continue
		}
		for _, key := range shareKeys(g, &w) {
			add(key, w.Edge)
		}
	}
	var out []string
	for k, ids := range edges {
		if len(ids) > 1 {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// shareKeys: what one change to which breaks this way: its resource (or
// trust) policy, or the identity policies of its own statements (an inline
// policy named by its principal, a managed one by its ARN).
func shareKeys(g *graph.Graph, w *paths.Way) []string {
	e := g.Edge(w.Edge)
	fx := &e.Fixes[w.Fix]
	switch {
	case fx.Resource != "" && (fx.Side == graph.SideResource || fx.Side == graph.SideTrust):
		return []string{fx.Resource}
	case fx.Side != graph.SideIdentity || !w.HasKnown:
		return nil
	}
	var out []string
	for _, gr := range fx.Grants {
		key := g.Node(e.From).Identity
		if strings.HasPrefix(gr.Policy, "arn:") && strings.Contains(gr.Policy, ":policy/") {
			key = gr.Policy
		}
		out = append(out, key)
	}
	return out
}

// alsoFixes: for each finding, the path findings of other rules (any entry
// and jewel) whose every path its cut breaks.
func alsoFixes(g *graph.Graph, all []built) {
	for i := range all {
		if !all[i].f.CutFinite() {
			continue
		}
		broken := map[graph.EdgeID]bool{}
		for _, id := range all[i].f.ChokepointEdge {
			broken[id] = true
		}
		for j := range all {
			o := &all[j]
			if o.f.Rule == all[i].f.Rule || !paths.Breaks(g, o.entry, o.jewel, &o.sel, broken) {
				continue
			}
			all[i].f.AlsoFixes = append(all[i].f.AlsoFixes, rules.FindingRef{Rule: o.f.Rule, Entry: o.f.Entry, Jewel: o.f.Jewel})
		}
		slices.SortFunc(all[i].f.AlsoFixes, func(a, b rules.FindingRef) int {
			return cmp.Or(strings.Compare(a.Rule, b.Rule), strings.Compare(a.Entry, b.Entry), strings.Compare(a.Jewel, b.Jewel))
		})
	}
}

// Dominated reports whether an escalation path is dominated (DESIGN.md §8):
// the source of its first CAN_ESCALATE reaches the jewel without one at a
// status at least as strong as the rest of the path.
func Dominated(g *graph.Graph, path paths.Path, jewel graph.NodeID) bool {
	k := slices.IndexFunc(path, func(id graph.EdgeID) bool { return g.Edge(id).Kind == graph.CanEscalate })
	return k >= 0 && isDominated(g, path, k, jewel)
}
