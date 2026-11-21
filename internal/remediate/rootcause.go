package remediate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/rules"
)

// Two strategies (decided in the Phase 5 review). A mitigation blocks the
// path only (a Deny, Block Public Access): verifiable at once, but the broad
// grant remains, and CLAPA-POST-008 keeps reporting it. A root-cause fix
// narrows the broad Allow itself to exactly what the declared intended
// access uses through it; without intended access that use is not known, so
// it is a suggestion listing what the wildcard matches in the input,
// unverified and never written.
const (
	StrategyRootCause  = "root-cause"
	StrategyMitigation = "mitigation"
)

// ForFinding plans the remediation of one finding: one plan per strategy,
// from the side the cut chose for each chokepoint edge. A resolve step is
// no change: it is listed as pending (an UNKNOWN finding also says what is
// missing), and with no known step there is no edit at all. A finding with
// no finite cut gets one plan saying so. A cut whose changes only remove
// explicit grants, detach policies or change settings is one root-cause
// plan; a cut that narrows broad grants has a mitigation plan (Deny) and a
// root-cause plan.
func ForFinding(in *Input, f *rules.Finding) []*Plan {
	p := &Plan{Fingerprint: f.Fingerprint}
	if !f.Confirmed {
		p.Missing = Missing(in.Graph, f.PathEdges)
	}
	if f.NoFix {
		p.NoFix = true
		return []*Plan{p}
	}
	pl := &planner{in: in, p: p, root: &Plan{Fingerprint: f.Fingerprint, Strategy: StrategyRootCause}, detached: map[string]bool{}}
	for i, id := range f.ChokepointEdge {
		fx := chosenFix(in.Graph.Edge(id), f.ChokepointFix, i)
		if fx == nil {
			p.NoFix = true
			return []*Plan{p}
		}
		pl.edge(id, fx)
	}
	root := pl.root
	root.Pending, root.Missing = p.Pending, p.Missing
	if len(p.Changes) == 0 {
		return []*Plan{p} // resolve steps only: nothing to apply before they are decided
	}
	if !pl.mitigates {
		return []*Plan{root}
	}
	p.Strategy = StrategyMitigation
	if len(pl.suggestions) > 0 {
		root.Changes = nil
		root.Suggestion = strings.Join(pl.suggestions, "; ")
	}
	return []*Plan{root, p}
}

// planner builds the mitigation (p) and root-cause plans of one finding.
type planner struct {
	in          *Input
	p, root     *Plan
	mitigates   bool
	suggestions []string
	detached    map[string]bool
}

// edge adds the chosen side of one chokepoint edge: its resolve steps as
// pending, each detach once, its own statements as a change.
func (pl *planner) edge(id graph.EdgeID, fx *graph.Fix) {
	p, root := pl.p, pl.root
	for _, r := range fx.Resolve {
		if s := r.Policy + ": " + r.Command; !slices.Contains(p.Pending, s) {
			p.Pending = append(p.Pending, s)
		}
	}
	for _, d := range fx.Detach {
		if !pl.detached[d.Group] {
			pl.detached[d.Group] = true
			c := detachChange(pl.in, id, &d)
			p.Changes, root.Changes = append(p.Changes, c), append(root.Changes, c)
		}
	}
	if fx.Kind != graph.FixNarrow && fx.Kind != graph.FixRevoke {
		return
	}
	known := *fx
	known.Detach, known.Resolve = nil, nil
	c := ForEdge(pl.in, id, &known)
	p.Changes = append(p.Changes, c)
	if !mitigation(&c) {
		root.Changes = append(root.Changes, c)
		return
	}
	pl.mitigates = true
	rc, suggestion := RootCause(pl.in, id, &known)
	if suggestion != "" {
		pl.suggestions = append(pl.suggestions, suggestion)
	}
	root.Changes = append(root.Changes, rc)
}

// chosenFix: the side the cut chose for chokepoint i (its cheapest when not
// recorded).
func chosenFix(e *graph.Edge, chosen []int, i int) *graph.Fix {
	k := 0
	if i < len(chosen) && chosen[i] >= 0 {
		k = chosen[i]
	}
	if k >= len(e.Fixes) {
		return nil
	}
	return &e.Fixes[k]
}

// detachChange: an AWS managed policy is detached, never edited; what
// replaces it is left to the owner (an unverified TODO in the change's
// reason), since what the principal needs is not in the input.
func detachChange(in *Input, id graph.EdgeID, d *graph.Detach) Change {
	g := in.Graph
	c := Change{Edge: g.Describe(id), Side: graph.SideIdentity, Kind: graph.FixRevoke, Cost: d.Cost}
	who := g.Node(g.Edge(id).From)
	for _, pr := range in.Inventory.Principals {
		if pr.ID() == who.ID {
			c.Edits = []Edit{{Op: OpDetachPolicy, Policy: d.Policy, Principal: pr}}
		}
	}
	if c.Edits == nil {
		c.TODO = fmt.Sprintf("%s is not a principal of the input: detach %s from it by hand", who.Identity, d.Policy)
		return c
	}
	c.Why = fmt.Sprintf("detach %s from %s (AWS owns its document, which cannot be narrowed); "+
		"TODO, not verified: replace it with a customer managed policy granting only what %s needs", d.Policy, who.Identity, who.Identity)
	return c
}

// mitigation: the change blocks the path without changing the grant.
func mitigation(c *Change) bool {
	return slices.ContainsFunc(c.Edits, func(e Edit) bool {
		return e.Op == OpAddStatement && e.Statement.Effect == model.EffectDeny || e.Op == OpRestrictPublic
	})
}

// RootCause narrows the broad grants of one edge's side to what the
// declared intended access uses through them; when none does, it returns a
// suggestion instead (with the candidates the wildcard matches).
func RootCause(in *Input, id graph.EdgeID, fx *graph.Fix) (c Change, suggestion string) {
	g := in.Graph
	c = Change{Edge: g.Describe(id), Side: fx.Side, Kind: graph.FixNarrow, Cost: fx.Cost}
	element := "Resource"
	if fx.Side != graph.SideIdentity {
		element = "Principal"
	}
	var why, suggest []string
	for _, gr := range fx.Grants {
		doc := Document(in.Inventory, gr.Policy)
		s := statementAt(doc, gr.Statement)
		if s == nil {
			continue
		}
		label := gr.Policy + " " + s.Label()
		need := needed(in, gr, fx.Side)
		if len(need) == 0 {
			suggest = append(suggest, fmt.Sprintf("narrow the %s of %s from %s to what it needs; no declared intended access uses it, and the wildcard matches, in the input: %s",
				element, label, current(s, element), strings.Join(candidates(in, g.Edge(id), fx.Side), ", ")))
			continue
		}
		c.Edits = append(c.Edits, Edit{Op: OpSetValues, Policy: gr.Policy, Index: gr.Statement, Element: element, Values: need})
		why = append(why, fmt.Sprintf("narrow the %s of %s to %s", element, label, strings.Join(need, ", ")))
	}
	c.Why = strings.Join(why, "; ")
	return c, strings.Join(suggest, "; ")
}

func statementAt(doc *model.PolicyDocument, index int) *model.Statement {
	if doc == nil {
		return nil
	}
	for _, s := range doc.Statements() {
		if s.Index() == index {
			return s
		}
	}
	return nil
}

func current(s *model.Statement, element string) string {
	if element == "Resource" {
		rs, neg := s.Resources()
		if neg {
			return "NotResource " + strings.Join(rs, ", ")
		}
		return strings.Join(rs, ", ")
	}
	spec, _ := s.Principal()
	if spec == nil || spec.Wildcard() {
		return "*"
	}
	var vals []string
	for _, r := range spec.Refs() {
		vals = append(vals, r.Value)
	}
	return strings.Join(vals, ", ")
}

// needed: the values a statement must keep for the intended access that
// uses it: on the identity side the targets (a bucket's objects, a key, a
// role), on a resource or trust side the principals.
func needed(in *Input, gr graph.Grant, side string) []string {
	var out []string
	for id := range in.Intended {
		e := in.Graph.Edge(id)
		if !slices.ContainsFunc(e.Fixes, func(f graph.Fix) bool { return f.Side == side && slices.Contains(f.Grants, gr) }) {
			continue
		}
		var v string
		switch {
		case side != graph.SideIdentity:
			v = in.Graph.Node(e.From).Identity
		case e.Kind == graph.CanRead:
			v = in.Graph.Node(e.To).Identity + "/*"
		case e.Kind == graph.CanDecrypt, e.Kind == graph.Assumes:
			v = in.Graph.Node(e.To).Identity
		}
		if v != "" && v != "anonymous" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// candidates: what the wildcard matches in the input, for the user to
// choose from: keys, buckets' objects, roles, or principals.
func candidates(in *Input, e *graph.Edge, side string) []string {
	var out []string
	add := func(v string) {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	self := in.Graph.Node(e.From).Identity
	switch {
	case side != graph.SideIdentity || e.Kind == graph.Assumes:
		for _, p := range in.Inventory.Principals {
			if p.Kind() == model.KindIAMRole && p.Identity() != self {
				add(p.Identity())
			}
		}
	default:
		for _, r := range in.Inventory.Resources {
			switch {
			case e.Kind == graph.CanDecrypt && r.Kind() == model.KindKMSKey:
				add(r.ARN())
			case e.Kind == graph.CanRead && r.Kind() == model.KindS3Bucket:
				add(r.ARN() + "/*")
			}
		}
	}
	slices.Sort(out)
	const most = 20
	if len(out) > most {
		out = append(out[:most], fmt.Sprintf("and %d more", len(out)-most))
	}
	return out
}
