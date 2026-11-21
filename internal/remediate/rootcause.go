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

// ForFinding plans the remediation of one finding: one plan per strategy.
// An UNKNOWN finding gets one plan saying what is missing; a finding with no
// finite cut, one plan saying so. A cut whose changes only remove explicit
// grants or change settings is one root-cause plan; a cut that narrows broad
// grants has a mitigation plan (Deny) and a root-cause plan.
func ForFinding(in *Input, f *rules.Finding) []*Plan {
	p := &Plan{Fingerprint: f.Fingerprint}
	switch {
	case !f.Confirmed:
		p.Missing = Missing(in.Graph, f.PathEdges)
		return []*Plan{p}
	case f.NoFix:
		p.NoFix = true
		return []*Plan{p}
	}
	root := &Plan{Fingerprint: f.Fingerprint, Strategy: StrategyRootCause}
	mitigates := false
	var suggestions []string
	for _, id := range f.ChokepointEdge {
		e := in.Graph.Edge(id)
		if len(e.Fixes) == 0 {
			p.NoFix = true
			return []*Plan{p}
		}
		c := ForEdge(in, id, &e.Fixes[0])
		p.Changes = append(p.Changes, c)
		if !mitigation(&c) {
			root.Changes = append(root.Changes, c)
			continue
		}
		mitigates = true
		rc, suggestion := RootCause(in, id, &e.Fixes[0])
		if suggestion != "" {
			suggestions = append(suggestions, suggestion)
		}
		root.Changes = append(root.Changes, rc)
	}
	if !mitigates {
		return []*Plan{root}
	}
	p.Strategy = StrategyMitigation
	if len(suggestions) > 0 {
		root.Changes = nil
		root.Suggestion = strings.Join(suggestions, "; ")
	}
	return []*Plan{root, p}
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
