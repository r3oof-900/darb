package remediate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// target is what an explicit grant names (SCORING.md §4.1, the same rule
// the access builder prices with).
type target struct {
	action    string
	resource  string // exact resource ARN
	objects   string // bucket ARN + "/": a narrow prefix of its objects
	principal string
	context   string // CAN_DECRYPT: the bucket the encryption context must name
}

func (t *target) namesResource(r string) bool {
	if t.objects != "" {
		return strings.HasPrefix(r, t.objects) && len(r) > len(t.objects)
	}
	return r == t.resource
}

// names: the statement names the action and the target (identity side) or
// the principal (resource side), and for a decrypt binds the context.
func (t *target) names(s *model.Statement, side string) bool {
	acts, neg := s.Actions()
	if neg || !slices.ContainsFunc(acts, func(a string) bool { return strings.EqualFold(a, t.action) }) {
		return false
	}
	if t.context != "" && !slices.ContainsFunc(s.Conditions(), func(c model.Condition) bool {
		return strings.EqualFold(c.Key(), "kms:EncryptionContext:aws:s3:arn") && !strings.Contains(c.Operator(), "Not") &&
			!slices.ContainsFunc(c.Values(), func(v string) bool { return v != t.context && !strings.HasPrefix(v, t.context+"/") })
	}) {
		return false
	}
	if side == graph.SideIdentity {
		if t.resource == "" && t.objects == "" {
			return true
		}
		rs, negRes := s.Resources()
		return !negRes && slices.ContainsFunc(rs, t.namesResource)
	}
	spec, neg := s.Principal()
	return spec != nil && !neg && !spec.Wildcard() &&
		slices.ContainsFunc(spec.Refs(), func(r model.PrincipalRef) bool { return r.Value == t.principal })
}

// Missing says what would decide an UNKNOWN path: the context keys a
// condition needs (set them under assume: in clapa.yaml), the values that
// are not known statically (scan a plan), the preconditions to state.
func Missing(g *graph.Graph, path []graph.EdgeID) []string {
	var out []string
	add := func(s string) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	var visit func(id graph.EdgeID)
	visit = func(id graph.EdgeID) {
		e := g.Edge(id)
		for _, u := range e.Under {
			visit(u)
		}
		if e.Precondition != nil && e.Precondition.State == model.Unknown {
			add("state whether " + e.Precondition.Reason + " (" + g.Describe(id) + ")")
		}
		if e.Verdict != eval.Unknown {
			return
		}
		for _, u := range e.Unresolved {
			add(missingOf(&u))
		}
		if len(e.Unresolved) == 0 && len(e.Under) == 0 {
			from, to := g.Node(e.From).Identity, g.Node(e.To).Identity
			if model.ContainsUnresolved(from) || model.ContainsUnresolved(to) {
				add("scan a Terraform plan (--plan): " + g.Describe(id) + " names a value that is not known statically")
			} else {
				add("decide " + g.Describe(id) + ": " + strings.Join(e.Evidence, "; "))
			}
		}
	}
	for _, id := range path {
		visit(id)
	}
	return out
}

// missingOf says what decides one undecided element: a context key to
// assume, or a value a plan would resolve.
func missingOf(u *graph.Unknown) string {
	if u.Element == "Condition" && strings.Contains(u.Key, ":") && !model.ContainsUnresolved(u.Key) {
		return fmt.Sprintf("set `assume: {%q: [...]}` in clapa.yaml: %s conditions on %s, whose value is not in the input (%s)",
			u.Key, u.Policy, u.Key, u.Reason)
	}
	return fmt.Sprintf("decide %s %s of %s: %s; a Terraform plan (--plan) resolves values that are not known statically",
		u.Element, u.Key, u.Policy, u.Reason)
}
