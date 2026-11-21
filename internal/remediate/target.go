package remediate

import (
	"slices"
	"strings"

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
		return strings.EqualFold(c.Key(), model.EncryptionContextKey(t.context)) && !strings.Contains(c.Operator(), "Not") &&
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

// Missing says what would decide an UNKNOWN path (graph.Undecided).
func Missing(g *graph.Graph, path []graph.EdgeID) []string { return g.Undecided(path) }
