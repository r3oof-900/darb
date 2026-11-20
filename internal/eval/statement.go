package eval

import (
	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/model"
)

// stmtResult is whether one statement applies to the request.
type stmtResult struct {
	ref        StatementRef
	via        match.Via
	unresolved []Unresolved
}

// evalDocument evaluates every statement of doc.
func evalDocument(doc *model.PolicyDocument, req *Request, ctx *condition.Context) []stmtResult {
	x := expander{ctx: ctx, enabled: doc.VariablesEnabled()}
	stmts := doc.Statements()
	out := make([]stmtResult, 0, len(stmts))
	for _, s := range stmts {
		out = append(out, evalStatement(doc, s, req, x))
	}
	return out
}

// evalStatement ANDs the statement's elements. Unresolved details are kept
// only when the statement's applicability is Unknown: an element that is
// definitely false makes the others irrelevant.
func evalStatement(doc *model.PolicyDocument, s *model.Statement, req *Request, x expander) stmtResult {
	res := stmtResult{ref: StatementRef{
		PolicyID: doc.ID(), Kind: doc.Kind(), Sid: s.Sid(), Index: s.Index(),
		Effect: s.Effect(), Source: *doc.Source(), Applies: model.True,
	}}
	acts, notAction := s.Actions()
	action := match.Action(acts, req.Action)
	if notAction {
		action = action.Not()
	}
	if action == model.False {
		res.ref.Applies = model.False
		return res
	}
	if action == model.Unknown {
		res.and(doc, s, "Action", "", "", condition.Result{Value: model.Unknown, Reason: "Action was not resolved in the source"})
	}
	res.and(doc, s, "Principal", "", "", principalApplies(s, &req.Principal, &res))
	res.and(doc, s, "Resource", "", "", resourceApplies(s, req.Resource, x))
	for _, c := range s.Conditions() {
		r := condition.Evaluate(&c, x.ctx, x)
		res.and(doc, s, "Condition", c.Operator(), c.Key(), r)
	}
	if res.ref.Applies != model.Unknown {
		res.unresolved = nil
	}
	return res
}

func (r *stmtResult) and(doc *model.PolicyDocument, s *model.Statement, element, op, key string, c condition.Result) {
	r.ref.Applies = r.ref.Applies.And(c.Value)
	if c.Value == model.Unknown {
		r.unresolved = append(r.unresolved, Unresolved{
			PolicyID: doc.ID(), Kind: doc.Kind(), Statement: s.Label(),
			Element: element, Operator: op, Key: key, Reason: c.Reason,
		})
	}
}

// principalApplies matches Principal/NotPrincipal (resource-based policies
// only; other kinds have none) and records how it matched.
func principalApplies(s *model.Statement, p *match.RequestPrincipal, res *stmtResult) condition.Result {
	spec, negated := s.Principal()
	if spec == nil {
		return condition.Result{Value: model.True}
	}
	var m match.PrincipalMatch
	if negated {
		m = match.NotPrincipal(spec, p)
		m.Via = match.ViaWildcard // NotPrincipal grants are as broad as a wildcard
	} else {
		m = match.Principal(spec, p)
	}
	res.via = m.Via
	return condition.Result{Value: m.Value, Reason: m.Reason}
}

func resourceApplies(s *model.Statement, resource string, x expander) condition.Result {
	patterns, negated := s.Resources()
	if len(patterns) == 0 {
		return condition.Result{Value: model.True} // no Resource element (e.g. trust policies)
	}
	v := match.Resource(patterns, resource, x)
	if negated {
		v = v.Not()
	}
	if v == model.Unknown {
		return condition.Result{Value: v, Reason: "Resource contains an unresolved policy variable"}
	}
	return condition.Result{Value: v}
}
