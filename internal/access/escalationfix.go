package access

import (
	"slices"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/scoring"
)

// grantReq is one request an IAM escalation needs, and what an explicit
// grant of it names.
type grantReq struct {
	req *eval.Request
	t   *grantTarget
}

func (b *builder) grantReq(src *model.Principal, action, resource string, present map[string][]string) grantReq {
	return grantReq{b.request(src, action, resource, present), &grantTarget{action: action, resource: resource}}
}

// escalationFixes: the fact fix of an IAM escalation, its identity side
// priced from every statement that grants one of the requests it needs:
// revoke when one names it explicitly, narrow when all are broad; detach for
// a known AWS managed policy; resolve for an UNKNOWN grant (SCORING.md 4.1).
func (b *builder) escalationFixes(e *graph.Edge, src *model.Principal, reqs []grantReq) []graph.Fix {
	fixes := b.factFixes(e, graph.FixNarrow)
	set := b.identitySet(src, nil, false)
	for i := range fixes {
		if fixes[i].Side != graph.SideIdentity {
			continue
		}
		merged := &fixes[i]
		merged.Kind, merged.Cost = "", 0
		for _, r := range reqs {
			fx := sideFix(graph.CanEscalate, "", graph.SideIdentity, r.req, set.Identity, r.t, "", merged.Policy, src.Identity())
			mergeSide(merged, &fx)
		}
		if merged.Kind == "" && len(merged.Detach) == 0 && len(merged.Resolve) == 0 {
			merged.Kind = graph.FixRevoke // no granting statement found: it cannot be shown broad
		}
		if merged.Kind == graph.FixNarrow || merged.Kind == graph.FixRevoke {
			merged.Cost = scoring.FixCost(graph.CanEscalate, "", graph.SideIdentity, merged.Kind)
		}
	}
	sortFixes(fixes)
	return fixes
}

// mergeSide adds one request's side to an escalation's: every way of
// granting it must go, so one explicit grant makes it a revoke.
func mergeSide(into, fx *graph.Fix) {
	switch {
	case fx.Kind == graph.FixRevoke || into.Kind == graph.FixRevoke:
		into.Kind = graph.FixRevoke
	case fx.Kind == graph.FixNarrow || into.Kind == graph.FixNarrow:
		into.Kind = graph.FixNarrow
	}
	unionParts(into, fx)
	switch {
	case into.Kind == "" && len(into.Detach) == 0 && len(into.Resolve) > 0:
		into.Kind = graph.FixResolve
	case into.Kind == graph.FixResolve && len(into.Detach) > 0:
		into.Kind = "" // the detach is the change; the resolve steps stay listed
	}
}

// unionParts adds fx's grants, detaches and resolve steps to into's.
func unionParts(into, fx *graph.Fix) {
	for _, g := range fx.Grants {
		if !slices.Contains(into.Grants, g) {
			into.Grants = append(into.Grants, g)
		}
	}
	for _, d := range fx.Detach {
		if !slices.ContainsFunc(into.Detach, func(x graph.Detach) bool { return x.Group == d.Group }) {
			into.Detach = append(into.Detach, d)
		}
	}
	for _, r := range fx.Resolve {
		if !slices.Contains(into.Resolve, r) {
			into.Resolve = append(into.Resolve, r)
		}
	}
}

// conj combines decisions that must all grant (an escalation's requests):
// ALLOW, or UNKNOWN that only unknown Denies may block (DenyOnly), stays
// deny-only; any UNKNOWN allow makes it UNKNOWN (DESIGN.md 6.2).
type conj struct {
	d        eval.Decision
	denyOnly bool
}

func allowAllOf() *conj { return &conj{d: eval.Decision{Verdict: eval.Allow}, denyOnly: true} }

func (c *conj) and(d *eval.Decision) {
	c.d.Verdict = both(c.d.Verdict, d.Verdict)
	if d.Verdict == eval.Unknown {
		c.denyOnly = c.denyOnly && d.DenyOnly
		c.d.Unresolved = append(c.d.Unresolved, d.Unresolved...)
	}
}

// andVerdict: a part known only by its verdict (UNKNOWN is not deny-only).
func (c *conj) andVerdict(v eval.Verdict) { c.and(&eval.Decision{Verdict: v}) }

func (c *conj) decision() *eval.Decision {
	d := c.d
	d.DenyOnly = d.Verdict == eval.Unknown && c.denyOnly
	return &d
}

// better: the stronger of two ways to the same request (ALLOW, then a
// deny-only UNKNOWN, then any UNKNOWN).
func better(a, b *eval.Decision) bool {
	rank := func(d *eval.Decision) int {
		switch {
		case d.Verdict == eval.Allow:
			return 3
		case d.Verdict == eval.Unknown && d.DenyOnly:
			return 2
		case d.Verdict == eval.Unknown:
			return 1
		}
		return 0
	}
	return rank(a) > rank(b)
}
