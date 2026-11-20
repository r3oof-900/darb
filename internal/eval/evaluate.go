package eval

import (
	"cmp"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/model"
)

// Evaluate decides req against ps following AWS's documented policy
// evaluation logic (docs/DESIGN.md section 6). It is a pure function:
// statement and policy order never change the result.
func Evaluate(req *Request, ps *PolicySet) Decision {
	ctx := contextOf(req)
	r := collect(req, ps, ctx)
	if denies := r.filter(model.EffectDeny, model.True); len(denies) > 0 {
		return Decision{Verdict: Deny, Contributing: sortRefs(denies)}
	}
	g := r.grants(ps)
	access, missing := decide(req, ps, &g)
	unknownDenies := r.filter(model.EffectDeny, model.Unknown)
	d := Decision{Assumptions: assumptions(ps)}
	switch {
	case access == model.True && len(unknownDenies) == 0:
		d.Verdict = Allow
		d.Contributing = sortRefs(r.filter(model.EffectAllow, model.True))
	case access == model.False:
		d.Verdict = ImplicitDeny
		d.Missing = missing
	default:
		d.Verdict = Unknown
		d.Missing = missing
		d.Contributing = sortRefs(append(unknownDenies, r.filter(model.EffectAllow, model.Unknown)...))
		d.Unresolved = r.unresolved()
	}
	return d
}

// contextOf: the request context; nil means every key is unknown.
func contextOf(req *Request) *condition.Context {
	if req.Context == nil {
		return condition.NewContext(&condition.Input{})
	}
	return req.Context
}

// Granting returns the Allow statements of docs that apply to req (TRUE or
// UNKNOWN), in document and statement order: the grants a change to those
// policies has to touch (SCORING.md §4.1).
func Granting(req *Request, docs []*model.PolicyDocument) []*model.Statement {
	ctx := contextOf(req)
	var out []*model.Statement
	for _, d := range docs {
		stmts := d.Statements()
		rs := evalDocument(d, req, ctx)
		for i := range rs {
			if r := &rs[i].ref; r.Effect == model.EffectAllow && r.Applies != model.False {
				out = append(out, stmts[i])
			}
		}
	}
	return out
}

// results holds the statement results per policy group.
type results struct {
	identity, resource, boundary, session []stmtResult
	scps, rcps                            [][]stmtResult
}

func collect(req *Request, ps *PolicySet, ctx *condition.Context) *results {
	docs := func(ds []*model.PolicyDocument) []stmtResult {
		var out []stmtResult
		for _, d := range ds {
			out = append(out, evalDocument(d, req, ctx)...)
		}
		return out
	}
	levels := func(ls [][]*model.PolicyDocument) [][]stmtResult {
		out := make([][]stmtResult, 0, len(ls))
		for _, l := range ls {
			out = append(out, docs(l))
		}
		return out
	}
	r := &results{
		identity: docs(ps.Identity), resource: docs(ps.Resource), session: docs(ps.Session),
		rcps: levels(ps.RCPs),
	}
	if governedBySCPs(req.Principal.Kind) {
		// SCPs govern principals in member accounts, never AWS service
		// principals, web identities or anonymous callers.
		r.scps = levels(ps.SCPs)
	}
	if ps.Boundary != nil {
		r.boundary = docs([]*model.PolicyDocument{ps.Boundary})
	}
	return r
}

func governedBySCPs(k match.PrincipalKind) bool {
	return k != match.KindService && k != match.KindWebIdentity && k != match.KindAnonymous
}

func (r *results) all() []stmtResult {
	out := slices.Concat(r.identity, r.resource, r.boundary, r.session)
	for _, l := range slices.Concat(r.scps, r.rcps) {
		out = append(out, l...)
	}
	return out
}

func (r *results) filter(effect model.Effect, applies model.Tri) []StatementRef {
	var out []StatementRef
	all := r.all()
	for i := range all {
		s := &all[i]
		if s.ref.Effect == effect && s.ref.Applies == applies {
			out = append(out, s.ref)
		}
	}
	return out
}

func (r *results) unresolved() []Unresolved {
	var out []Unresolved
	all := r.all()
	for i := range all {
		s := &all[i]
		out = append(out, s.unresolved...)
	}
	slices.SortFunc(out, func(a, b Unresolved) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), strings.Compare(a.PolicyID, b.PolicyID),
			strings.Compare(a.Statement, b.Statement), strings.Compare(a.Element, b.Element),
			strings.Compare(a.Operator, b.Operator), strings.Compare(a.Key, b.Key))
	})
	return slices.Compact(out)
}

// allows ORs the applicability of the Allow statements.
func allows(rs []stmtResult) model.Tri {
	acc := model.False
	for i := range rs {
		s := &rs[i]
		if s.ref.Effect == model.EffectAllow {
			acc = acc.Or(s.ref.Applies)
		}
	}
	return acc
}

// levelsAllow: every organization level must allow; nil means not modelled.
func levelsAllow(levels [][]stmtResult, modelled bool) model.Tri {
	if !modelled {
		return model.True
	}
	acc := model.True
	for _, l := range levels {
		acc = acc.And(allows(l))
	}
	return acc
}

func assumptions(ps *PolicySet) []string {
	var out []string
	if ps.SCPs == nil {
		out = append(out, "service control policies not provided; assumed to allow")
	}
	if ps.RCPs == nil {
		out = append(out, "resource control policies not provided; assumed to allow")
	}
	if ps.Session == nil {
		out = append(out, "no session policy; assumed none was passed")
	}
	return out
}

func sortRefs(refs []StatementRef) []StatementRef {
	slices.SortFunc(refs, func(a, b StatementRef) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), strings.Compare(a.PolicyID, b.PolicyID),
			cmp.Compare(a.Index, b.Index), strings.Compare(a.Sid, b.Sid))
	})
	return refs
}

// grantSet is what each policy type contributes.
type grantSet struct {
	identity, boundary, session, scp, rcp model.Tri
	// Resource-based grants by how the Principal element matched.
	resUnlimited model.Tri // user ARN, session ARN, service, federated, canonical user
	resLimited   model.Tri // role ARN, or IAM user ARN for a federated session: boundary and session policy still apply
	resWildcard  model.Tri // "*" or {"AWS": "*"}
	resAccount   model.Tri // account delegation: the identity side must allow
}

func (r *results) grants(ps *PolicySet) grantSet {
	g := grantSet{
		identity: allows(r.identity), boundary: model.True, session: model.True,
		scp: levelsAllow(r.scps, ps.SCPs != nil), rcp: levelsAllow(r.rcps, ps.RCPs != nil),
		resUnlimited: model.False, resLimited: model.False, resWildcard: model.False, resAccount: model.False,
	}
	if ps.Boundary != nil {
		g.boundary = allows(r.boundary)
	}
	if ps.Session != nil {
		g.session = allows(r.session)
	}
	for i := range r.resource {
		s := &r.resource[i]
		if s.ref.Effect == model.EffectAllow {
			g.addResource(s.ref.Applies, s.via)
		}
	}
	return g
}

// addResource files a resource-policy grant under its match kind. A grant
// whose principal match is undecided (ViaNone) counts as Unknown everywhere.
func (g *grantSet) addResource(applies model.Tri, via match.Via) {
	if t := g.bucket(via); t != nil {
		*t = t.Or(applies)
		return
	}
	if applies == model.Unknown {
		for _, t := range []*model.Tri{&g.resAccount, &g.resWildcard, &g.resLimited, &g.resUnlimited} {
			*t = t.Or(model.Unknown)
		}
	}
}

// bucket returns the grant category for a match kind; nil for ViaNone.
// Unrecognised kinds fall into the most permissive category, so a future
// match kind can never silently drop a grant.
func (g *grantSet) bucket(via match.Via) *model.Tri {
	switch via {
	case match.ViaNone:
		return nil
	case match.ViaAccount:
		return &g.resAccount
	case match.ViaWildcard:
		return &g.resWildcard
	case match.ViaRoleARN, match.ViaFederatedUserCreator:
		return &g.resLimited
	case match.ViaUserARN, match.ViaSessionARN, match.ViaService, match.ViaFederated, match.ViaCanonicalUser:
	}
	return &g.resUnlimited
}

func (g *grantSet) resourceAny() model.Tri {
	return g.resUnlimited.Or(g.resLimited).Or(g.resWildcard).Or(g.resAccount)
}
