package eval

import (
	"github.com/r3oof-900/darb/internal/eval/match"
	"github.com/r3oof-900/darb/internal/model"
)

// decide combines the grants into the access decision (before unknown
// denies are considered) and lists the components that did not allow.
func decide(req *Request, ps *PolicySet, g *grantSet) (model.Tri, []Component) {
	kind := req.Principal.Kind
	access := principalAccess(req, ps, g)
	if !governedBySCPs(kind) {
		// No identity policies, SCPs or boundaries: only the resource side.
		access = g.resUnlimited.Or(g.resWildcard).And(g.rcp)
	} else if kind == match.KindAccountRoot {
		access = rootAccess(req, ps, g)
	}
	return access, missing(req, ps, g)
}

// principalAccess handles IAM users, role sessions and federated sessions.
func principalAccess(req *Request, ps *PolicySet, g *grantSet) model.Tri {
	access := byAccount(sameAccount(req), sameAccountAccess(ps, g), crossAccountAccess(g))
	return access.And(g.scp).And(g.rcp)
}

// byAccount picks the same- or cross-account result. When the relation is
// unknown, a decision is made only if both interpretations agree.
func byAccount(same, sameResult, crossResult model.Tri) model.Tri {
	if same == model.True {
		return sameResult
	}
	if same == model.False {
		return crossResult
	}
	if sameResult == crossResult {
		return sameResult
	}
	return model.Unknown
}

// sameAccountAccess implements IAM User Guide › "Policy evaluation for
// requests within a single account" and › "Permissions boundaries for IAM
// entities" › "Resource-based policies" (docs/DESIGN.md section 6.1):
//
//   - a grant to the user ARN or session ARN suffices on its own;
//   - a grant to the role ARN (or to the IAM user behind a federated
//     session) is still limited by the boundary and session policy;
//   - a grant to the account delegates to IAM (identity side must allow);
//   - for KMS keys and role trust policies the resource policy must allow.
func sameAccountAccess(ps *PolicySet, g *grantSet) model.Tri {
	identitySide := g.identity.And(g.boundary).And(g.session)
	direct := g.resUnlimited.
		Or(g.resLimited.And(g.boundary).And(g.session)).
		Or(g.resWildcard.And(wildcardLimit(g)))
	if ps.ResourcePolicyRequired {
		return direct.Or(g.resAccount.And(identitySide))
	}
	return direct.Or(identitySide)
}

// wildcardLimit: whether a boundary or session policy limits a same-account
// "Principal": "*" grant is not documented. With neither present the grant
// stands; when they definitely deny, the result is Unknown, never a guess.
func wildcardLimit(g *grantSet) model.Tri {
	lim := g.boundary.And(g.session)
	if lim == model.False {
		return model.Unknown
	}
	return lim
}

// crossAccountAccess: both the identity side and the resource side must
// allow (IAM User Guide › "Cross-account policy evaluation logic").
func crossAccountAccess(g *grantSet) model.Tri {
	return g.identity.And(g.boundary).And(g.session).And(g.resourceAny())
}

// rootAccess: identity policies do not apply to the root user; within its
// own account it is allowed unless the resource policy must allow.
func rootAccess(req *Request, ps *PolicySet, g *grantSet) model.Tri {
	resource := g.resourceAny()
	own := model.True
	if ps.ResourcePolicyRequired {
		own = resource
	}
	return byAccount(sameAccount(req), own, resource).And(g.scp).And(g.rcp)
}

func sameAccount(req *Request) model.Tri {
	if req.ResourceAccount == "" || req.Principal.Account == "" ||
		model.ContainsUnresolved(req.ResourceAccount) || model.ContainsUnresolved(req.Principal.Account) {
		return model.Unknown
	}
	return model.TriOf(req.ResourceAccount == req.Principal.Account)
}

// missing lists the components that were consulted and did not definitely allow.
func missing(req *Request, ps *PolicySet, g *grantSet) []Component {
	var out []Component
	add := func(c Component, t model.Tri) {
		if t != model.True {
			out = append(out, c)
		}
	}
	hasIdentity := req.Principal.Kind != match.KindService && req.Principal.Kind != match.KindWebIdentity &&
		req.Principal.Kind != match.KindAnonymous && req.Principal.Kind != match.KindAccountRoot
	if hasIdentity {
		add(CompIdentity, g.identity)
	}
	// The resource side is consulted when a resource policy exists, when it
	// is required (KMS, trust), or when the request may be cross-account.
	crossAccount := hasIdentity && sameAccount(req) != model.True
	if len(ps.Resource) > 0 || ps.ResourcePolicyRequired || crossAccount {
		add(CompResource, g.resourceAny())
	}
	if hasIdentity {
		add(CompBoundary, g.boundary)
		add(CompSession, g.session)
	}
	if hasIdentity || req.Principal.Kind == match.KindAccountRoot {
		add(CompSCP, g.scp)
	}
	add(CompRCP, g.rcp)
	return out
}
