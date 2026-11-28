package access

import (
	"slices"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
)

// rewriter: whether a principal can rewrite a target's resource policy (a
// bucket policy, a key policy or grant, a role's trust), the §4.2 guard of
// SCORING.md. can: ALLOW or UNKNOWN, the resource side does not count;
// survives: whether, after an identity fix, it could still write the grant
// back in the resource's own account.
type rewriter struct {
	can      bool
	survives func(fx *graph.Fix) bool
}

func (b *builder) rewriter(who *model.Principal, resource, account string, res []*model.PolicyDocument, required bool, actions ...string) *rewriter {
	rw := &rewriter{}
	for _, a := range actions {
		rw.can = rw.can || b.canDo(who, a, resource, account, res, required)
	}
	rw.survives = func(fx *graph.Fix) bool {
		if who == nil || account == "" || account != who.Account() {
			return false // across accounts the identity grant is still required
		}
		for _, a := range actions {
			req := &eval.Request{Principal: b.session(who), Action: a, Resource: resource, ResourceAccount: account, Context: b.context(who, a, resource, nil)}
			if keepsRewrite(req, b.identitySet(who, res, required), fx) {
				return true
			}
		}
		return false
	}
	return rw
}

// keepsRewrite: the rewrite is a known ALLOW that the identity fix leaves in
// place: the resource policy alone grants it, or a statement outside every
// policy the fix detaches (narrowing or revoking one grant does not take
// away the statement's other actions). An UNKNOWN rewrite never guards:
// resolving it is part of the cut, and a guard never removes knowledge
// (Phase 6 review).
func keepsRewrite(req *eval.Request, set *eval.PolicySet, fx *graph.Fix) bool {
	if eval.Evaluate(req, set).Verdict != eval.Allow {
		return false
	}
	without := *set
	without.Identity = nil
	if eval.Evaluate(req, &without).Verdict == eval.Allow {
		return true
	}
	for _, gd := range eval.GrantingDetail(req, set.Identity) {
		id := gd.Doc.ID()
		if gd.Applies == model.True && !slices.ContainsFunc(fx.Detach, func(d graph.Detach) bool { return d.Policy == id }) {
			return true
		}
	}
	return false
}

func (rw *rewriter) guardsIdentity(fx *graph.Fix) bool {
	return rw != nil && rw.can && rw.survives != nil && rw.survives(fx)
}

// guardsResource: a principal that can rewrite the resource policy (ALLOW or
// UNKNOWN) undoes a cut of it.
func (rw *rewriter) guardsResource() bool { return rw != nil && rw.can }
