package access

import (
	"slices"
	"strconv"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
)

// The IAM escalations and lateral moves of users (item 4, after
// v0.1.0-rc.1; DESIGN.md §7.2). Each leads to a synthetic principal that
// keeps the user's ARN as its identity (model.Kind* in ids.go), or to
// another user's own node.

// userEscalations: the escalations of src, a user or a synthetic principal
// standing for one; it returns the new synthetic principals to queue.
func (b *builder) userEscalations(src *model.Principal) []*model.Principal {
	u := b.byARN[src.Identity()]
	if u == nil || u.Kind() != model.KindIAMUser {
		return nil
	}
	var out []*model.Principal
	add := func(p *model.Principal, ok bool) {
		if ok {
			out = append(out, p)
		}
	}
	if src.Kind() != model.KindIAMUserAnyPermission {
		add(b.modifyUser(src, u))
	}
	add(b.dropBoundary(src, u, eval.Allow, "iam:DeleteUserPermissionsBoundary", "iam:PutUserPermissionsBoundary"))
	out = append(out, b.switchVersions(src, u)...)
	add(b.joinGroups(src, u))
	for _, v := range b.users {
		if v.Kind() == model.KindIAMUser && v.Identity() != u.Identity() {
			b.createKey(src, v)
			add(b.loginProfile(src, v))
		}
	}
	return out
}

// modifyUser: iam:AttachUserPolicy or PutUserPolicy on the user,
// CreatePolicyVersion on one of its customer managed policies (with room
// for a version, or DeletePolicyVersion on it; --set-as-default needs no
// SetDefaultPolicyVersion), or PutGroupPolicy / AttachGroupPolicy on one of
// its groups: the user with any permission.
func (b *builder) modifyUser(src, u *model.Principal) (*model.Principal, bool) {
	best := &eval.Decision{Verdict: eval.ImplicitDeny}
	var why []string
	var reqs []grantReq
	try := func(d *eval.Decision, label string, r ...grantReq) {
		if better(d, best) {
			best, why = d, append(evidence(d), label)
		}
		if grants(d.Verdict) {
			reqs = append(reqs, r...)
		}
	}
	for _, a := range []string{"iam:AttachUserPolicy", "iam:PutUserPolicy"} {
		d := b.ask(src, a, u.Identity(), nil)
		try(&d, a+" on "+u.Identity(), b.grantReq(src, a, u.Identity(), nil))
	}
	for _, mp := range b.inv.ManagedPolicies {
		if !slices.Contains(mp.Attached, u.ID()) {
			continue
		}
		d := b.ask(src, "iam:CreatePolicyVersion", mp.ARN, nil)
		r := []grantReq{b.grantReq(src, "iam:CreatePolicyVersion", mp.ARN, nil)}
		if mp.Count >= 5 { // IAM keeps five versions: one must be deleted first
			del := b.ask(src, "iam:DeletePolicyVersion", mp.ARN, nil)
			d.Verdict = both(d.Verdict, del.Verdict)
			r = append(r, b.grantReq(src, "iam:DeletePolicyVersion", mp.ARN, nil))
		}
		try(&d, "iam:CreatePolicyVersion on "+mp.ARN, r...)
	}
	for _, g := range b.inv.Groups {
		if !slices.Contains(g.Members, u.ID()) {
			continue
		}
		for _, a := range []string{"iam:PutGroupPolicy", "iam:AttachGroupPolicy"} {
			d := b.ask(src, a, g.ARN, nil)
			try(&d, a+" on "+g.ARN, b.grantReq(src, a, g.ARN, nil))
		}
	}
	if !grants(best.Verdict) {
		return nil, false
	}
	target, isNew := b.anyPermission(u)
	b.escalation(src, target, "iam:modify-policy", best, why, reqs)
	return target, isNew
}

// dropBoundary: removing (or replacing with a broader one) dst's
// permissions boundary, when src is or can become dst (act): dst with no
// boundary. No edge when dst has none.
func (b *builder) dropBoundary(src, dst *model.Principal, act eval.Verdict, actions ...string) (*model.Principal, bool) {
	if _, ok := b.boundaries[dst.ID()]; !ok || !grants(act) || src.Kind() == model.KindNoBoundary {
		return nil, false
	}
	best, why, reqs := b.anyOf(src, dst.Identity(), actions...)
	best.Verdict = both(best.Verdict, act)
	if !grants(best.Verdict) {
		return nil, false
	}
	target, isNew := b.synthetic(model.KindNoBoundary, dst, "", b.policies[dst.ID()], nil)
	b.escalation(src, target, "iam:boundary", best, why, reqs)
	return target, isNew
}

// switchVersions: iam:SetDefaultPolicyVersion on one of the user's
// customer managed policies: the user with that policy at each other
// stored version. A version that adds nothing gives only dominated paths
// (DESIGN.md §8), which are not reported: the escalation shows where a
// version is broader.
func (b *builder) switchVersions(src, u *model.Principal) []*model.Principal {
	var out []*model.Principal
	for _, mp := range b.inv.ManagedPolicies {
		if !slices.Contains(mp.Attached, u.ID()) || len(mp.Others) == 0 || src.Kind() == model.KindPolicyVersion {
			continue
		}
		best, why, reqs := b.anyOf(src, mp.ARN, "iam:SetDefaultPolicyVersion")
		if !grants(best.Verdict) {
			continue
		}
		for _, v := range mp.Others {
			docs := slices.Clone(b.policies[u.ID()])
			for i, d := range docs {
				if d.ID() == mp.ARN {
					docs[i] = v
				}
			}
			target, isNew := b.synthetic(model.KindPolicyVersion, u, v.ID(), docs, b.boundaries[u.ID()])
			b.escalation(src, target, "iam:set-default-version", best, why, reqs)
			if isNew {
				out = append(out, target)
			}
		}
	}
	return out
}

// joinGroups: iam:AddUserToGroup on groups the user is not in: the user in
// every group it can join.
func (b *builder) joinGroups(src, u *model.Principal) (*model.Principal, bool) {
	if src.Kind() == model.KindInGroups {
		return nil, false
	}
	best := &eval.Decision{Verdict: eval.ImplicitDeny}
	var why []string
	var reqs []grantReq
	docs := slices.Clone(b.policies[u.ID()])
	for _, g := range b.inv.Groups {
		if slices.Contains(g.Members, u.ID()) {
			continue
		}
		d, w, r := b.anyOf(src, g.ARN, "iam:AddUserToGroup")
		if !grants(d.Verdict) {
			continue
		}
		if better(d, best) {
			best, why = d, w
		}
		reqs = append(reqs, r...)
		docs = append(docs, g.Policies...)
	}
	if !grants(best.Verdict) {
		return nil, false
	}
	target, isNew := b.synthetic(model.KindInGroups, u, "", docs, b.boundaries[u.ID()])
	b.escalation(src, target, "iam:add-to-group", best, why, reqs)
	return target, isNew
}

// createKey: iam:CreateAccessKey for another user v, who has fewer than
// two keys (inactive ones count: IAM allows two per user); UNKNOWN when the
// count is not in the input. src then acts as v.
func (b *builder) createKey(src, v *model.Principal) {
	c := b.inv.CredentialsOf(v.ID())
	if c != nil && c.KeyCount >= 2 {
		return
	}
	best, why, reqs := b.anyOf(src, v.Identity(), "iam:CreateAccessKey")
	if !grants(best.Verdict) {
		return
	}
	if c == nil || c.KeyCount < 0 {
		best.Verdict = both(best.Verdict, eval.Unknown)
		best.Unresolved = append(best.Unresolved, eval.Unresolved{
			PolicyID: v.Identity(), Element: "Credentials", Key: "access key count",
			Reason: "the number of access keys of " + v.Identity() + " is not in the input (iam:GetCredentialReport, iam:ListAccessKeys)",
		})
	}
	b.escalation(src, v, "iam:create-access-key", best, append(why, "keys of "+v.Identity()+": "+keyCount(c)), reqs)
}

func keyCount(c *model.Credentials) string {
	if c == nil || c.KeyCount < 0 {
		return "unknown"
	}
	return strconv.Itoa(c.KeyCount)
}

// loginProfile: iam:CreateLoginProfile for a user without a password, or
// UpdateLoginProfile for one with: src signs in to the console as v. No
// edge when v has an MFA device (sign-in needs it); UNKNOWN when that is
// not known.
func (b *builder) loginProfile(src, v *model.Principal) (*model.Principal, bool) {
	c := b.inv.CredentialsOf(v.ID())
	if c != nil && c.MFA == model.True {
		return nil, false
	}
	var actions []string
	if c == nil || c.Password != model.True {
		actions = append(actions, "iam:CreateLoginProfile")
	}
	if c == nil || c.Password != model.False {
		actions = append(actions, "iam:UpdateLoginProfile")
	}
	best, why, reqs := b.anyOf(src, v.Identity(), actions...)
	if !grants(best.Verdict) {
		return nil, false
	}
	if c == nil || c.MFA == model.Unknown {
		best.Verdict = both(best.Verdict, eval.Unknown)
		best.Unresolved = append(best.Unresolved, eval.Unresolved{
			PolicyID: v.Identity(), Element: "Credentials", Key: "mfa_active",
			Reason: "whether " + v.Identity() + " has an MFA device is not in the input (iam:GetCredentialReport)",
		})
	}
	target, isNew := b.synthetic(model.KindConsoleSession, v, "", b.policies[v.ID()], b.boundaries[v.ID()])
	b.escalation(src, target, "iam:login-profile", best, why, reqs)
	return target, isNew
}

// anyOf: the best decision of src's actions on resource, with the evidence
// and the grants a fix must remove.
func (b *builder) anyOf(src *model.Principal, resource string, actions ...string) (*eval.Decision, []string, []grantReq) {
	best := &eval.Decision{Verdict: eval.ImplicitDeny}
	var why []string
	var reqs []grantReq
	for _, a := range actions {
		d := b.ask(src, a, resource, nil)
		if better(&d, best) {
			best, why = &d, append(evidence(&d), a+" on "+resource)
		}
		if grants(d.Verdict) {
			reqs = append(reqs, b.grantReq(src, a, resource, nil))
		}
	}
	return best, why, reqs
}

// escalation adds CAN_ESCALATE[sub] src -> dst, its identity side priced
// from every grant it needs (SCORING.md 4.1).
func (b *builder) escalation(src, dst *model.Principal, sub string, d *eval.Decision, why []string, reqs []grantReq) {
	b.edge(src.ID(), dst.ID(), graph.CanEscalate, sub, d, func(e *graph.Edge) {
		e.Evidence = why
		e.Fixes = nonNil(b.escalationFixes(e, src, reqs))
	})
}

// synthetic returns the synthetic principal of kind for base (one per key),
// creating it with docs and boundary the first time.
func (b *builder) synthetic(kind model.NodeKind, base *model.Principal, key string, docs []*model.PolicyDocument, boundary *model.PolicyDocument) (*model.Principal, bool) {
	id := model.NewID(kind, base.Identity()+"|"+key)
	if p, ok := b.rewritten[id]; ok {
		return p, false
	}
	p := model.NewSyntheticPrincipal(kind, base.Identity(), key, base.Account(), base.Source())
	b.rewritten[id] = p
	b.order = append(b.order, p)
	b.g.Node(p.ID(), p.Kind(), base.Identity())
	b.policies[p.ID()] = slices.Clone(docs)
	if boundary != nil {
		b.boundaries[p.ID()] = boundary
	}
	return p, true
}
