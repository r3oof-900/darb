package access

import (
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// kubernetes adds RUNS_AS, CAN_ESCALATE[k8s-token], CAN_ESCALATE[rbac],
// ASSUMES[irsa] and ASSUMES[pod-identity] (DESIGN.md §7.2).
func (b *builder) kubernetes() {
	allow := &eval.Decision{Verdict: eval.Allow}
	for _, w := range b.inv.Workloads {
		sa := saID(w.Cluster(), w.Namespace(), w.ServiceAccount())
		if _, ok := b.g.Lookup(sa); !ok {
			continue // the service account is not in the input (a gap was recorded)
		}
		b.edge(w.ID(), sa, graph.RunsAs, "", allow, nil)
		switch w.AutomountToken() {
		case model.True:
			b.edge(w.ID(), sa, graph.CanEscalate, "k8s-token", allow, func(e *graph.Edge) {
				if slices.Contains(w.Defaulted(), model.DefaultAutomountToken) {
					e.Defaults = []string{model.DefaultAutomountToken}
				}
			})
		case model.Unknown:
			b.edge(w.ID(), sa, graph.CanEscalate, "k8s-token", &eval.Decision{Verdict: eval.Unknown}, func(e *graph.Edge) {
				e.Precondition = &graph.Precondition{Reason: "service account token mounted", State: model.Unknown}
			})
		case model.False:
		}
	}
	for _, g := range b.inv.RBAC {
		b.rbac(g)
	}
	for _, sa := range b.inv.ServiceAccounts {
		b.irsa(sa)
	}
	b.projected()
	for _, a := range b.inv.PodIdentity {
		b.podIdentity(a)
	}
}

// rbac: a service account that may create pods (or exec into them, mint
// tokens for, or impersonate service accounts) in a namespace can act as
// that namespace's service accounts (DESIGN.md §7.2).
func (b *builder) rbac(g *model.RBACGrant) {
	if g.SubjectKind != "ServiceAccount" {
		return
	}
	from := saID(g.Cluster, g.SubjectNamespace, g.SubjectName)
	if _, ok := b.g.Lookup(from); ok {
		b.rbacFrom(from, g)
	}
}

// rbacFrom adds the escalation edges a grant gives a subject node.
func (b *builder) rbacFrom(from model.ID, g *model.RBACGrant) {
	verdict, ok := grantVerdict(g)
	if !ok {
		return
	}
	for _, sa := range b.namespaceAccounts(g) {
		if sa.ID == from {
			b.selfMinters[sa.ID] = verdict
			continue
		}
		b.minters[sa.ID] = true
		b.edge(from, sa.ID, graph.CanEscalate, "rbac", &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
			e.Evidence = []string{"RBAC " + g.Source.String()}
		})
	}
}

// grantVerdict: ALLOW when the rules control service accounts, UNKNOWN when
// the referenced role is not in the input (its rules are unknown).
func grantVerdict(g *model.RBACGrant) (verdict eval.Verdict, ok bool) {
	if g.Unresolved != "" {
		return eval.Unknown, true
	}
	return eval.Allow, controlsServiceAccounts(g.Rules)
}

// namespaceAccounts: the service accounts a grant reaches ("" namespace:
// cluster-wide), in a stable order.
func (b *builder) namespaceAccounts(g *model.RBACGrant) []*model.ServiceAccount {
	var out []*model.ServiceAccount
	for _, sa := range b.inv.ServiceAccounts {
		if sa.Cluster == g.Cluster && (g.Namespace == "" || sa.Namespace == g.Namespace) {
			out = append(out, sa)
		}
	}
	return out
}

// controlsServiceAccounts: create on pods or pods/exec (a pod runs as any
// service account of its namespace; exec runs in one), create on
// serviceaccounts/token (mints a token for any audience), or impersonate on
// serviceaccounts; with wildcards.
func controlsServiceAccounts(rules []model.RBACRule) bool {
	has := func(list []string, v string) bool { return slices.Contains(list, v) || slices.Contains(list, "*") }
	for _, r := range rules {
		if !has(r.APIGroups, "") || len(r.ResourceNames) > 0 {
			continue
		}
		creates := has(r.Verbs, "create") && (has(r.Resources, "pods") || has(r.Resources, "pods/exec") || has(r.Resources, "serviceaccounts/token"))
		if creates || has(r.Verbs, "impersonate") && has(r.Resources, "serviceaccounts") {
			return true
		}
	}
	return false
}

// irsa: a service account annotated with eks.amazonaws.com/role-arn gets a
// token for its audience, which it can present to every role whose trust
// allows its sub and aud and whose OIDC provider accepts the audience, not
// only the annotated one.
func (b *builder) irsa(sa *model.ServiceAccount) {
	if sa.RoleARN == "" {
		return
	}
	var defaults []string
	if slices.Contains(sa.Defaulted, model.DefaultIRSAAudience) {
		defaults = []string{model.DefaultIRSAAudience}
	}
	b.webIdentity(sa.ID, sa, []string{sa.Audience}, "irsa", defaults)
}

// webIdentity adds ASSUMES edges from a node holding a token of sa, for one
// of the audiences, to every role that accepts it.
func (b *builder) webIdentity(from model.ID, sa *model.ServiceAccount, audiences []string, sub string, defaults []string) {
	cluster, ok := b.clusters[sa.Cluster]
	if !ok {
		cluster = &model.Cluster{Name: sa.Cluster}
	}
	for _, role := range b.roles {
		trust, ok := b.trusts[role.ID()]
		if !ok {
			continue
		}
		verdict := eval.ImplicitDeny
		var used, why []string
		for _, aud := range audiences {
			holder := *sa
			holder.Audience = aud
			accepted, extra := b.accepted(cluster, role.Account(), aud)
			d := eval.Evaluate(IRSARequest(&holder, cluster, role.Identity(), role.Account(), b.opts.Partition), TrustPolicySet(trust))
			if v := both(d.Verdict, accepted); v.Grants() > verdict.Grants() {
				verdict, used, why = v, extra, append(evidence(&d), "audience "+aud)
			}
		}
		if grants(verdict) {
			b.edge(from, role.ID(), graph.Assumes, sub, &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
				e.Evidence = why
				e.Defaults = append(slices.Clone(defaults), used...)
				slices.Sort(e.Defaults)
			})
		}
	}
}

// accepted: STS takes a web identity token only when its aud is a client ID
// of the OIDC provider (IAM User Guide, "Create an OpenID Connect (OIDC)
// identity provider"). A provider in the input decides; without one,
// sts.amazonaws.com is the documented IRSA setup (a documented default) and
// any other audience is unknown.
func (b *builder) accepted(cluster *model.Cluster, account, aud string) (verdict eval.Verdict, defaults []string) {
	issuer := strings.TrimSuffix(strings.TrimPrefix(cluster.OIDCIssuer, "https://"), "/")
	if issuer == "" {
		return eval.Unknown, nil
	}
	arn := "arn:" + b.opts.Partition + ":iam::" + account + ":oidc-provider/" + issuer
	for _, p := range b.inv.OIDCProviders {
		if p.ARN != arn {
			continue
		}
		switch {
		case slices.Contains(p.ClientIDs, aud):
			return eval.Allow, nil
		case model.AnyUnresolved(p.ClientIDs):
			return eval.Unknown, nil
		}
		return eval.ImplicitDeny, nil
	}
	if aud == "sts.amazonaws.com" {
		return eval.Allow, []string{model.DefaultOIDCAudience}
	}
	return eval.Unknown, nil
}

// minted: a node that controls a service account (it reached it through
// RBAC, or holds the right itself) can get a token for it with any accepted
// audience (a pod with a projected token, or the TokenRequest API), and so
// assume every role that accepts its sub, with or without an annotation.
// "minted-self" edges may be used straight from the account's own
// Kubernetes token (it holds the right itself); "minted" ones only after an
// RBAC escalation (DESIGN.md §7.2).
func (b *builder) minted() {
	for _, sa := range b.inv.ServiceAccounts {
		self, isSelf := b.selfMinters[sa.ID]
		if !isSelf && !b.minters[sa.ID] {
			continue
		}
		sub := "minted"
		if isSelf {
			sub = "minted-self"
		}
		auds := b.audiences()
		b.webIdentity(sa.ID, sa, auds, sub, nil)
		if isSelf && self == eval.Unknown {
			b.downgrade(sa.ID, sub)
		}
	}
}

// downgrade makes the edges just added UNKNOWN: the right to mint rests on
// an RBAC role that is not in the input.
func (b *builder) downgrade(from model.ID, sub string) {
	b.g.EachFrom(b.node(from), func(e *graph.Edge) {
		if e.Kind == graph.Assumes && e.Sub == sub {
			e.Verdict, e.Confidence = eval.Unknown, graph.Low
		}
	})
}

// audiences an attacker can request: the client IDs of the providers in the
// input, and the documented sts.amazonaws.com.
func (b *builder) audiences() []string {
	out := []string{"sts.amazonaws.com"}
	for _, p := range b.inv.OIDCProviders {
		for _, id := range p.ClientIDs {
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	return out
}

// projected: a pod spec that projects a service account token with an
// audience gets that token without any annotation.
func (b *builder) projected() {
	for _, w := range b.inv.Workloads {
		auds := w.ProjectedAudiences()
		if len(auds) == 0 {
			continue
		}
		for _, sa := range b.inv.ServiceAccounts {
			if sa.Cluster == w.Cluster() && sa.Namespace == w.Namespace() && sa.Name == w.ServiceAccount() {
				b.webIdentity(w.ID(), sa, auds, "projected", nil)
			}
		}
	}
}

func (b *builder) podIdentity(a *model.PodIdentityAssociation) {
	sa := saID(a.Cluster, a.Namespace, a.ServiceAccount)
	role, ok := b.byARN[a.RoleARN]
	if _, known := b.g.Lookup(sa); !known || !ok {
		return
	}
	trust, ok := b.trusts[role.ID()]
	if !ok {
		return
	}
	cluster, ok := b.clusters[a.Cluster]
	if !ok {
		cluster = &model.Cluster{Name: a.Cluster}
	}
	r := PodIdentityAssume(a, cluster, trust, role.Account(), AgentInstalled(b.inv, a.Cluster))
	if grants(r.Verdict) {
		b.edge(sa, role.ID(), graph.Assumes, "pod-identity", &eval.Decision{Verdict: r.Verdict}, func(e *graph.Edge) {
			e.Evidence = []string{
				"Pod Identity association " + a.Source.String(),
				"sts:AssumeRole " + r.AssumeRole.String(), "sts:TagSession " + r.TagSession.String(),
			}
			e.Defaults = a.Defaulted
		})
	}
}
