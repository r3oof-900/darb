package access

import (
	"slices"

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
	for _, a := range b.inv.PodIdentity {
		b.podIdentity(a)
	}
}

// rbac: a service account that may create pods (or exec into them) in a
// namespace can run code as that namespace's service accounts.
func (b *builder) rbac(g *model.RBACGrant) {
	if g.SubjectKind != "ServiceAccount" {
		return
	}
	from := saID(g.Cluster, g.SubjectNamespace, g.SubjectName)
	if _, ok := b.g.Lookup(from); !ok {
		return
	}
	verdict := eval.Unknown // the referenced role is not in the input: its rules are unknown
	if g.Unresolved == "" {
		if !createsPods(g.Rules) {
			return
		}
		verdict = eval.Allow
	}
	for key, accounts := range b.accounts {
		if g.Namespace != "" && key != g.Cluster+"/"+g.Namespace {
			continue
		}
		for _, sa := range accounts {
			if sa.Cluster == g.Cluster && sa.ID != from {
				b.edge(from, sa.ID, graph.CanEscalate, "rbac", &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
					e.Evidence = []string{"RBAC " + g.Source.String()}
				})
			}
		}
	}
}

// createsPods: create on pods, or create on pods/exec (exec into a pod runs
// as its service account), with wildcards.
func createsPods(rules []model.RBACRule) bool {
	for _, r := range rules {
		group := slices.Contains(r.APIGroups, "") || slices.Contains(r.APIGroups, "*")
		res := slices.Contains(r.Resources, "pods") || slices.Contains(r.Resources, "pods/exec") || slices.Contains(r.Resources, "*")
		verb := slices.Contains(r.Verbs, "create") || slices.Contains(r.Verbs, "*")
		if group && res && verb && len(r.ResourceNames) == 0 {
			return true
		}
	}
	return false
}

// irsa: a service account annotated with eks.amazonaws.com/role-arn gets an
// STS-audience token, which it can present to every role whose trust allows
// its sub and aud — not only the annotated one.
func (b *builder) irsa(sa *model.ServiceAccount) {
	if sa.RoleARN == "" {
		return
	}
	cluster, ok := b.clusters[sa.Cluster]
	if !ok {
		cluster = &model.Cluster{Name: sa.Cluster}
	}
	for _, role := range b.roles {
		trust, ok := b.trusts[role.ID()]
		if !ok {
			continue
		}
		req := IRSARequest(sa, cluster, role.Identity(), role.Account(), b.opts.Partition)
		if d := eval.Evaluate(req, TrustPolicySet(trust)); grants(d.Verdict) {
			b.edge(sa.ID, role.ID(), graph.Assumes, "irsa", &d, func(e *graph.Edge) {
				if slices.Contains(sa.Defaulted, model.DefaultIRSAAudience) {
					e.Defaults = []string{model.DefaultIRSAAudience}
				}
			})
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
