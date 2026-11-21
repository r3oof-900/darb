package access

import (
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/scoring"
)

// k8sSecretReads adds CAN_READ_PLAINTEXT[k8s] to a Kubernetes Secret from
// every subject whose RBAC may get, list or watch it (list and watch
// return the data too; Kubernetes, "Good practices for Kubernetes
// Secrets"). The API returns the value decoded, so there is no decrypt
// step. The edge needs the subject's Kubernetes credentials: the path
// search allows it only after the token or a mapping, never with the
// cloud identity alone (paths.allowed). Its one side is the RBAC rule.
func (b *builder) k8sSecretReads(j *model.Resource) {
	cluster, ns, name, ok := splitSecretIdentity(j.ARN())
	if !ok {
		return
	}
	for _, g := range b.inv.RBAC {
		if g.Cluster != cluster || g.Namespace != "" && g.Namespace != ns {
			continue
		}
		verdict := eval.Allow
		switch {
		case g.Unresolved != "":
			verdict = eval.Unknown // the role is not in the input
		case !readsSecret(g.Rules, name):
			continue
		}
		from, known := b.rbacSubject(g)
		if !known {
			continue
		}
		b.edge(from, j.ID(), graph.CanReadPlaintext, "k8s", &eval.Decision{Verdict: verdict}, func(e *graph.Edge) {
			e.Evidence = []string{"RBAC " + g.Source.String()}
			e.Fixes = []graph.Fix{{
				Side: graph.SideRBAC, Kind: graph.FixRevoke, Policy: "RBAC " + g.Source.String(),
				Cost: scoring.FixCost(graph.CanReadPlaintext, "k8s", graph.SideRBAC, graph.FixRevoke),
			}}
		})
	}
}

// rbacSubject is the node of a grant's subject: a service account in the
// input, a Kubernetes user or group, or an IAM principal (EKS access policy).
func (b *builder) rbacSubject(g *model.RBACGrant) (model.ID, bool) {
	switch g.SubjectKind {
	case "ServiceAccount":
		id := saID(g.Cluster, g.SubjectNamespace, g.SubjectName)
		_, ok := b.g.Lookup(id)
		return id, ok
	case "User", "Group":
		return b.k8sSubject(g.Cluster, g.SubjectKind, g.SubjectName), true
	case model.SubjectIAMPrincipal:
		if p := b.principalFor(g.SubjectName); p != nil {
			return p.ID(), true
		}
	}
	return "", false
}

// readsSecret: get, list or watch on secrets (core API group), for every
// name or for this one.
func readsSecret(rules []model.RBACRule, name string) bool {
	has := func(list []string, v string) bool { return slices.Contains(list, v) || slices.Contains(list, "*") }
	for _, r := range rules {
		if !has(r.APIGroups, "") || !has(r.Resources, "secrets") {
			continue
		}
		if len(r.ResourceNames) > 0 && !slices.Contains(r.ResourceNames, name) {
			continue
		}
		if has(r.Verbs, "get") || has(r.Verbs, "list") || has(r.Verbs, "watch") {
			return true
		}
	}
	return false
}

// splitSecretIdentity splits "k8s:{cluster key}/{namespace}/Secret/{name}";
// the cluster key may be an ARN ("...:cluster/prod").
func splitSecretIdentity(id string) (cluster, ns, name string, ok bool) {
	s, found := strings.CutPrefix(id, "k8s:")
	i := strings.LastIndex(s, "/Secret/")
	if !found || i < 0 {
		return "", "", "", false
	}
	head, name := s[:i], s[i+len("/Secret/"):]
	j := strings.LastIndex(head, "/")
	if j < 0 {
		return "", "", "", false
	}
	return head[:j], head[j+1:], name, true
}
