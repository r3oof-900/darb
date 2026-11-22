package access

import (
	"strings"

	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/model"
)

// Built-in group whose members are cluster administrators without any RBAC
// binding (Kubernetes › "Using RBAC Authorization", default roles).
const systemMasters = "system:masters"

// k8sSubject is the node of a Kubernetes user or group.
func (b *builder) k8sSubject(cluster, kind, name string) model.ID {
	identity := model.K8sIdentity(cluster, "", kind, name)
	nodeKind := model.KindK8sUser
	if kind == "Group" {
		nodeKind = model.KindK8sGroup
	}
	id := model.NewID(nodeKind, identity)
	b.g.Node(id, nodeKind, identity)
	return id
}

// mappings adds MAPS_TO from IAM principals to the Kubernetes user and
// groups they are mapped to (aws-auth, access entries), then the RBAC
// escalation edges of users, groups and IAM principals (access policies).
// An aws-auth rolearn carries no path (EKS User Guide › "aws-auth"), so a
// role matches by account and name.
func (b *builder) mappings() {
	for _, m := range b.inv.Mappings {
		p := b.principalFor(m.PrincipalARN)
		if p == nil {
			continue
		}
		mapTo := func(kind, name string) {
			to := b.k8sSubject(m.Cluster, kind, name)
			b.edge(p.ID(), to, graph.MapsTo, kind, &eval.Decision{Verdict: eval.Allow}, func(e *graph.Edge) {
				e.Evidence = []string{"mapping " + m.Source.String()}
			})
		}
		if m.Username != "" && !strings.Contains(m.Username, "{{") {
			mapTo("User", m.Username)
		}
		for _, g := range m.Groups {
			mapTo("Group", g)
			if g == systemMasters {
				b.rbacFrom(b.k8sSubject(m.Cluster, "Group", g), &model.RBACGrant{
					Cluster: m.Cluster, Rules: []model.RBACRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}, Source: m.Source,
				})
			}
		}
	}
	for _, g := range b.inv.RBAC {
		switch g.SubjectKind {
		case "User", "Group":
			b.rbacFrom(b.k8sSubject(g.Cluster, g.SubjectKind, g.SubjectName), g)
		case model.SubjectIAMPrincipal:
			if p := b.principalFor(g.SubjectName); p != nil {
				b.rbacFrom(p.ID(), g)
			}
		}
	}
}

// principalFor finds a principal by ARN, or a role by account and name when
// the ARN carries no path.
func (b *builder) principalFor(arn string) *model.Principal {
	if p, ok := b.byARN[arn]; ok {
		return p
	}
	account, name, ok := roleParts(arn)
	if !ok {
		return nil
	}
	for _, r := range b.roles {
		if a, n, ok := roleParts(r.Identity()); ok && a == account && n == name {
			return r
		}
	}
	return nil
}

// roleParts splits arn:<p>:iam::<account>:role/<path/>name.
func roleParts(arn string) (account, name string, ok bool) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[2] != "iam" || !strings.HasPrefix(parts[5], "role/") {
		return "", "", false
	}
	return parts[4], parts[5][strings.LastIndex(parts[5], "/")+1:], true
}
