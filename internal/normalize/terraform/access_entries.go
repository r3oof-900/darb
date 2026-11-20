package terraform

import (
	"strings"

	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
)

// accessEntry: aws_eks_access_entry maps an IAM principal to a Kubernetes
// user name and groups, which bind through the cluster's own RBAC (EKS User
// Guide › "Create access entries": "Create Kubernetes RoleBinding or
// ClusterRoleBinding objects ... that specify the group name as a subject").
func (n *norm) accessEntry(r *tfraw.Resource) {
	get := func(k string) string { s, _ := n.str(r.Root, attr(r, k)); return s }
	m := &model.IdentityMapping{Cluster: get("cluster_name"), PrincipalARN: get("principal_arn"), Username: get("user_name")}
	if v := attr(r, "kubernetes_groups"); v != nil && v.Kind != tfraw.KNull && !v.Computed() {
		for _, item := range listItems(v) {
			g, _ := n.str(r.Root, item)
			m.Groups = append(m.Groups, g)
		}
	}
	if v := attr(r, "user_name"); v == nil || v.Kind == tfraw.KNull || v.Computed() {
		// EKS generates the user name; bindings to it cannot be matched.
		m.Username = ""
	}
	m.Source = src(r)
	n.b.AddMapping(m)
}

// accessPolicy: aws_eks_access_policy_association gives the principal the
// Kubernetes permissions of an EKS access policy, cluster-wide or in the
// listed namespaces (EKS User Guide › "Access policy permissions").
func (n *norm) accessPolicy(r *tfraw.Resource) {
	get := func(k string) string { s, _ := n.str(r.Root, attr(r, k)); return s }
	policy := get("policy_arn")
	rules, known := accessPolicyRules(policy)
	namespaces := []string{""}
	for _, scope := range r.Attrs.Blocks("access_scope") {
		if t, _ := n.str(r.Root, valueOf(scope, "type")); t == "namespace" {
			namespaces = nil
			if v, ok := scope.Get("namespaces"); ok {
				for _, item := range listItems(v) {
					ns, _ := n.str(r.Root, item)
					namespaces = append(namespaces, ns)
				}
			}
		}
	}
	unresolved := ""
	if !known {
		unresolved = "access policy " + policy + " is not modelled"
		n.gap(coverage.KindNotModelled, r, unresolved+"; its Kubernetes permissions are unknown")
	}
	for _, ns := range namespaces {
		n.b.AddRBAC(&model.RBACGrant{
			Cluster: get("cluster_name"), Namespace: ns, SubjectKind: model.SubjectIAMPrincipal, SubjectName: get("principal_arn"),
			Rules: rules, Unresolved: unresolved, Source: src(r),
		})
	}
}

// accessPolicyRules: the escalation-relevant rules of the EKS access
// policies, as the access policy permissions page lists them.
func accessPolicyRules(policyARN string) ([]model.RBACRule, bool) {
	name := policyARN[strings.LastIndex(policyARN, "/")+1:]
	read := []model.RBACRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list", "watch"}}}
	pods := model.RBACRule{APIGroups: []string{""}, Resources: []string{"pods", "pods/exec"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}}
	switch name {
	case "AmazonEKSClusterAdminPolicy":
		return []model.RBACRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}, true
	case "AmazonEKSAdminPolicy":
		return append(read, pods, model.RBACRule{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, Verbs: []string{"impersonate"}}), true
	case "AmazonEKSEditPolicy":
		return append(read, pods), true
	case "AmazonEKSViewPolicy", "AmazonEKSAdminViewPolicy":
		return read, true
	}
	return nil, false
}
