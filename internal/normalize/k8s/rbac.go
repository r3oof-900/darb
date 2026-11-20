package k8s

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"

	"github.com/r3oof-900/clapa/internal/collect/k8sraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
)

// rbac resolves every (Cluster)RoleBinding to the rules of the role it
// references. A role that is not in the input, or an aggregated ClusterRole,
// yields a grant with unknown rules instead of being dropped. Of the
// built-in roles only cluster-admin is modelled exactly (Kubernetes ›
// "Using RBAC Authorization" › "User-facing roles").
func (n *norm) rbac(items []*k8sraw.Object) {
	roles := map[string][]rbacv1.PolicyRule{}        // "ns/name"
	clusterRoles := map[string][]rbacv1.PolicyRule{} // name
	aggregated := map[string]bool{}
	for _, o := range items {
		switch r := o.Obj.(type) {
		case *rbacv1.Role:
			roles[o.Namespace+"/"+o.Name] = r.Rules
		case *rbacv1.ClusterRole:
			clusterRoles[o.Name] = r.Rules
			aggregated[o.Name] = r.AggregationRule != nil
		}
	}
	if _, defined := clusterRoles["cluster-admin"]; !defined {
		clusterRoles["cluster-admin"] = []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}
	}
	for _, o := range items {
		switch b := o.Obj.(type) {
		case *rbacv1.RoleBinding:
			rules, why := lookupRole(b.RoleRef, o.Namespace, roles, clusterRoles, aggregated)
			n.grant(o, o.Namespace, b.Subjects, rules, why)
		case *rbacv1.ClusterRoleBinding:
			rules, why := lookupRole(b.RoleRef, "", roles, clusterRoles, aggregated)
			n.grant(o, "", b.Subjects, rules, why)
		}
	}
}

func lookupRole(ref rbacv1.RoleRef, ns string, roles, clusterRoles map[string][]rbacv1.PolicyRule, aggregated map[string]bool) (rules []rbacv1.PolicyRule, why string) {
	if ref.Kind == "Role" {
		if found, ok := roles[ns+"/"+ref.Name]; ok {
			return found, ""
		}
		return nil, "Role " + ns + "/" + ref.Name + " is not in the input"
	}
	rules, ok := clusterRoles[ref.Name]
	switch {
	case !ok:
		return nil, "ClusterRole " + ref.Name + " is not in the input (built-in roles other than cluster-admin are not modelled)"
	case aggregated[ref.Name]:
		return nil, "ClusterRole " + ref.Name + " is aggregated; aggregation is not modelled"
	}
	return rules, ""
}

func (n *norm) grant(o *k8sraw.Object, ns string, subjects []rbacv1.Subject, rules []rbacv1.PolicyRule, why string) {
	if why != "" {
		n.gap(coverage.KindUnresolved, o, why)
	}
	converted := make([]model.RBACRule, 0, len(rules))
	for _, r := range rules {
		converted = append(converted, model.RBACRule{
			APIGroups: slices.Clone(r.APIGroups), Resources: slices.Clone(r.Resources),
			Verbs: slices.Clone(r.Verbs), ResourceNames: slices.Clone(r.ResourceNames),
		})
	}
	for _, s := range subjects {
		subjectNS := s.Namespace
		if s.Kind == rbacv1.ServiceAccountKind && subjectNS == "" {
			subjectNS = o.Namespace // a RoleBinding's SA subject defaults to the binding's namespace
		}
		n.b.AddRBAC(&model.RBACGrant{
			Cluster: n.cluster, Namespace: ns, SubjectKind: s.Kind, SubjectNamespace: subjectNS, SubjectName: s.Name,
			Rules: converted, Unresolved: why, Source: loc(o),
		})
	}
}

// awsAuth reads kube-system/aws-auth (EKS User Guide › "Grant IAM users and
// roles access to Kubernetes APIs" › aws-auth ConfigMap).
func (n *norm) awsAuth(items []*k8sraw.Object) {
	for _, o := range items {
		cm, ok := o.Obj.(*corev1.ConfigMap)
		if !ok || o.Namespace != "kube-system" || o.Name != "aws-auth" {
			continue
		}
		for _, key := range []string{"mapRoles", "mapUsers"} {
			n.mappings(o, key, cm.Data[key])
		}
	}
}

func (n *norm) mappings(o *k8sraw.Object, key, data string) {
	if data == "" {
		return
	}
	var entries []struct {
		RoleARN  string   `json:"rolearn"`
		UserARN  string   `json:"userarn"`
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	}
	if err := yaml.Unmarshal([]byte(data), &entries); err != nil {
		n.gap(coverage.KindParseError, o, "aws-auth "+key+": "+err.Error())
		return
	}
	for _, e := range entries {
		principal := e.RoleARN
		if key == "mapUsers" {
			principal = e.UserARN
		}
		n.b.AddMapping(&model.IdentityMapping{
			Cluster: n.cluster, PrincipalARN: principal, Username: e.Username, Groups: slices.Clone(e.Groups), Source: loc(o),
		})
	}
}
