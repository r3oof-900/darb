package live

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// kind is one listed object kind: the kinds the manifest collector
// analyses (docs/DESIGN.md 4.2), except Secret (metadata only, secrets.go)
// and ConfigMap (aws-auth only).
type kind struct {
	gvk      schema.GroupVersionKind
	resource string
	list     func(ctx context.Context, c *Clients, o metav1.ListOptions) ([]runtime.Object, string, error)
}

// ptrs returns pointers to the list's items as runtime objects.
func ptrs[T any, PT interface {
	*T
	runtime.Object
}](items []T) []runtime.Object {
	out := make([]runtime.Object, len(items))
	for i := range items {
		out[i] = PT(&items[i])
	}
	return out
}

func gvk(group, version, k string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: group, Version: version, Kind: k}
}

// listFunc is a typed client's List.
type listFunc[PL any] func(ctx context.Context, o metav1.ListOptions) (PL, error)

// lister adapts a typed List (chosen from the clients by pick) to kind.list.
func lister[L any, PL interface {
	*L
	metav1.ListInterface
}, T any, PT interface {
	*T
	runtime.Object
}](pick func(c *Clients) listFunc[PL], items func(PL) []T) func(context.Context, *Clients, metav1.ListOptions) ([]runtime.Object, string, error) {
	return func(ctx context.Context, c *Clients, o metav1.ListOptions) ([]runtime.Object, string, error) {
		l, err := pick(c)(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return ptrs[T, PT](items(l)), l.GetContinue(), nil
	}
}

// kinds lists every kind; all are listed across namespaces.
func kinds() []kind {
	return []kind{
		{gvk("", "v1", "Namespace"), "namespaces", lister(
			func(c *Clients) listFunc[*corev1.NamespaceList] { return c.Typed.CoreV1().Namespaces().List },
			func(l *corev1.NamespaceList) []corev1.Namespace { return l.Items })},
		{gvk("", "v1", "Pod"), "pods", lister(
			func(c *Clients) listFunc[*corev1.PodList] { return c.Typed.CoreV1().Pods("").List },
			func(l *corev1.PodList) []corev1.Pod { return l.Items })},
		{gvk("", "v1", "ServiceAccount"), "serviceaccounts", lister(
			func(c *Clients) listFunc[*corev1.ServiceAccountList] {
				return c.Typed.CoreV1().ServiceAccounts("").List
			},
			func(l *corev1.ServiceAccountList) []corev1.ServiceAccount { return l.Items })},
		{gvk("", "v1", "Service"), "services", lister(
			func(c *Clients) listFunc[*corev1.ServiceList] { return c.Typed.CoreV1().Services("").List },
			func(l *corev1.ServiceList) []corev1.Service { return l.Items })},
		{gvk("apps", "v1", "Deployment"), "deployments", lister(
			func(c *Clients) listFunc[*appsv1.DeploymentList] { return c.Typed.AppsV1().Deployments("").List },
			func(l *appsv1.DeploymentList) []appsv1.Deployment { return l.Items })},
		{gvk("apps", "v1", "StatefulSet"), "statefulsets", lister(
			func(c *Clients) listFunc[*appsv1.StatefulSetList] { return c.Typed.AppsV1().StatefulSets("").List },
			func(l *appsv1.StatefulSetList) []appsv1.StatefulSet { return l.Items })},
		{gvk("apps", "v1", "DaemonSet"), "daemonsets", lister(
			func(c *Clients) listFunc[*appsv1.DaemonSetList] { return c.Typed.AppsV1().DaemonSets("").List },
			func(l *appsv1.DaemonSetList) []appsv1.DaemonSet { return l.Items })},
		{gvk("apps", "v1", "ReplicaSet"), "replicasets", lister(
			func(c *Clients) listFunc[*appsv1.ReplicaSetList] { return c.Typed.AppsV1().ReplicaSets("").List },
			func(l *appsv1.ReplicaSetList) []appsv1.ReplicaSet { return l.Items })},
		{gvk("batch", "v1", "Job"), "jobs", lister(
			func(c *Clients) listFunc[*batchv1.JobList] { return c.Typed.BatchV1().Jobs("").List },
			func(l *batchv1.JobList) []batchv1.Job { return l.Items })},
		{gvk("batch", "v1", "CronJob"), "cronjobs", lister(
			func(c *Clients) listFunc[*batchv1.CronJobList] { return c.Typed.BatchV1().CronJobs("").List },
			func(l *batchv1.CronJobList) []batchv1.CronJob { return l.Items })},
		{gvk("rbac.authorization.k8s.io", "v1", "Role"), "roles", lister(
			func(c *Clients) listFunc[*rbacv1.RoleList] { return c.Typed.RbacV1().Roles("").List },
			func(l *rbacv1.RoleList) []rbacv1.Role { return l.Items })},
		{gvk("rbac.authorization.k8s.io", "v1", "ClusterRole"), "clusterroles", lister(
			func(c *Clients) listFunc[*rbacv1.ClusterRoleList] { return c.Typed.RbacV1().ClusterRoles().List },
			func(l *rbacv1.ClusterRoleList) []rbacv1.ClusterRole { return l.Items })},
		{gvk("rbac.authorization.k8s.io", "v1", "RoleBinding"), "rolebindings", lister(
			func(c *Clients) listFunc[*rbacv1.RoleBindingList] { return c.Typed.RbacV1().RoleBindings("").List },
			func(l *rbacv1.RoleBindingList) []rbacv1.RoleBinding { return l.Items })},
		{gvk("rbac.authorization.k8s.io", "v1", "ClusterRoleBinding"), "clusterrolebindings", lister(
			func(c *Clients) listFunc[*rbacv1.ClusterRoleBindingList] {
				return c.Typed.RbacV1().ClusterRoleBindings().List
			},
			func(l *rbacv1.ClusterRoleBindingList) []rbacv1.ClusterRoleBinding { return l.Items })},
		{gvk("networking.k8s.io", "v1", "NetworkPolicy"), "networkpolicies", lister(
			func(c *Clients) listFunc[*networkingv1.NetworkPolicyList] {
				return c.Typed.NetworkingV1().NetworkPolicies("").List
			},
			func(l *networkingv1.NetworkPolicyList) []networkingv1.NetworkPolicy { return l.Items })},
		{gvk("networking.k8s.io", "v1", "Ingress"), "ingresses", lister(
			func(c *Clients) listFunc[*networkingv1.IngressList] { return c.Typed.NetworkingV1().Ingresses("").List },
			func(l *networkingv1.IngressList) []networkingv1.Ingress { return l.Items })},
	}
}
