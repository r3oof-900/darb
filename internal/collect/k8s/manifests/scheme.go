package manifests

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
)

// newSerializer builds a strict JSON serializer over a scheme holding only
// the API groups CLAPA analyses, so field semantics match the API server and
// unknown fields are reported (docs/DESIGN.md section 4.2).
func newSerializer() (*kjson.Serializer, error) {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, batchv1.AddToScheme, rbacv1.AddToScheme, networkingv1.AddToScheme,
	} {
		if err := add(s); err != nil {
			return nil, fmt.Errorf("%s: registering built-in API types: %w", Name, err)
		}
	}
	return kjson.NewSerializerWithOptions(kjson.DefaultMetaFactory, s, s, kjson.SerializerOptions{Strict: true}), nil
}

// supported lists the kinds CLAPA analyses (docs/DESIGN.md section 4.2).
func supported(kind string) bool {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet",
		"ServiceAccount", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding",
		"NetworkPolicy", "Service", "Ingress", "Namespace", "ConfigMap", "Secret":
		return true
	}
	return false
}
