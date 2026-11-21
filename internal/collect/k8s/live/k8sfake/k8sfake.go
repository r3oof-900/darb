// Package k8sfake serves Kubernetes objects from client-go's fake API
// servers, for tests of the commands that read live clusters. It never
// opens a connection.
package k8sfake

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	metafake "k8s.io/client-go/metadata/fake"

	"github.com/r3oof-900/clapa/internal/collect/k8s/live"
)

// Clients serves objs: Secrets as their metadata, everything else typed.
func Clients(objs ...runtime.Object) *live.Clients {
	var typed, secrets []runtime.Object
	for _, o := range objs {
		if s, ok := o.(*corev1.Secret); ok {
			secrets = append(secrets, &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: s.ObjectMeta})
			continue
		}
		typed = append(typed, o)
	}
	scheme := metafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		panic(err) // registering the meta types into a new scheme cannot fail
	}
	return &live.Clients{Typed: fake.NewClientset(typed...), Metadata: metafake.NewSimpleMetadataClient(scheme, secrets...)}
}

// Workload is a namespace, a service account annotated with an IRSA role
// (roleARN "" for none) and a Deployment that runs as it.
func Workload(namespace, name, roleARN string) []runtime.Object {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	if roleARN != "" {
		sa.Annotations = map[string]string{"eks.amazonaws.com/role-arn": roleARN}
	}
	labels := map[string]string{"app": name}
	return []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
		sa,
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: labels},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: labels},
					Spec:       corev1.PodSpec{ServiceAccountName: name, Containers: []corev1.Container{{Name: name, Image: "registry.example.com/" + name + ":1"}}},
				},
			},
		},
	}
}
