package live

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	metafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/r3oof-900/darb/internal/collect/k8sraw"
	"github.com/r3oof-900/darb/internal/coverage"
)

func om(ns, name string) metav1.ObjectMeta { return metav1.ObjectMeta{Namespace: ns, Name: name} }

func owned(m metav1.ObjectMeta, kind, name string) metav1.ObjectMeta { //nolint:gocritic // hugeParam: a copy is what the test wants.
	yes := true
	m.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: kind, Name: name, Controller: &yes}}
	return m
}

// secretMeta is a Secret as the metadata API returns it.
func secretMeta(ns, name string) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: om(ns, name)}
}

func newMetadata(objs ...runtime.Object) *metafake.FakeMetadataClient {
	s := metafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(s); err != nil {
		panic(err)
	}
	return metafake.NewSimpleMetadataClient(s, objs...)
}

func clusterObjects() []runtime.Object {
	replicas := int32(1)
	return []runtime.Object{
		&corev1.Namespace{ObjectMeta: om("", "payments")},
		&appsv1.Deployment{ObjectMeta: om("payments", "api"), Spec: appsv1.DeploymentSpec{Replicas: &replicas}},
		&appsv1.ReplicaSet{ObjectMeta: owned(om("payments", "api-7d9"), "Deployment", "api")},
		&corev1.Pod{ObjectMeta: owned(om("payments", "api-7d9-x1"), "ReplicaSet", "api-7d9")},
		&corev1.Pod{ObjectMeta: om("payments", "debug")},
		// Owned by a controller darb does not list (a custom resource): kept,
		// or the workload would vanish.
		&corev1.Pod{ObjectMeta: owned(om("payments", "canary-1"), "Rollout", "canary")},
		&corev1.ServiceAccount{ObjectMeta: om("payments", "api")},
		&rbacv1.Role{ObjectMeta: om("payments", "reader")},
		&rbacv1.RoleBinding{ObjectMeta: om("payments", "reader"), RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "reader"}},
		&rbacv1.ClusterRole{ObjectMeta: om("", "admin")},
		&corev1.ConfigMap{ObjectMeta: om("kube-system", "aws-auth"), Data: map[string]string{"mapRoles": "[]"}},
		&corev1.ConfigMap{ObjectMeta: om("payments", "settings"), Data: map[string]string{"x": "y"}},
	}
}

func collectAll(t *testing.T, c *Clients) (*k8sraw.Objects, *coverage.Recorder) {
	t.Helper()
	rec := &coverage.Recorder{}
	objs, err := Collect(context.Background(), &Options{Cluster: "prod", Clients: c, PageSize: 2}, rec)
	if err != nil {
		t.Fatal(err)
	}
	return objs, rec
}

func names(objs *k8sraw.Objects) []string {
	var out []string
	for _, o := range objs.Items {
		out = append(out, o.Kind+"/"+o.Namespace+"/"+o.Name)
	}
	return out
}

func TestCollectLists(t *testing.T) {
	c := &Clients{Typed: fake.NewClientset(clusterObjects()...), Metadata: newMetadata(secretMeta("payments", "db"))}
	objs, rec := collectAll(t, c)
	if rec.Len() != 0 {
		t.Fatalf("gaps %+v", rec.Gaps())
	}
	got := strings.Join(names(objs), " ")
	want := "ClusterRole//admin ConfigMap/kube-system/aws-auth Deployment/payments/api Namespace//payments Pod/payments/canary-1 Pod/payments/debug " +
		"Role/payments/reader RoleBinding/payments/reader Secret/payments/db ServiceAccount/payments/api"
	if got != want {
		t.Fatalf("objects\n got %s\nwant %s", got, want)
	}
	for _, o := range objs.Items {
		if o.Obj.GetObjectKind().GroupVersionKind().Kind != o.Kind || o.APIVersion == "" {
			t.Errorf("%s: type meta %v", o.Kind, o.Obj.GetObjectKind().GroupVersionKind())
		}
		if s, ok := o.Obj.(*corev1.Secret); ok && (s.Data != nil || s.StringData != nil) {
			t.Error("a Secret carries data")
		}
	}
}

// Every page is read (Limit/Continue), and a list that fails part-way keeps
// nothing of that kind.
func TestCollectPaginates(t *testing.T) {
	typed := fake.NewClientset()
	var limits []int64
	pages := map[string]*corev1.PodList{
		"":   {ListMeta: metav1.ListMeta{Continue: "p2"}, Items: []corev1.Pod{{ObjectMeta: om("a", "one")}}},
		"p2": {ListMeta: metav1.ListMeta{Continue: "p3"}, Items: []corev1.Pod{{ObjectMeta: om("a", "two")}}},
		"p3": {Items: []corev1.Pod{{ObjectMeta: om("b", "three")}}},
	}
	typed.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		la, _ := a.(k8stesting.ListActionImpl)
		o := la.ListOptions
		limits = append(limits, o.Limit)
		return true, pages[o.Continue], nil
	})
	objs, _ := collectAll(t, &Clients{Typed: typed, Metadata: newMetadata()})
	if got := strings.Join(names(objs), " "); got != "Pod/a/one Pod/a/two Pod/b/three" || len(limits) != 3 || limits[0] != 2 {
		t.Fatalf("pods %s, limits %v", got, limits)
	}

	typed = fake.NewClientset()
	typed.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if la, _ := a.(k8stesting.ListActionImpl); la.ListOptions.Continue == "p2" {
			return true, nil, apierrors.NewServerTimeout(schema.GroupResource{Resource: "pods"}, "list", 1)
		}
		return true, pages[""], nil
	})
	objs, rec := collectAll(t, &Clients{Typed: typed, Metadata: newMetadata()})
	if len(names(objs)) != 0 || rec.Count(coverage.KindTimeout) != 1 {
		t.Fatalf("partial list kept %v, gaps %+v", names(objs), rec.Gaps())
	}
}

func TestCollectForbidden(t *testing.T) {
	typed := fake.NewClientset(clusterObjects()...)
	forbid := func(resource string) k8stesting.ReactionFunc {
		return func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: resource}, "", errors.New("RBAC: access denied"))
		}
	}
	typed.PrependReactor("list", "roles", forbid("roles"))
	typed.PrependReactor("get", "configmaps", forbid("configmaps"))
	meta := newMetadata(secretMeta("payments", "db"))
	meta.PrependReactor("list", "secrets", forbid("secrets"))
	objs, rec := collectAll(t, &Clients{Typed: typed, Metadata: meta})
	apis := map[string]bool{}
	for _, g := range rec.Gaps() {
		if g.Kind != coverage.KindAccessDenied || g.Source != Name || g.Address != "prod" {
			t.Fatalf("gap %+v", g)
		}
		apis[g.API] = true
	}
	if len(apis) != 3 || !apis["list roles"] || !apis["list secrets (metadata)"] || !apis["get configmaps kube-system/aws-auth"] {
		t.Fatalf("gaps %v", apis)
	}
	for _, n := range names(objs) {
		if strings.HasPrefix(n, "Role/") || strings.HasPrefix(n, "Secret/") || strings.HasPrefix(n, "ConfigMap/") {
			t.Fatalf("%s collected", n)
		}
	}
}

func TestCollectNothing(t *testing.T) {
	typed := fake.NewClientset()
	typed.PrependReactor("*", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewUnauthorized("no credentials")
	})
	meta := newMetadata()
	meta.PrependReactor("*", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewUnauthorized("no credentials")
	})
	_, err := Collect(context.Background(), &Options{Cluster: "prod", Clients: &Clients{Typed: typed, Metadata: meta}}, &coverage.Recorder{})
	if !errors.Is(err, ErrNothingCollected) {
		t.Fatalf("err %v", err)
	}
}

func TestCollectCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Collect(ctx, &Options{Cluster: "prod", Clients: &Clients{Typed: fake.NewClientset(), Metadata: newMetadata()}}, &coverage.Recorder{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}
