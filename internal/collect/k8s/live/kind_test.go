//go:build integration

package live

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/k8s/manifests"
	"github.com/r3oof-900/clapa/internal/collect/k8sraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/safeio"
)

// The live collector against a kind cluster (.github/workflows/
// integration.yml). The test refuses an API server that is not on this
// machine. It applies scenario manifests as the cluster admin, then reads
// the cluster as a service account bound to exactly the ClusterRole of
// docs/PERMISSIONS.md.
func TestIntegrationKind(t *testing.T) {
	kubeContext := os.Getenv("CLAPA_KIND_CONTEXT")
	if kubeContext == "" {
		t.Skip("CLAPA_KIND_CONTEXT is not set")
	}
	admin, err := KubeconfigREST("", kubeContext, false)
	if err != nil {
		t.Fatal(err)
	}
	if u, perr := url.Parse(admin.Host); perr != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		t.Fatalf("refusing API server %q: the integration test runs against a local kind cluster only", admin.Host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fixtures := filepath.Join("..", "..", "..", "..", "tests", "fixtures")
	var want []*k8sraw.Objects
	for _, s := range []string{"01_classic/vulnerable/k8s", "08_rbac_create_pods/vulnerable/k8s", "09_hostnetwork_imds/vulnerable/k8s"} {
		objs, merr := manifests.Collect(ctx, &collect.Input{Root: filepath.Join(fixtures, filepath.FromSlash(s)), Path: ".", Limits: safeio.DefaultLimits()},
			&manifests.Options{Cluster: "kind"}, &coverage.Recorder{})
		if merr != nil {
			t.Fatal(merr)
		}
		apply(ctx, t, admin, objs)
		want = append(want, objs)
	}
	typed, err := kubernetes.NewForConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "db"}, StringData: map[string]string{"password": "dummy"}}
	if _, cerr := typed.CoreV1().Secrets("payments").Create(ctx, secret, metav1.CreateOptions{}); cerr != nil && !apierrors.IsAlreadyExists(cerr) {
		t.Fatal(err)
	}

	reader := readerConfig(ctx, t, admin, typed)
	clients, err := NewClients(reader)
	if err != nil {
		t.Fatal(err)
	}
	rec := &coverage.Recorder{}
	got, err := Collect(ctx, &Options{Cluster: "kind", Clients: clients, PageSize: 50}, rec)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Len() != 0 {
		t.Fatalf("the ClusterRole of docs/PERMISSIONS.md is not enough: %+v", rec.Gaps())
	}
	live := summarize(t, got)
	for _, objs := range want {
		for _, item := range summarize(t, objs) {
			if !slices.Contains(live, item) {
				t.Errorf("collected live, missing or different:\n %s", item)
			}
		}
	}
	found := false
	for _, o := range got.Items {
		if s, ok := o.Obj.(*corev1.Secret); ok && s.Namespace == "payments" && s.Name == "db" {
			found = true
			if s.Data != nil || s.StringData != nil {
				t.Fatal("a Secret's data was received")
			}
		}
	}
	if !found {
		t.Fatal("the Secret's metadata was not listed")
	}
}

// apply creates the objects (namespaces first), as the cluster admin.
func apply(ctx context.Context, t *testing.T, cfg *rest.Config, objs *k8sraw.Objects) {
	t.Helper()
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	items := slices.Clone(objs.Items)
	slices.SortStableFunc(items, func(a, b *k8sraw.Object) int {
		return map[bool]int{true: 0, false: 1}[a.Kind == "Namespace"] - map[bool]int{true: 0, false: 1}[b.Kind == "Namespace"]
	})
	namespaces := map[string]bool{}
	for _, o := range items {
		if o.Namespace != "" && !namespaces[o.Namespace] {
			namespaces[o.Namespace] = true
			ns := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": o.Namespace}}}
			if _, err := dyn.Resource(corev1.SchemeGroupVersion.WithResource("namespaces")).Create(ctx, ns, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
				t.Fatal(err)
			}
		}
		content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o.Obj)
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{Object: content}
		gvk := o.Obj.GetObjectKind().GroupVersionKind()
		m, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			t.Fatalf("%s: %v", o.Kind, err)
		}
		var res dynamic.ResourceInterface = dyn.Resource(m.Resource)
		if o.Namespace != "" {
			res = dyn.Resource(m.Resource).Namespace(o.Namespace)
		}
		if _, err := res.Create(ctx, u, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("%s %s/%s: %v", o.Kind, o.Namespace, o.Name, err)
		}
	}
}

// readerConfig: a service account bound to the ClusterRole of
// docs/PERMISSIONS.md, and a short-lived token for it.
func readerConfig(ctx context.Context, t *testing.T, admin *rest.Config, typed kubernetes.Interface) *rest.Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "PERMISSIONS.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest1, _ := strings.Cut(string(data), "```yaml")
	block, _, _ := strings.Cut(rest1, "```")
	var role rbacv1.ClusterRole
	if derr := yaml.NewYAMLOrJSONDecoder(strings.NewReader(block), 4096).Decode(&role); derr != nil {
		t.Fatal(derr)
	}
	ignore := func(_ any, err error) {
		t.Helper()
		if err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	ignore(typed.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "clapa"}}, metav1.CreateOptions{}))
	ignore(typed.CoreV1().ServiceAccounts("clapa").Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "reader"}}, metav1.CreateOptions{}))
	ignore(typed.RbacV1().ClusterRoles().Create(ctx, &role, metav1.CreateOptions{}))
	ignore(typed.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "clapa-read-only"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: role.Name},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "clapa", Name: "reader"}},
	}, metav1.CreateOptions{}))
	expiry := int64(600)
	tok, err := typed.CoreV1().ServiceAccounts("clapa").CreateToken(ctx, "reader", &authv1.TokenRequest{Spec: authv1.TokenRequestSpec{ExpirationSeconds: &expiry}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return &rest.Config{Host: admin.Host, BearerToken: tok.Status.Token, TLSClientConfig: rest.TLSClientConfig{CAData: admin.CAData}}
}
