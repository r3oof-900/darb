package live

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/k8s/manifests"
	"github.com/r3oof-900/clapa/internal/collect/k8sraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/normalize"
	normk8s "github.com/r3oof-900/clapa/internal/normalize/k8s"
	"github.com/r3oof-900/clapa/internal/safeio"
)

// For every scenario with manifests: the objects, served by a fake API
// server and collected live, normalize to the same inventory as the
// manifest scan (source positions aside).
func TestLiveMatchesManifests(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "tests", "fixtures", "*", "*", "k8s"))
	if err != nil {
		t.Fatal(err)
	}
	dirs = clusterDirs(dirs)
	checked := 0
	for _, dir := range dirs {
		name, _ := filepath.Rel(filepath.Join("..", "..", "..", "..", "tests", "fixtures"), dir)
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		mrec := &coverage.Recorder{}
		objs, err := manifests.Collect(context.Background(), &collect.Input{Root: dir, Path: ".", Limits: safeio.DefaultLimits()}, &manifests.Options{Cluster: "prod"}, mrec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if mrec.Count(coverage.KindParseError) > 0 {
			continue // a malformed-input scenario: nothing an API server would hold
		}
		typed, secrets := serve(objs)
		live, err := Collect(context.Background(), &Options{Cluster: "prod", Clients: &Clients{Typed: fake.NewClientset(typed...), Metadata: newMetadata(secrets...)}}, &coverage.Recorder{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, got := summarize(t, objs), summarize(t, live)
		if !slices.Equal(want, got) {
			t.Errorf("%s: live differs from manifests\n manifests %v\n live      %v", name, want, got)
		}
		checked++
	}
	if checked < 15 {
		t.Fatalf("only %d scenarios compared", checked)
	}
}

// clusterDirs: a k8s/ directory holding only k8s/<region>/ directories
// (scenario 18) is one cluster per directory.
func clusterDirs(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		var subs []string
		for _, e := range entries {
			if !e.IsDir() {
				subs = nil
				break
			}
			subs = append(subs, filepath.Join(d, e.Name()))
		}
		if len(subs) == 0 {
			out = append(out, d)
		}
		out = append(out, subs...)
	}
	return out
}

// serve returns the objects an API server would hold: Secrets as their
// metadata, ConfigMaps other than aws-auth left out (live reads aws-auth
// only, and the normalizer reads no other ConfigMap).
func serve(objs *k8sraw.Objects) (typed, secrets []runtime.Object) {
	for _, o := range objs.Items {
		switch v := o.Obj.(type) {
		case *corev1.Secret:
			secrets = append(secrets, &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: v.ObjectMeta})
		case *corev1.ConfigMap:
			if v.Namespace == "kube-system" && v.Name == "aws-auth" {
				typed = append(typed, o.Obj.DeepCopyObject())
			}
		default:
			typed = append(typed, o.Obj.DeepCopyObject())
		}
	}
	return typed, secrets
}

// summarize normalizes objs and describes every node and edge input
// without its source position.
func summarize(t *testing.T, objs *k8sraw.Objects) []string {
	t.Helper()
	b := normalize.NewBuilder()
	normk8s.Normalize(objs, b, &coverage.Recorder{})
	inv, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, w := range inv.Workloads {
		out = append(out, fmt.Sprintf("workload %s sa=%s host=%t automount=%s priv=%t aud=%v def=%v",
			w.ID(), w.ServiceAccount(), w.HostNetwork(), w.AutomountToken(), w.Privileged(), w.ProjectedAudiences(), w.Defaulted()))
	}
	for _, r := range inv.Resources {
		out = append(out, fmt.Sprintf("resource %s %s %v", r.Kind(), r.ARN(), r.Tags()))
	}
	for _, list := range []any{inv.ServiceAccounts, inv.RBAC, inv.Mappings, inv.NetworkPolicies, inv.Exposures} {
		v := reflect.ValueOf(list)
		for i := range v.Len() {
			out = append(out, withoutSource(v.Index(i).Elem()))
		}
	}
	slices.Sort(out)
	return out
}

// withoutSource prints v without its source position (exported Source or
// unexported source field).
func withoutSource(v reflect.Value) string {
	text := fmt.Sprintf("%s %+v", v.Type().Name(), v.Interface())
	return regexp.MustCompile(`(?i)source:\{[^}]*\}`).ReplaceAllString(text, "source:-")
}
