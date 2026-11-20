package manifests

import (
	"context"
	"strconv"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/safeio"
)

func TestCollectManifests(t *testing.T) {
	rec := &coverage.Recorder{}
	objs, err := Collect(context.Background(), &collect.Input{Root: "testdata", Path: "m", Limits: safeio.DefaultLimits()},
		&Options{Cluster: "prod"}, rec)
	if err != nil {
		t.Fatal(err)
	}
	if objs.Cluster != "prod" || len(objs.Items) != 3 {
		t.Fatalf("got %d objects: %+v", len(objs.Items), objs.Items)
	}
	dep, svc, sa := objs.Items[0], objs.Items[1], objs.Items[2] // sorted by kind: Deployment, Service, ServiceAccount
	if d, ok := dep.Obj.(*appsv1.Deployment); !ok || d.Spec.Template.Spec.ServiceAccountName != "api" || dep.Pos.Line != 9 {
		t.Errorf("deployment %+v", dep)
	}
	if s, ok := sa.Obj.(*corev1.ServiceAccount); !ok || s.Annotations["eks.amazonaws.com/role-arn"] == "" ||
		sa.Pos.File != "m/app.yaml" || sa.Pos.Line != 1 || sa.Namespace != "payments" {
		t.Errorf("service account %+v", sa)
	}
	if s, ok := svc.Obj.(*corev1.Service); !ok || s.Spec.Type != corev1.ServiceTypeLoadBalancer || svc.Pos.File != "m/nested/svc.json" {
		t.Errorf("service %+v", svc)
	}
	var gaps []string
	for _, g := range rec.Gaps() {
		gaps = append(gaps, string(g.Kind)+" "+g.File+":"+strconv.Itoa(g.Line)+" "+g.Detail)
	}
	all := strings.Join(gaps, "\n")
	for _, want := range []string{
		`unsupported m/app.yaml:9 Deployment api: strict decoding error: unknown field "spec.template.spec.containers[0].bogusField"`, // object kept
		"unsupported m/app.yaml:29 unsupported kind example.com/v1 Widget",
		"unsupported m/app.yaml:33 kind PersistentVolume is not analysed",
		"parse-error m/broken.yaml:3",
		"parse-error m/bomb.yaml:1", // alias expansion bomb: refused, scan continues
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing gap %q in:\n%s", want, all)
		}
	}
}

func TestMissingDirectory(t *testing.T) {
	_, err := Collect(context.Background(), &collect.Input{Root: "testdata", Path: "none", Limits: safeio.DefaultLimits()}, &Options{}, &coverage.Recorder{})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestDocumentLimits(t *testing.T) {
	deep := strings.Repeat("a:\n  ", 0)
	for i := range 70 {
		deep += strings.Repeat("  ", i) + "k:\n"
	}
	rec := &coverage.Recorder{}
	s, err := newSerializer()
	if err != nil {
		t.Fatal(err)
	}
	d := &decoder{rec: rec, limits: safeio.Limits{MaxFileBytes: 1 << 20, MaxDepth: 64}, serializer: s}
	if got := d.file("deep.yaml", []byte(deep)); len(got) != 0 || !strings.Contains(rec.Gaps()[0].Detail, "exceeds limits") {
		t.Fatalf("deep document: %v %+v", got, rec.Gaps())
	}
	if yamlErrorLine(errNoLine{}) != 0 {
		t.Error("an error without a line number")
	}
}

type errNoLine struct{}

func (errNoLine) Error() string { return "boom" }
