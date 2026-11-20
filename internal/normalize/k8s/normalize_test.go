package k8s

import (
	"context"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/k8s/manifests"
	"github.com/r3oof-900/clapa/internal/collect/k8sraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
	"github.com/r3oof-900/clapa/internal/safeio"
)

func load(t *testing.T) (*model.Inventory, *coverage.Recorder) {
	t.Helper()
	rec := &coverage.Recorder{}
	objs, err := manifests.Collect(context.Background(), &collect.Input{Root: "testdata", Path: "all", Limits: safeio.DefaultLimits()},
		&manifests.Options{Cluster: "c1"}, rec)
	if err != nil {
		t.Fatal(err)
	}
	b := normalize.NewBuilder()
	Normalize(objs, b, rec)
	inv, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return inv, rec
}

func TestWorkloadsAndServiceAccounts(t *testing.T) {
	inv, _ := load(t)
	got := map[string]*model.Workload{}
	for _, w := range inv.Workloads {
		got[w.Identity()] = w
	}
	for _, kind := range []string{"Pod/lone", "StatefulSet/db", "DaemonSet/agent", "ReplicaSet/rs", "Job/once", "CronJob/nightly"} {
		k, name, _ := strings.Cut(kind, "/")
		if got["k8s:c1/web/"+k+"/"+name] == nil {
			t.Errorf("missing workload %s", kind)
		}
	}
	if got["k8s:c1/web/Pod/lone"].AutomountToken() != model.False {
		t.Error("a service account with automount disabled applies to its pods")
	}
	if got["k8s:c1/web/StatefulSet/db"].AutomountToken() != model.True {
		t.Error("the pod's own automountServiceAccountToken overrides the service account")
	}
	sas := map[string]*model.ServiceAccount{}
	for _, sa := range inv.ServiceAccounts {
		sas[sa.SubjectString()] = sa
	}
	if sas["system:serviceaccount:web:quiet"].AutomountToken != model.False || sas["system:serviceaccount:web:default"] == nil {
		t.Errorf("service accounts: %v", sas)
	}
	if sas["system:serviceaccount:web:default"].Audience != "sts.amazonaws.com" {
		t.Error("the implicit default service account gets the default audience")
	}
	var secret *model.Resource
	for _, r := range inv.Resources {
		if r.Kind() == model.KindK8sSecret {
			secret = r
		}
	}
	if secret == nil || secret.ARN() != "k8s:c1/web/Secret/creds" || secret.Tags()[0].Value != "secret" {
		t.Errorf("secret %+v", secret)
	}
}

func TestExposures(t *testing.T) {
	inv, rec := load(t)
	names := map[model.ID]string{}
	for _, w := range inv.Workloads {
		names[w.ID()] = w.Identity()
	}
	got := map[string]string{}
	for _, e := range inv.Exposures {
		got[names[e.Workload()]+" "+e.Via()] += e.Public().String() + ";"
	}
	want := map[string]string{
		"k8s:c1/web/StatefulSet/db Service/LoadBalancer":  "false;", // scheme: internal
		"k8s:c1/web/DaemonSet/agent Service/LoadBalancer": "false;", // LB controller defaults to internal
		"k8s:c1/web/ReplicaSet/rs Service/LoadBalancer":   "false;", // legacy internal annotation
		"k8s:c1/web/Pod/lone Service/LoadBalancer":        "true;",
		"k8s:c1/web/Job/once Service/NodePort":            "unknown;",
		"k8s:c1/web/CronJob/nightly Ingress":              "false;true;true;unknown;", // internal, internet-facing (rule + default backend), no annotation
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	gaps := gapText(rec)
	for _, w := range []string{"service has no selector", "ingress backend service nowhere is not in the input", "service account web/missing-sa is not in the input"} {
		if !strings.Contains(gaps, w) {
			t.Errorf("missing gap %q", w)
		}
	}
}

func TestRBACAndAWSAuth(t *testing.T) {
	inv, rec := load(t)
	grants := map[string]*model.RBACGrant{}
	for _, g := range inv.RBAC {
		grants[g.SubjectKind+":"+g.SubjectNamespace+"/"+g.SubjectName+"@"+g.Namespace] = g
	}
	admin := grants["Group:/ops@"]
	if admin == nil || admin.Unresolved != "" || admin.Rules[0].Verbs[0] != "*" {
		t.Errorf("cluster-admin is modelled: %+v", admin)
	}
	for key, want := range map[string]string{
		"ServiceAccount:web/quiet@web": "", // two bindings; checked below
		"User:/alice@web":              "aggregated",
	} {
		if g := grants[key]; g == nil || (want != "" && !strings.Contains(g.Unresolved, want)) {
			t.Errorf("%s: %+v", key, g)
		}
	}
	var unresolved []string
	for _, g := range inv.RBAC {
		if g.SubjectName == "quiet" {
			unresolved = append(unresolved, g.Unresolved)
		}
	}
	joined := strings.Join(unresolved, "|")
	if !strings.Contains(joined, "Role web/not-here is not in the input") || !strings.Contains(joined, "ClusterRole view is not in the input") {
		t.Errorf("unknown roles must give grants with unknown rules: %q", joined)
	}
	maps := map[string]*model.IdentityMapping{}
	for _, m := range inv.Mappings {
		maps[m.PrincipalARN] = m
	}
	if len(maps) != 3 || maps["arn:aws:iam::111122223333:role/admins"].Groups[0] != "system:masters" ||
		maps["arn:aws:iam::111122223333:user/alice"].Username != "alice" {
		t.Errorf("aws-auth mappings %+v", maps)
	}
	if !strings.Contains(gapText(rec), "built-in roles other than cluster-admin are not modelled") {
		t.Error("unmodelled built-in roles are reported")
	}
}

func TestMalformedAWSAuth(t *testing.T) {
	rec := &coverage.Recorder{}
	b := normalize.NewBuilder()
	n := &norm{cluster: "c1", b: b, rec: rec}
	n.mappings(&k8sraw.Object{Kind: "ConfigMap", Namespace: "kube-system", Name: "aws-auth"}, "mapRoles", "{not: [a list")
	if rec.Count(coverage.KindParseError) != 1 {
		t.Fatal("malformed mapRoles is reported")
	}
}

func gapText(rec *coverage.Recorder) string {
	var b strings.Builder
	all := rec.Gaps()
	for i := range all {
		b.WriteString(all[i].Detail + "\n")
	}
	return b.String()
}
