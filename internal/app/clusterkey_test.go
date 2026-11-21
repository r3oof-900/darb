package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
	"github.com/r3oof-900/clapa/internal/safeio"
)

const (
	euw1Prod = "arn:aws:eks:eu-west-1:111122223333:cluster/prod"
	use1Prod = "arn:aws:eks:us-east-1:111122223333:cluster/prod"
)

func twoProd(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`version: 1
clusters:
  - {name: prod, account: "111122223333", region: eu-west-1}
  - {name: prod, account: "111122223333", region: us-east-1}
  - {name: dev, account: "111122223333", region: eu-west-1}
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestClusterKeyResolution(t *testing.T) {
	l := &loader{in: &Inputs{Config: twoProd(t)}, b: newBuilderForTest()}
	for name, want := range map[string]string{euw1Prod: euw1Prod, "dev": "arn:aws:eks:eu-west-1:111122223333:cluster/dev", "staging": "staging"} {
		if got, err := l.clusterKey(name); err != nil || got != want {
			t.Errorf("%q: %q, %v", name, got, err)
		}
	}
	for _, name := range []string{"prod", ""} {
		_, err := l.clusterKey(name)
		if !errors.Is(err, config.ErrInvalid) || !errors.Is(err, ErrAmbiguousCluster) {
			t.Errorf("%q: %v", name, err)
		}
	}
	if _, err := l.clusterKey("prod"); err == nil || !strings.Contains(err.Error(), euw1Prod) || !strings.Contains(err.Error(), use1Prod) {
		t.Errorf("the error lists the ARNs to choose from: %v", err)
	}
	one := &loader{in: &Inputs{Config: &config.Config{Clusters: []config.Cluster{{Name: "prod", Account: "111122223333", Region: "us-east-1"}}}}, b: newBuilderForTest()}
	if got, err := one.clusterKey(""); err != nil || got != use1Prod {
		t.Errorf("no name, one cluster: %q %v", got, err)
	}
	none := &loader{in: &Inputs{Config: config.Default()}, b: newBuilderForTest()}
	if got, err := none.clusterKey(""); err != nil || got != model.DefaultClusterName {
		t.Errorf("no name, no cluster: %q %v", got, err)
	}
	// A name only Terraform or AWS describes resolves to that cluster.
	b := newBuilderForTest()
	b.AddCluster(&model.Cluster{Name: "tf", ARN: "arn:aws:eks:ap-south-1:111122223333:cluster/tf"})
	if got, err := (&loader{in: &Inputs{Config: config.Default()}, b: b}).clusterKey("tf"); err != nil || got != "arn:aws:eks:ap-south-1:111122223333:cluster/tf" {
		t.Errorf("tf: %q %v", got, err)
	}
}

// A scan of two clusters named prod with manifests that name only "prod"
// is a configuration error, never a guess.
func TestAmbiguousManifestCluster(t *testing.T) {
	dir := t.TempDir()
	in := &Inputs{Root: dir, Config: twoProd(t), Limits: safeio.DefaultLimits(), K8sDirs: []K8sDir{{Path: ".", Cluster: "prod"}}}
	if _, err := Load(context.Background(), in); !errors.Is(err, ErrAmbiguousCluster) {
		t.Fatalf("err %v", err)
	}
}

func TestResolveIdentities(t *testing.T) {
	for id, want := range map[string][2]string{
		"k8s:prod/payments/Deployment/api":         {"prod", "payments/Deployment/api"},
		"k8s:" + euw1Prod + "/payments/Pod/x":      {euw1Prod, "payments/Pod/x"},
		"k8s:" + euw1Prod + "//Namespace/payments": {euw1Prod, "/Namespace/payments"},
	} {
		c, rest, ok := splitK8sIdentity(id)
		if !ok || c != want[0] || rest != want[1] {
			t.Errorf("%s: %q %q %v", id, c, rest, ok)
		}
	}
	for _, bad := range []string{"arn:aws:iam::1:role/x", "k8s:prod", "k8s:arn:aws:eks:eu-west-1:1:nodegroup", "k8s:arn:aws:eks:eu-west-1:1:cluster/prod"} {
		if _, _, ok := splitK8sIdentity(bad); ok {
			t.Errorf("%s accepted", bad)
		}
	}
	inv := &model.Inventory{Clusters: []*model.Cluster{{Name: "prod", ARN: euw1Prod}, {Name: "dev", ARN: "arn:aws:eks:eu-west-1:111122223333:cluster/dev"}}}
	cfg := &config.Config{IntendedAccess: []config.IntendedAccess{
		{Principal: "k8s:dev/a/Deployment/x"}, {Principal: "k8s:" + euw1Prod + "/a/Deployment/x"}, {Principal: "k8s:other/a/Deployment/x"}, {Principal: "arn:aws:iam::1:role/r"},
	}}
	got, err := resolveIdentities(inv, cfg)
	if err != nil || got[0].Principal != "k8s:arn:aws:eks:eu-west-1:111122223333:cluster/dev/a/Deployment/x" ||
		got[1].Principal != cfg.IntendedAccess[1].Principal || got[2].Principal != "k8s:other/a/Deployment/x" || got[3].Principal != "arn:aws:iam::1:role/r" {
		t.Fatalf("%v %+v", err, got)
	}
	if cfg.IntendedAccess[0].Principal != "k8s:dev/a/Deployment/x" {
		t.Fatal("the configuration was modified")
	}
	inv.Clusters = append(inv.Clusters, &model.Cluster{Name: "prod", ARN: use1Prod})
	cfg.IntendedAccess = []config.IntendedAccess{{Principal: "k8s:prod/a/Deployment/x"}}
	if _, err := resolveIdentities(inv, cfg); !errors.Is(err, ErrAmbiguousCluster) {
		t.Fatalf("ambiguous: %v", err)
	}
}

func newBuilderForTest() *normalize.Builder { return normalize.NewBuilder() }
