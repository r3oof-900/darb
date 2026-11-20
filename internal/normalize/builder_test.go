package normalize

import (
	"errors"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/model"
)

// TestDuplicateDefinitionsAreErrors: docs/DESIGN.md section 5 — never
// "keep first, drop second"; both locations are named.
func TestDuplicateDefinitionsAreErrors(t *testing.T) {
	b := NewBuilder()
	a := model.FileLocation("a/main.tf", 3, 9, "aws_iam_role.app")
	c := model.FileLocation("b/main.tf", 1, 4, "aws_iam_role.app")
	b.AddPrincipal(model.NewPrincipal(model.KindIAMRole, "arn:aws:iam::111122223333:role/app", "111122223333", &a))
	b.AddPrincipal(model.NewPrincipal(model.KindIAMRole, "arn:aws:iam::111122223333:role/app", "111122223333", &c))
	_, err := b.Build()
	if !errors.Is(err, ErrDuplicate) || !strings.Contains(err.Error(), "a/main.tf:3-9") || !strings.Contains(err.Error(), "b/main.tf:1-4") {
		t.Fatalf("got %v", err)
	}
	// The same name in two accounts is not a duplicate (scenario 14).
	b = NewBuilder()
	b.AddPrincipal(model.NewPrincipal(model.KindIAMRole, "arn:aws:iam::111122223333:role/app", "111122223333", &a))
	b.AddPrincipal(model.NewPrincipal(model.KindIAMRole, "arn:aws:iam::444455556666:role/app", "444455556666", &c))
	if _, err := b.Build(); err != nil {
		t.Fatal(err)
	}
}

func TestBuilderSortsEverything(t *testing.T) {
	b := NewBuilder()
	s := model.FileLocation("f", 1, 1, "")
	for _, n := range []string{"b", "a"} {
		b.AddResource(model.NewResource(&model.ResourceInput{Kind: model.KindS3Bucket, ARN: "arn:aws:s3:::" + n, Source: s}))
		b.AddWorkload(model.NewWorkload(&model.WorkloadInput{Cluster: "c", Namespace: "ns", Kind: "Pod", Name: n, Source: s}))
		b.AddServiceAccount(&model.ServiceAccount{ID: model.NewID(model.KindK8sServiceAcct, n), Cluster: "c", Namespace: "ns", Name: n, Source: s})
		b.AddCluster(&model.Cluster{Name: n, Source: s})
		b.AddPodIdentity(&model.PodIdentityAssociation{Cluster: "c", Namespace: "ns", ServiceAccount: n})
		b.AddNodeGroup(&model.NodeGroup{Cluster: "c", Name: n})
		b.AddRBAC(&model.RBACGrant{Cluster: "c", SubjectKind: "User", SubjectName: n})
		b.AddMapping(&model.IdentityMapping{Cluster: "c", PrincipalARN: n})
		b.AddExposure(model.NewNetworkExposure(model.ID(n), "Ingress", model.True, &s))
	}
	b.AddCluster(&model.Cluster{Name: "a", Source: s}) // duplicate cluster definition
	if _, err := b.Build(); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate cluster: %v", err)
	}
	b.errs = nil
	inv, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if inv.Clusters[0].Name != "a" || inv.PodIdentity[0].ServiceAccount != "a" || inv.NodeGroups[0].Name != "a" ||
		inv.RBAC[0].SubjectName != "a" || inv.Mappings[0].PrincipalARN != "a" || inv.Exposures[0].Workload() != "a" {
		t.Errorf("not sorted: %+v", inv)
	}
	if inv.Resources[0].ARN() > inv.Resources[1].ARN() && inv.Resources[0].ID() > inv.Resources[1].ID() {
		t.Error("resources must be sorted by ID")
	}
}
