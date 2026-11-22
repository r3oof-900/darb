package terraform

import (
	"testing"

	"github.com/r3oof-900/darb/internal/model"
)

// aws_eks_pod_identity_association: disable_session_tags defaults to false
// (EKS API › CreatePodIdentityAssociation), an unresolved value is unknown;
// target_role_arn is kept; aws_eks_addon is recorded.
// prodARN: references by cluster_name resolve to the cluster key, its ARN
// in the resource's account and region.
const prodARN = "arn:aws:eks:us-east-1:111122223333:cluster/prod"

func TestPodIdentityAssociation(t *testing.T) {
	inv := normalizeHCL(t, &Options{Account: "111122223333", Region: "us-east-1"}, map[string]string{"main.tf": `
variable "tags_off" {}
resource "aws_eks_pod_identity_association" "default" {
  cluster_name    = "prod"
  namespace       = "a"
  service_account = "sa"
  role_arn        = "arn:aws:iam::111122223333:role/a"
}
resource "aws_eks_pod_identity_association" "off" {
  cluster_name         = "prod"
  namespace            = "b"
  service_account      = "sa"
  role_arn             = "arn:aws:iam::111122223333:role/b"
  target_role_arn      = "arn:aws:iam::444455556666:role/target"
  disable_session_tags = true
}
resource "aws_eks_pod_identity_association" "var" {
  cluster_name         = "prod"
  namespace            = "c"
  service_account      = "sa"
  role_arn             = "arn:aws:iam::111122223333:role/c"
  disable_session_tags = var.tags_off
}
resource "aws_eks_addon" "agent" {
  cluster_name = "prod"
  addon_name   = "eks-pod-identity-agent"
}
`})
	want := map[string]struct {
		disabled model.Tri
		target   string
	}{
		"a": {model.False, ""},
		"b": {model.True, "arn:aws:iam::444455556666:role/target"},
		"c": {model.Unknown, ""},
	}
	if len(inv.PodIdentity) != len(want) {
		t.Fatalf("associations: %+v", inv.PodIdentity)
	}
	for _, a := range inv.PodIdentity {
		w := want[a.Namespace]
		if a.SessionTagsDisabled != w.disabled || a.TargetRoleARN != w.target || a.Cluster != prodARN || a.ServiceAccount != "sa" {
			t.Errorf("%s: %+v, want %+v", a.Namespace, a, w)
		}
	}
	if len(inv.Addons) != 1 || inv.Addons[0].Name != "eks-pod-identity-agent" || inv.Addons[0].Cluster != prodARN {
		t.Errorf("addons: %+v", inv.Addons)
	}
}
