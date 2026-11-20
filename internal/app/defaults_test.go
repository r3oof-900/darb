package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
)

// One test per row of the documented defaults (docs/DESIGN.md §4.7): an
// unstated setting takes its documented value and is marked as defaulted;
// a stated one is not. TestEveryDefaultIsTested keeps the table and these
// cases in step. Settings without a deterministic default stay unknown and
// are coverage gaps (TestNoDeterministicDefault).

const saManifest = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: payments
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: payments
spec:
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      serviceAccountName: api
      containers:
        - name: api
          image: registry.example.com/api:1
`

const statedManifest = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: payments
  annotations:
    eks.amazonaws.com/audience: custom
automountServiceAccountToken: true
---
apiVersion: v1
kind: Pod
metadata:
  name: api
  namespace: payments
spec:
  serviceAccountName: api
  automountServiceAccountToken: false
  hostNetwork: true
  containers:
    - name: api
      image: registry.example.com/api:1
      securityContext: {privileged: true}
`

func k8sOnly(in *Inputs) { in.K8sDirs = []K8sDir{{Path: "k8s", Cluster: "prod"}} }
func tfOnly(in *Inputs)  { in.TerraformDirs = []string{"terraform"} }

type defaultCase struct {
	key   string
	check func(t *testing.T)
}

func defaultCases() []defaultCase {
	return []defaultCase{
		{model.DefaultAutomountToken, func(t *testing.T) {
			inv := loadTree(t, map[string]string{"k8s/a.yaml": saManifest}, k8sOnly).Inventory
			w := inv.Workloads[0]
			if w.AutomountToken() != model.True || !slices.Contains(w.Defaulted(), model.DefaultAutomountToken) {
				t.Errorf("unstated: %s %v", w.AutomountToken(), w.Defaulted())
			}
			if sa := inv.ServiceAccounts[0]; sa.AutomountToken != model.True || !slices.Contains(sa.Defaulted, model.DefaultAutomountToken) {
				t.Errorf("service account: %s %v", sa.AutomountToken, sa.Defaulted)
			}
			w = loadTree(t, map[string]string{"k8s/a.yaml": statedManifest}, k8sOnly).Inventory.Workloads[0]
			if w.AutomountToken() != model.False || slices.Contains(w.Defaulted(), model.DefaultAutomountToken) {
				t.Errorf("the Pod's false wins over the service account's true: %s %v", w.AutomountToken(), w.Defaulted())
			}
		}},
		{model.DefaultHostNetwork, func(t *testing.T) {
			if w := loadTree(t, map[string]string{"k8s/a.yaml": saManifest}, k8sOnly).Inventory.Workloads[0]; w.HostNetwork() {
				t.Error("unstated hostNetwork is false")
			}
			if w := loadTree(t, map[string]string{"k8s/a.yaml": statedManifest}, k8sOnly).Inventory.Workloads[0]; !w.HostNetwork() {
				t.Error("stated hostNetwork: true")
			}
		}},
		{model.DefaultPrivileged, func(t *testing.T) {
			if w := loadTree(t, map[string]string{"k8s/a.yaml": saManifest}, k8sOnly).Inventory.Workloads[0]; w.Privileged() {
				t.Error("unstated privileged is false")
			}
			if w := loadTree(t, map[string]string{"k8s/a.yaml": statedManifest}, k8sOnly).Inventory.Workloads[0]; !w.Privileged() {
				t.Error("stated privileged: true")
			}
		}},
		{model.DefaultIRSAAudience, func(t *testing.T) {
			sa := loadTree(t, map[string]string{"k8s/a.yaml": saManifest}, k8sOnly).Inventory.ServiceAccounts[0]
			if sa.Audience != "sts.amazonaws.com" || !slices.Contains(sa.Defaulted, model.DefaultIRSAAudience) {
				t.Errorf("unstated: %q %v", sa.Audience, sa.Defaulted)
			}
			sa = loadTree(t, map[string]string{"k8s/a.yaml": statedManifest}, k8sOnly).Inventory.ServiceAccounts[0]
			if sa.Audience != "custom" || slices.Contains(sa.Defaulted, model.DefaultIRSAAudience) {
				t.Errorf("stated: %q %v", sa.Audience, sa.Defaulted)
			}
		}},
		{model.DefaultKeyRotationTF, func(t *testing.T) {
			inv := loadTree(t, map[string]string{"terraform/k.tf": `
resource "aws_kms_key" "unset" { description = "u" }
resource "aws_kms_key" "on" {
  description         = "o"
  enable_key_rotation = true
}`}, tfOnly).Inventory
			if len(inv.Resources) != 2 {
				t.Fatalf("keys: %d", len(inv.Resources))
			}
			for _, r := range inv.Resources {
				defaulted := slices.Contains(r.Defaulted(), model.DefaultKeyRotationTF)
				if !strings.HasSuffix(r.ARN(), "unset") && !strings.HasSuffix(r.ARN(), ".on") {
					t.Errorf("unexpected key %s", r.ARN())
				}
				switch {
				case strings.HasSuffix(r.ARN(), "unset") && (r.KeyRotation() != model.False || !defaulted):
					t.Errorf("unset: %s %v", r.KeyRotation(), r.Defaulted())
				case strings.HasSuffix(r.ARN(), ".on") && (r.KeyRotation() != model.True || defaulted):
					t.Errorf("stated: %s %v", r.KeyRotation(), r.Defaulted())
				}
			}
		}},
		{model.DefaultKeyPolicy, func(t *testing.T) {
			inv := loadTree(t, map[string]string{"terraform/k.tf": `
resource "aws_kms_key" "unset" { description = "u" }
resource "aws_kms_key" "stated" {
  description = "s"
  policy      = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::111122223333:root" }, Action = "kms:Decrypt", Resource = "*" }] })
}`}, tfOnly).Inventory
			got := map[string]string{}
			for _, p := range inv.Policies {
				got[p.Doc.ID()] = p.Default
			}
			if got["aws_kms_key.unset.policy"] != model.DefaultKeyPolicy || got["aws_kms_key.stated.policy"] != "" {
				t.Errorf("key policies: %v", got)
			}
		}},
		{model.DefaultS3Encryption, func(t *testing.T) {
			// A bucket without an encryption configuration is SSE-S3 by default
			// (decision 4 of the Phase 4 review).
			inv := loadTree(t, map[string]string{"terraform/b.tf": `
resource "aws_s3_bucket" "unset" { bucket = "unset" }
resource "aws_s3_bucket" "kms" { bucket = "kms" }
resource "aws_s3_bucket_server_side_encryption_configuration" "kms" {
  bucket = aws_s3_bucket.kms.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}`}, tfOnly).Inventory
			if len(inv.Resources) != 2 {
				t.Fatalf("buckets: %d", len(inv.Resources))
			}
			for _, r := range inv.Resources {
				defaulted := slices.Contains(r.Defaulted(), model.DefaultS3Encryption)
				switch r.ARN() {
				default:
					t.Errorf("unexpected bucket %s", r.ARN())
				case "arn:aws:s3:::unset":
					if r.Encryption().Type != "AES256" || !defaulted {
						t.Errorf("unset: %+v %v", r.Encryption(), r.Defaulted())
					}
				case "arn:aws:s3:::kms":
					if r.Encryption().Type != "aws:kms" || r.Encryption().KeyARN != "" || defaulted {
						t.Errorf("stated: %+v %v", r.Encryption(), r.Defaulted())
					}
				}
			}
		}},
		{model.DefaultPodIdentitySTags, func(t *testing.T) {
			inv := loadTree(t, map[string]string{"terraform/p.tf": `
resource "aws_eks_pod_identity_association" "a" {
  cluster_name    = "prod"
  namespace       = "payments"
  service_account = "api"
  role_arn        = "arn:aws:iam::111122223333:role/r"
}`}, tfOnly).Inventory
			if a := inv.PodIdentity[0]; a.SessionTagsDisabled != model.False || !slices.Contains(a.Defaulted, model.DefaultPodIdentitySTags) {
				t.Errorf("unset: %s %v", a.SessionTagsDisabled, a.Defaulted)
			}
		}},
		{model.DefaultUnsetRoleBindings, func(t *testing.T) {
			inv := loadTree(t, map[string]string{"terraform/r.tf": roleHCL}, tfOnly).Inventory
			if len(inv.Policies) != 0 {
				t.Errorf("a role without managed_policy_arns or inline_policy gets no policy: %d", len(inv.Policies))
			}
		}},
	}
}

func TestDocumentedDefaults(t *testing.T) {
	for _, c := range defaultCases() {
		t.Run(c.key, c.check)
	}
}

func TestEveryDefaultIsTested(t *testing.T) {
	tested := map[string]bool{}
	for _, c := range defaultCases() {
		tested[c.key] = true
	}
	for _, d := range model.DocumentedDefaults() {
		if !tested[d.Key] {
			t.Errorf("documented default %s has no test", d.Key)
		}
		if !strings.HasPrefix(d.Reference, "https://") || d.Quote == "" || d.Value == "" {
			t.Errorf("documented default %s needs a reference, quote and value", d.Key)
		}
		if got, ok := model.LookupDefault(d.Key); !ok || got != d {
			t.Errorf("LookupDefault(%s)", d.Key)
		}
	}
	if len(tested) != len(model.DocumentedDefaults()) {
		t.Errorf("%d tests for %d defaults", len(tested), len(model.DocumentedDefaults()))
	}
	if _, ok := model.LookupDefault("no.such.default"); ok {
		t.Error("unknown key")
	}
}

// IMDS and S3 Block Public Access have no deterministic default: unknown,
// and reported.
func TestNoDeterministicDefault(t *testing.T) {
	l := loadTree(t, map[string]string{"terraform/n.tf": `
resource "aws_s3_bucket" "b" { bucket = "b" }
resource "aws_eks_node_group" "ng" {
  cluster_name    = "prod"
  node_group_name = "ng"
  node_role_arn   = "arn:aws:iam::111122223333:role/node"
}`}, tfOnly)
	if ng := l.Inventory.NodeGroups[0]; ng.HTTPTokens != "" {
		t.Errorf("IMDS: %q", ng.HTTPTokens)
	}
	for _, r := range l.Inventory.Resources {
		if r.S3().RestrictPublicBuckets != model.Unknown {
			t.Errorf("Block Public Access: %s", r.S3().RestrictPublicBuckets)
		}
	}
	want := map[string]bool{"IMDS settings": false, "Block Public Access": false}
	for i := range l.Gaps {
		for k := range want {
			if l.Gaps[i].Kind == coverage.KindUnresolved && strings.Contains(l.Gaps[i].Detail, k) {
				want[k] = true
			}
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("no gap for %s: %+v", k, l.Gaps)
		}
	}
}
