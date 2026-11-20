package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/terraform/hclstatic"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/managedpolicies"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
	"github.com/r3oof-900/clapa/internal/safeio"
)

// Unknown parts of ARNs (account, region, name) must reach the evaluator as
// unresolved, so a literal ARN in a policy gives UNKNOWN, not a definite
// "no" that silently hides a path (docs/DESIGN.md section 4.6). Each case
// goes from HCL through the collector and normalizer to the evaluator.

const roleHCL = `
resource "aws_iam_role" "app" {
  name               = "app"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
`

// normalizeHCL writes files into a temp dir and normalizes them.
func normalizeHCL(t *testing.T, opts *Options, files map[string]string) *model.Inventory {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := &coverage.Recorder{}
	m, err := hclstatic.Collect(context.Background(), &collect.Input{Root: dir, Path: ".", Limits: safeio.DefaultLimits()}, rec)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := managedpolicies.Load()
	if err != nil {
		t.Fatal(err)
	}
	b := normalize.NewBuilder()
	Normalize(m, opts, mp, b, rec)
	inv, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// sessionOf is a session of the role named name, in whatever account the
// normalizer gave it (possibly unresolved).
func sessionOf(t *testing.T, inv *model.Inventory, name string) match.RequestPrincipal {
	t.Helper()
	for _, p := range inv.Principals {
		if p.Kind() == model.KindIAMRole && filepath.Base(p.Identity()) == name {
			return match.RequestPrincipal{
				Kind: match.KindAssumedRole, ARN: "arn:aws:sts::" + p.Account() + ":assumed-role/" + name + "/s",
				Account: p.Account(), SourceARN: p.Identity(),
			}
		}
	}
	t.Fatalf("role %s not found", name)
	return match.RequestPrincipal{}
}

func resourceOfKind(t *testing.T, inv *model.Inventory, kind model.NodeKind) *model.Resource {
	t.Helper()
	for _, r := range inv.Resources {
		if r.Kind() == kind {
			return r
		}
	}
	t.Fatalf("no %s", kind)
	return nil
}

// policySet gathers the identity policies of the role and the resource
// policies of the resource from the inventory.
func policySet(inv *model.Inventory, role string, res *model.Resource, required bool) *eval.PolicySet {
	ps := &eval.PolicySet{ResourcePolicyRequired: required}
	for _, p := range inv.Policies {
		switch p.Target {
		case model.NewID(model.KindIAMRole, role):
			ps.Identity = append(ps.Identity, p.Doc)
		case res.ID():
			ps.Resource = append(ps.Resource, p.Doc)
		}
	}
	return ps
}

func decide(t *testing.T, inv *model.Inventory, action, resourceSuffix string, kind model.NodeKind, required bool) eval.Verdict {
	t.Helper()
	caller := sessionOf(t, inv, "app")
	res := resourceOfKind(t, inv, kind)
	req := &eval.Request{
		Principal: caller, Action: action, Resource: res.ARN() + resourceSuffix, ResourceAccount: res.Account(),
		Context: condition.NewContext(&condition.Input{Default: condition.StateAbsent}),
	}
	return eval.Evaluate(req, policySet(inv, caller.SourceARN, res, required)).Verdict
}

// (a) A bucket whose name is not resolved, and a policy with a literal ARN.
func TestUnresolvedBucketName(t *testing.T) {
	files := map[string]string{"main.tf": roleHCL + `
variable "env" {}
resource "aws_s3_bucket" "pii" {
  bucket = "${var.env}-pii"
}
resource "aws_iam_role_policy" "read" {
  role   = aws_iam_role.app.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::prod-pii/*" }] })
}
`}
	known := &Options{Account: "111122223333", Region: "us-east-1"}
	if v := decide(t, normalizeHCL(t, known, files), "s3:GetObject", "/report.csv", model.KindS3Bucket, false); v != eval.Unknown {
		t.Errorf("(a) unresolved bucket name: %s, want UNKNOWN", v)
	}
	// (d) Resolving the variable decides it.
	files["terraform.tfvars"] = `env = "prod"`
	if v := decide(t, normalizeHCL(t, known, files), "s3:GetObject", "/report.csv", model.KindS3Bucket, false); v != eval.Allow {
		t.Errorf("(d) env = prod: %s, want ALLOW", v)
	}
	files["terraform.tfvars"] = `env = "dev"`
	if v := decide(t, normalizeHCL(t, known, files), "s3:GetObject", "/report.csv", model.KindS3Bucket, false); v != eval.ImplicitDeny {
		t.Errorf("(d) env = dev: %s, want IMPLICIT_DENY", v)
	}
}

// (b) Unknown account, and an identity policy naming the key with a literal account.
func TestUnknownAccountKMS(t *testing.T) {
	files := map[string]string{"main.tf": roleHCL + `
resource "aws_kms_key" "k" {
  description = "k"
  policy      = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::111122223333:root" }, Action = "kms:*", Resource = "*" }] })
}
resource "aws_iam_role_policy" "decrypt" {
  role   = aws_iam_role.app.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "kms:Decrypt", Resource = "arn:aws:kms:us-east-1:111122223333:key/*" }] })
}
`}
	for _, c := range []struct {
		name string
		opts *Options
		want eval.Verdict
	}{
		{"(b) account unknown", &Options{Region: "us-east-1"}, eval.Unknown},
		{"(d) account configured", &Options{Account: "111122223333", Region: "us-east-1"}, eval.Allow},
		{"(d) another account configured", &Options{Account: "999999999999", Region: "us-east-1"}, eval.ImplicitDeny},
	} {
		if v := decide(t, normalizeHCL(t, c.opts, files), "kms:Decrypt", "", model.KindKMSKey, true); v != c.want {
			t.Errorf("%s: %s, want %s", c.name, v, c.want)
		}
	}
}

// (c) Unknown account, and a bucket policy naming the role with a literal account.
func TestUnknownAccountResourcePolicy(t *testing.T) {
	files := map[string]string{"main.tf": roleHCL + `
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::111122223333:role/app" }, Action = "s3:GetObject", Resource = "arn:aws:s3:::data/*" }] })
}
`}
	for _, c := range []struct {
		name string
		opts *Options
		want eval.Verdict
	}{
		{"(c) account unknown", &Options{Region: "us-east-1"}, eval.Unknown},
		{"(d) account configured", &Options{Account: "111122223333", Region: "us-east-1"}, eval.Allow},
		{"(d) another account configured", &Options{Account: "999999999999", Region: "us-east-1"}, eval.ImplicitDeny},
	} {
		if v := decide(t, normalizeHCL(t, c.opts, files), "s3:GetObject", "/k", model.KindS3Bucket, false); v != c.want {
			t.Errorf("%s: %s, want %s", c.name, v, c.want)
		}
	}
}

// A name_prefix keeps its known prefix and an unresolved suffix; a resource
// created without any name gets a pending ID (AWS generates it).
func TestGeneratedNames(t *testing.T) {
	inv := normalizeHCL(t, &Options{Account: "111122223333", Region: "us-east-1"}, map[string]string{"main.tf": `
resource "aws_s3_bucket" "prefixed" {
  bucket_prefix = "logs-"
}
resource "aws_s3_bucket" "anonymous" {}
`})
	got := map[string]bool{}
	for _, r := range inv.Resources {
		got[r.ARN()] = true
	}
	for _, want := range []string{
		"arn:aws:s3:::logs-${clapa:unresolved:aws_s3_bucket.prefixed.generated_suffix}",
		"arn:aws:s3:::tf-aws_s3_bucket.anonymous",
	} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
}
