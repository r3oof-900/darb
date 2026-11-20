package terraform

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/terraform/plan"
	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/managedpolicies"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
	"github.com/r3oof-900/clapa/internal/safeio"
)

func normalizePlan(t *testing.T, root, file, configDir string) (*model.Inventory, *coverage.Recorder) {
	t.Helper()
	rec := &coverage.Recorder{}
	m, err := plan.Collect(context.Background(), &collect.Input{Root: root, Path: file, Limits: safeio.DefaultLimits()}, &plan.Options{ConfigDir: configDir}, rec)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := managedpolicies.Load()
	if err != nil {
		t.Fatal(err)
	}
	b := normalize.NewBuilder()
	Normalize(m, &Options{Account: "111122223333", Region: "us-east-1"}, mp, b, rec)
	inv, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return inv, rec
}

// Real plans (Terraform 1.17.1) of scenario 13: a for_each policy whose role
// is aws_iam_role.r[each.key].id, or [each.value].id over toset(...) with the
// configuration given, is attached to its own instance. A map source, or no
// configuration, does not say which instance: the policy may apply to each,
// so UNKNOWN for every role, never ALLOW for one and IMPLICIT_DENY for the
// others, and never dropped.
func TestForEachRoleSelection(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "tests", "fixtures", "13_module_for_each", "vulnerable")
	planTestdata := filepath.Join("..", "..", "collect", "terraform", "plan", "testdata")
	for _, c := range []struct {
		name, root, configDir string
		want                  eval.Verdict
		gap                   bool
	}{
		{"each.key", filepath.Join(planTestdata, "for_each_key"), "", eval.Allow, false},
		{"each.value of toset(...)", fixture, "terraform", eval.Allow, false},
		{"each.value without configuration", fixture, "", eval.Unknown, true},
		{"each.value of a map", filepath.Join(planTestdata, "for_each_map"), "terraform", eval.Unknown, true},
	} {
		inv, rec := normalizePlan(t, c.root, "plan.json", c.configDir)
		bucket := resourceOfKind(t, inv, model.KindS3Bucket)
		for _, name := range []string{"reader-etl", "reader-bi", "reader-ml"} {
			caller := sessionOf(t, inv, name)
			req := &eval.Request{
				Principal: caller, Action: "s3:GetObject", Resource: bucket.ARN() + "/report.csv", ResourceAccount: bucket.Account(),
				Context: condition.NewContext(&condition.Input{Default: condition.StateAbsent}),
			}
			if v := eval.Evaluate(req, policySet(inv, caller.SourceARN, bucket, false)).Verdict; v != c.want {
				t.Errorf("%s: %s reading PII = %s, want %s", c.name, name, v, c.want)
			}
		}
		found := false
		for _, g := range rec.Gaps() {
			found = found || strings.Contains(g.Detail, "selected by each.value")
			if strings.Contains(g.Detail, "attached role is not defined") {
				t.Errorf("%s: policy dropped: %s", c.name, g.Detail)
			}
		}
		if found != c.gap {
			t.Errorf("%s: selection gap reported = %v, want %v", c.name, found, c.gap)
		}
	}
}

// The each.key and each.value forms of scenario 13 give exactly the same
// roles and policy attachments.
func TestForEachKeyAndValueAgree(t *testing.T) {
	attachments := func(inv *model.Inventory) []string {
		var out []string
		for _, p := range inv.Policies {
			s := string(p.Target) + " " + p.Doc.ID()
			for _, st := range p.Doc.Statements() {
				acts, _ := st.Actions()
				res, _ := st.Resources()
				s += " " + st.Effect().String() + strings.Join(acts, ",") + strings.Join(res, ",") + strconv.Itoa(len(st.Conditions()))
			}
			out = append(out, s)
		}
		for _, p := range inv.Principals {
			out = append(out, p.Identity())
		}
		return out
	}
	key, _ := normalizePlan(t, filepath.Join("..", "..", "collect", "terraform", "plan", "testdata", "for_each_key"), "plan.json", "")
	value, _ := normalizePlan(t, filepath.Join("..", "..", "..", "tests", "fixtures", "13_module_for_each", "vulnerable"), "plan.json", "terraform")
	a, b := attachments(key), attachments(value)
	if strings.Join(a, " | ") != strings.Join(b, " | ") || len(a) != 6 {
		t.Errorf("each.key: %s; each.value: %s", strings.Join(a, " | "), strings.Join(b, " | "))
	}
}

// The uncertain copy keeps every element of every statement and adds only
// the selection condition.
func TestOnlyIfSelected(t *testing.T) {
	inv := normalizeHCL(t, &Options{Account: "1", Region: "r"}, map[string]string{"main.tf": `
resource "aws_s3_bucket" "b" {
  bucket = "b"
}
resource "aws_s3_bucket_policy" "b" {
  bucket = aws_s3_bucket.b.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "N", Effect = "Deny", NotPrincipal = { AWS = "arn:aws:iam::1:root" }, NotAction = "s3:Get*", NotResource = "arn:aws:s3:::b/x",
      Condition = { Bool = { "aws:SecureTransport" = "false" } } },
    { Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*" },
  ] })
}
`})
	var d *model.PolicyDocument
	for _, p := range inv.Policies {
		if p.Doc.Kind() == model.PolicyResource && p.Doc.ID() == "aws_s3_bucket_policy.b" {
			d = p.Doc
		}
	}
	if d == nil {
		t.Fatal("bucket policy not found")
	}
	got := (&norm{b: normalize.NewBuilder()}).onlyIfSelected(d, model.UnresolvedPlaceholder("k")).Statements()
	deny, allow := got[0], got[1]
	acts, negA := deny.Actions()
	res, negR := deny.Resources()
	_, negP := deny.Principal()
	if deny.Sid() != "N" || deny.Effect() != model.EffectDeny || acts[0] != "s3:Get*" || !negA || res[0] != "arn:aws:s3:::b/x" || !negR || !negP {
		t.Errorf("negated statement changed: %+v", deny)
	}
	if c := deny.Conditions(); len(c) != 2 || c[1].Key() != model.UnresolvedPlaceholder("k") {
		t.Errorf("conditions: %+v", c)
	}
	if p, neg := allow.Principal(); neg || !p.Wildcard() || len(allow.Conditions()) != 1 {
		t.Errorf("allow statement: %+v", allow)
	}
}

// An unknown inline_policy or managed_policy_arns adds an unknown policy only
// when the configuration sets it; the provider-computed value of an
// unconfigured attribute adds nothing (AWS provider › aws_iam_role).
func TestComputedPolicyAttributes(t *testing.T) {
	trust := tfraw.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	computed := &tfraw.Value{Kind: tfraw.KUnknownAfterApply, Reason: tfraw.ReasonComputed}
	configured := &tfraw.Value{Kind: tfraw.KUnknownAfterApply}
	for _, c := range []struct {
		name            string
		inline, arns    *tfraw.Value
		unknownPolicies int
	}{
		{"both computed", computed, computed, 0},
		{"inline configured, unknown", configured, computed, 1},
		{"managed_policy_arns configured, unknown", computed, configured, 1},
		{"dynamic inline_policy (static)", tfraw.Unresolved("dynamic block", "", tfraw.Pos{}), computed, 1},
	} {
		attrs := tfraw.NewObject()
		attrs.Set("name", tfraw.String("app"))
		attrs.Set("assume_role_policy", trust)
		attrs.Set("inline_policy", c.inline)
		attrs.Set("managed_policy_arns", c.arns)
		m := &tfraw.Module{Resources: []*tfraw.Resource{{
			Address: "aws_iam_role.app", Mode: "managed", Type: "aws_iam_role", Name: "app", Root: "plan.json", Attrs: attrs,
		}}}
		mp, err := managedpolicies.Load()
		if err != nil {
			t.Fatal(err)
		}
		b := normalize.NewBuilder()
		Normalize(m, &Options{Account: "111122223333", Region: "us-east-1"}, mp, b, &coverage.Recorder{})
		inv, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		if got := len(inv.Policies); got != c.unknownPolicies {
			t.Errorf("%s: %d attached policies, want %d", c.name, got, c.unknownPolicies)
		}
		for _, p := range inv.Policies {
			acts, _ := p.Doc.Statements()[0].Actions()
			if !model.AnyUnresolved(acts) {
				t.Errorf("%s: %s must be an unknown policy", c.name, p.Doc.ID())
			}
		}
	}
}
