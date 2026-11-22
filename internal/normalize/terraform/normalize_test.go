package terraform

import (
	"context"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/collect"
	"github.com/r3oof-900/darb/internal/collect/terraform/hclstatic"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/eval/condition"
	"github.com/r3oof-900/darb/internal/eval/match"
	"github.com/r3oof-900/darb/internal/managedpolicies"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/normalize"
	"github.com/r3oof-900/darb/internal/safeio"
)

func load(t *testing.T, opts *Options) (inv *model.Inventory, gapsText string) {
	t.Helper()
	rec := &coverage.Recorder{}
	m, err := hclstatic.Collect(context.Background(), &collect.Input{Root: "testdata", Path: "all", Limits: safeio.DefaultLimits()}, rec)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := managedpolicies.Load()
	if err != nil {
		t.Fatal(err)
	}
	b := normalize.NewBuilder()
	Normalize(m, opts, mp, b, rec)
	inv, err = b.Build()
	if err != nil {
		t.Fatal(err)
	}
	var gaps strings.Builder
	all := rec.Gaps()
	for i := range all {
		gaps.WriteString(all[i].Address + ": " + all[i].Detail + "\n")
	}
	return inv, gaps.String()
}

func policiesOf(inv *model.Inventory, target string) map[string]*model.PolicyDocument {
	out := map[string]*model.PolicyDocument{}
	for _, p := range append(append([]*model.AttachedPolicy{}, inv.Policies...), inv.Boundaries...) {
		if p.Target == model.NewID(model.KindIAMRole, target) {
			out[p.Doc.ID()] = p.Doc
		}
	}
	return out
}

func statements(d *model.PolicyDocument) string {
	var b strings.Builder
	for _, s := range d.Statements() {
		a, _ := s.Actions()
		r, _ := s.Resources()
		b.WriteString(s.Effect().String() + " " + strings.Join(a, ",") + " " + strings.Join(r, ",") + ";")
	}
	return b.String()
}

func TestRolePoliciesAndManagedPolicies(t *testing.T) {
	inv, gaps := load(t, &Options{})
	role := "arn:aws:iam::${darb:unresolved:account_of_all}:role/svc/app" // the account is unknown: no provider pin, no option
	if inv.Principals[0].Identity() != role {
		t.Fatalf("role identity %q", inv.Principals[0].Identity())
	}
	ps := policiesOf(inv, role)
	for id, want := range map[string]string{
		"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess":               "Allow s3:Get*",      // from the vendored snapshot
		"arn:aws:iam::aws:policy/NotInTheSnapshot":                     "${darb:unresolved:", // not guessed
		"arn:aws:iam::999999999999:policy/elsewhere":                   "${darb:unresolved:", // not in the input
		"aws_iam_role.app.inline_policy[0](inline-unknown)":            "${darb:unresolved:", // policy = var.extra_policy, unresolved
		"arn:aws:iam::aws:policy/AdministratorAccess":                  "Allow * *",          // the boundary
		"aws_iam_role_policy.oidc_ref":                                 "oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/XYZ",
		"arn:aws:iam::${darb:unresolved:account_of_all}:policy/broken": "${darb:unresolved:", // malformed JSON
	} {
		d, ok := ps[id]
		if !ok || !strings.Contains(statements(d), want) {
			t.Errorf("%s: %v %q", id, ok, func() string {
				if d == nil {
					return ""
				}
				return statements(d)
			}())
		}
	}
	custom := ps["arn:aws:iam::${darb:unresolved:account_of_all}:policy/custom"]
	if custom == nil || !strings.Contains(statements(custom), "secret:db-password-tfpend") || !strings.Contains(statements(custom), "parameter/app/token") {
		t.Fatalf("customer managed policy with resolved references: %v", custom)
	}
	for _, want := range []string{
		"account unknown", "AWS managed policy arn:aws:iam::aws:policy/NotInTheSnapshot is not in the vendored snapshot",
		"attached role is not defined in the input", "source_policy_documents is not modelled",
		"bucket is not defined in the input", "OIDC issuer of cluster c is unknown", "IMDS settings of node group bare are unknown",
		"aws_iam_policy.broken: arn:aws:iam::${darb:unresolved:account_of_all}:policy/broken:",
	} {
		if !strings.Contains(gaps, want) {
			t.Errorf("missing gap %q in:\n%s", want, gaps)
		}
	}
}

// The trust policy is a rendered aws_iam_policy_document; evaluate it to
// check the rendering (principals "*", not_principals, conditions, and the
// unknown statements standing for source_policy_documents).
func TestPolicyDocumentRendering(t *testing.T) {
	inv, _ := load(t, &Options{Account: "111122223333", Region: "us-east-1", OIDCIssuers: map[string]string{"arn:aws:eks:eu-west-1:111122223333:cluster/c": "https://x"}})
	trust := inv.Trusts[0].Policy()
	req := &eval.Request{
		Principal: match.RequestPrincipal{
			Kind: match.KindAssumedRole, ARN: "arn:aws:sts::111122223333:assumed-role/x/s",
			Account: "111122223333", SourceARN: "arn:aws:iam::111122223333:role/x",
		},
		Action: "sts:AssumeRole", Resource: "arn:aws:iam::111122223333:role/svc/app", ResourceAccount: "111122223333",
		Context: condition.NewContext(&condition.Input{Default: condition.StateAbsent, Present: map[string][]string{"aws:SecureTransport": {"true"}}}),
	}
	d := eval.Evaluate(req, &eval.PolicySet{Resource: []*model.PolicyDocument{trust}, ResourcePolicyRequired: true})
	if d.Verdict != eval.Unknown {
		t.Fatalf("source_policy_documents are not modelled, so the trust is UNKNOWN: %+v", d)
	}
	if !strings.Contains(statements(trust), "Deny sts:AssumeRole") || len(trust.Statements()) != 4 {
		t.Errorf("rendered statements: %s", statements(trust))
	}
	if len(inv.PodIdentity) != 1 || inv.PodIdentity[0].RoleARN != "arn:aws:iam::111122223333:role/svc/app" || inv.Clusters[0].OIDCIssuer != "https://x" {
		t.Errorf("pod identity %+v clusters %+v", inv.PodIdentity, inv.Clusters)
	}
	var key *model.PolicyDocument
	for _, p := range inv.Policies {
		if strings.HasPrefix(p.Doc.ID(), "aws_kms_key.k") {
			key = p.Doc
		}
	}
	if key == nil || statements(key) != "Allow kms:* *;" {
		t.Errorf("explicit key policy %v", key)
	}
}

func TestPlaceholderAndHelpers(t *testing.T) {
	if p := placeholderID(`var.a "b"/c`); p != "var.a__b__c" {
		t.Errorf("placeholder %q", p)
	}
	if !strings.Contains(defaultKeyPolicy("aws", model.UnresolvedPlaceholder("account_of_x")), ":iam::${darb:unresolved:account_of_x}:root") {
		t.Error("an unknown account keeps the default key policy's delegation unresolved")
	}
	if kindName(99) != "value" || kindName(0) != "null" {
		t.Error("kindName")
	}
}
