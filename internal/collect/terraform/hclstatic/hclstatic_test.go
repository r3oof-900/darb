package hclstatic

import (
	"context"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/safeio"
)

func collectBasic(t *testing.T) (*tfraw.Module, *coverage.Recorder) {
	t.Helper()
	rec := &coverage.Recorder{}
	m, err := Collect(context.Background(), &collect.Input{Root: "testdata", Path: "basic", Limits: safeio.DefaultLimits()}, rec)
	if err != nil {
		t.Fatal(err)
	}
	return m, rec
}

func find(t *testing.T, m *tfraw.Module, root, address string) *tfraw.Resource {
	t.Helper()
	for _, r := range m.Resources {
		if r.Root == root && r.Address == address {
			return r
		}
	}
	t.Fatalf("resource %s in %s not found", address, root)
	return nil
}

func TestResolvedValues(t *testing.T) {
	m, _ := collectBasic(t)
	role := find(t, m, "basic", "aws_iam_role.app")
	// local.prefix depends on local.org (declared later) and var.team (from terraform.tfvars, not other.tfvars).
	if name, _ := role.Attrs.Str("name"); name != "ACME-PAYMENTS" {
		t.Errorf("name = %q", name)
	}
	if role.Pos.File != "basic/main.tf" || role.Pos.StartLine == 0 {
		t.Errorf("position %+v", role.Pos)
	}
	key := find(t, m, "basic", "aws_kms_key.pii")
	if v, _ := key.Attrs.Get("enable_key_rotation"); v.Kind != tfraw.KBool || !v.Bool {
		t.Errorf("bool %+v", v)
	}
	if len(m.Providers) != 2 || m.Providers[0].Key != "basic:aws" || m.Providers[0].Region.Str != "eu-west-1" ||
		m.Providers[0].Account.Str != "111122223333" || m.Providers[1].Key != "basic:aws.east" {
		t.Errorf("providers %+v %+v", m.Providers[0], m.Providers[1])
	}
	if sub := find(t, m, "basic/sub", "aws_iam_role.app"); sub == nil {
		t.Error("each directory is its own root")
	}
}

func TestSymbolicAndUnresolvedValues(t *testing.T) {
	m, _ := collectBasic(t)
	pol, _ := find(t, m, "basic", "aws_iam_role_policy.decrypt").Attrs.Get("policy")
	if pol.Kind != tfraw.KObject || pol.Expr != "jsonencode" {
		t.Fatalf("jsonencode with a reference must keep its structure: %+v", pol)
	}
	stmts, _ := pol.Obj.Get("Statement")
	res0, _ := stmts.List[0].Obj.Get("Resource")
	if res0.Kind != tfraw.KRef || res0.Ref.String() != "aws_kms_key.pii.arn" {
		t.Errorf("resource reference: %+v", res0)
	}
	res1, _ := stmts.List[1].Obj.Get("Resource")
	if res1.Kind != tfraw.KTemplate || res1.List[1].Kind != tfraw.KUnresolved || res1.List[1].Expr != "var.bucket" {
		t.Errorf("unresolved variable inside a template: %+v", res1)
	}
	if role, _ := find(t, m, "basic", "aws_iam_role_policy.decrypt").Attrs.Get("role"); role.Kind != tfraw.KRef || role.Ref.Attr != "id" {
		t.Errorf("role ref %+v", role)
	}
	trust, _ := find(t, m, "basic", "aws_iam_role.app").Attrs.Get("assume_role_policy")
	if trust.Kind != tfraw.KTemplate || trust.List[1].Ref.String() != "aws_iam_role.other.arn" {
		t.Errorf("heredoc interpolation %+v", trust)
	}
}

func TestPolicyDocumentBlocks(t *testing.T) {
	m, _ := collectBasic(t)
	doc := find(t, m, "basic", "data.aws_iam_policy_document.trust")
	st := doc.Attrs.Blocks("statement")
	if doc.Mode != "data" || len(st) != 1 {
		t.Fatalf("statement blocks %v", st)
	}
	ids, _ := st[0].Blocks("principals")[0].Get("identifiers")
	if ids.List[0].Kind != tfraw.KRef || ids.List[0].Ref.Address != "data.aws_iam_openid_connect_provider.eks" {
		t.Errorf("data reference %+v", ids.List[0])
	}
	variable, _ := st[0].Blocks("condition")[0].Get("variable")
	if variable.Kind != tfraw.KTemplate || variable.List[0].Kind != tfraw.KUnresolved {
		t.Errorf("unresolved condition key %+v", variable)
	}
}

func TestGapsAndContinuation(t *testing.T) {
	m, rec := collectBasic(t)
	many := find(t, m, "basic", "aws_iam_role.many[*]")
	if many.Index != "[*]" || many.Provider != "aws.east" {
		t.Errorf("for_each resource %+v", many)
	}
	if dyn, _ := find(t, m, "basic", "aws_s3_bucket.dyn").Attrs.Get("grant"); dyn.Kind != tfraw.KUnresolved {
		t.Errorf("dynamic block %+v", dyn)
	}
	var details []string
	for _, g := range rec.Gaps() {
		details = append(details, string(g.Kind)+" "+g.File+" "+g.Detail)
	}
	all := strings.Join(details, "\n")
	for _, want := range []string{
		"parse-error basic/broken.tf",
		"module calls are expanded only from a plan",
		"count/for_each instances are expanded only from a plan",
		"dynamic \"grant\" blocks",
		"var.bucket: depends on var.bucket",
		"local.oidc",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing gap %q in:\n%s", want, all)
		}
	}
	if _, ok := find(t, m, "basic", "aws_kms_key.pii").Attrs.Get("lifecycle"); ok {
		t.Error("lifecycle is not an attribute")
	}
}

func TestMissingRoot(t *testing.T) {
	_, err := Collect(context.Background(), &collect.Input{Root: "testdata", Path: "missing", Limits: safeio.DefaultLimits()}, &coverage.Recorder{})
	if err == nil {
		t.Fatal("expected an error")
	}
}
