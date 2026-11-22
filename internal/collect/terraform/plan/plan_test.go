package plan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/r3oof-900/darb/internal/collect"
	"github.com/r3oof-900/darb/internal/collect/tfraw"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/safeio"
)

func collectFile(t *testing.T, root, path string, opts *Options) (*tfraw.Module, *coverage.Recorder, error) {
	t.Helper()
	rec := &coverage.Recorder{}
	m, err := Collect(context.Background(), &collect.Input{Root: root, Path: path, Limits: safeio.DefaultLimits()}, opts, rec)
	return m, rec, err
}

func byAddress(m *tfraw.Module) map[string]*tfraw.Resource {
	out := map[string]*tfraw.Resource{}
	for _, r := range m.Resources {
		out[r.Address] = r
	}
	return out
}

func TestCollectPlan(t *testing.T) {
	m, rec, err := collectFile(t, "testdata", "plan.json", &Options{})
	if err != nil {
		t.Fatal(err)
	}
	rs := byAddress(m)
	if len(m.Resources) != 6 {
		t.Fatalf("got %d resources: %v", len(m.Resources), rs)
	}
	role := rs["aws_iam_role.app"]
	if p, ok := role.Attrs.Str("assume_role_policy"); !ok || !strings.Contains(p, "sts:AssumeRole") {
		t.Errorf("assume_role_policy: %q", p)
	}
	if v, _ := role.Attrs.Get("max_session_duration"); v.Kind != tfraw.KNumber || v.Str != "3600" {
		t.Errorf("number: %+v", v)
	}
	if v, _ := role.Attrs.Get("tags"); v.Kind != tfraw.KObject {
		t.Errorf("tags: %+v", v)
	}
	// A value known only after apply that names one attribute stays a symbolic reference.
	pol, _ := rs["aws_iam_role_policy.decrypt"].Attrs.Get("policy")
	if pol.Kind != tfraw.KRef || pol.Ref.String() != "aws_kms_key.pii.arn" {
		t.Errorf("policy: %+v", pol)
	}
	// Several distinct references: a computed expression, recorded as unknown.
	id, _ := rs["aws_iam_role_policy.decrypt"].Attrs.Get("id")
	if id.Kind != tfraw.KUnknownAfterApply {
		t.Errorf("id: %+v", id)
	}
	if arn, _ := rs["aws_kms_key.pii"].Attrs.Get("arn"); arn.Kind != tfraw.KUnknownAfterApply {
		t.Errorf("kms arn: %+v", arn)
	}
	if rule := rs["aws_kms_key.pii"].Attrs.Blocks("rule"); len(rule) != 1 {
		t.Errorf("nested block: %v", rule)
	}
	if rec.Count(coverage.KindUnknownAfterApply) != 2 {
		t.Errorf("gaps: %+v", rec.Gaps())
	}
	if r := rs[`module.roles.aws_iam_role.r["a"]`]; r == nil || r.Module != "module.roles" || r.Index != `"a"` || r.ConfigAddress() != "module.roles.aws_iam_role.r" {
		t.Errorf("module instance: %+v", r)
	}
	if r := rs["module.roles.aws_iam_role.r[0]"]; r == nil || r.Index != "0" {
		t.Errorf("count instance: %+v", r)
	}
	if d := rs["data.aws_caller_identity.me"]; d == nil || d.Mode != "data" {
		t.Error("data source from prior state must be included")
	}
	if len(m.Providers) != 1 || m.Providers[0].Region.Str != "us-east-1" {
		t.Errorf("providers: %+v", m.Providers)
	}
}

// Real "terraform show -json" output (Terraform 1.17.1, hashicorp/aws 6.73.0):
// a plan records role = aws_iam_role.r[each.key].id or [each.value].id only
// as ["aws_iam_role.r", "each.key"|"each.value"]. each.key names the
// instance's own key; each.value does too when the configuration shows the
// for_each source is a set (toset(...)); a map comprehension, or no
// configuration, leaves the instance unknown, with a gap that says why.
func TestForEachInstanceReferences(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "..", "tests", "fixtures", "13_module_for_each", "vulnerable")
	cases := []struct {
		name, root, configDir string
		exact                 bool
		why                   string
	}{
		{"each.key", filepath.Join("testdata", "for_each_key"), "", true, ""},
		{"each.value of toset(...)", fixture, "terraform", true, ""},
		{"each.value without configuration", fixture, "", false, "no configuration directory was given"},
		{"each.value of a map", filepath.Join("testdata", "for_each_map"), "terraform", false, "is not toset(...)"},
		{"configuration not found", fixture, "missing", false, "is not in missing/modules/readers"},
	}
	for _, c := range cases {
		m, rec, err := collectFile(t, c.root, "plan.json", &Options{ConfigDir: c.configDir})
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"etl", "bi", "ml"} {
			role, _ := byAddress(m)[`module.readers.aws_iam_role_policy.read["`+key+`"]`].Attrs.Get("role")
			exact := role.Kind == tfraw.KRef && role.Ref.Address == `module.readers.aws_iam_role.r["`+key+`"]` && role.Ref.Selector == ""
			unknown := role.Kind == tfraw.KRef && role.Ref.Address == "module.readers.aws_iam_role.r" && role.Ref.Selector == "each.value"
			if exact != c.exact || (!c.exact && !unknown) {
				t.Errorf("%s, %s: %+v %+v", c.name, key, role, role.Ref)
			}
		}
		found := c.why == ""
		for _, g := range rec.Gaps() {
			if c.why != "" && strings.Contains(g.Detail, c.why) {
				found = true
			}
			if c.exact && strings.Contains(g.Detail, "each.value is not known") {
				t.Errorf("%s: unexpected gap %s", c.name, g.Detail)
			}
		}
		if !found {
			t.Errorf("%s: no gap explaining %q in %+v", c.name, c.why, rec.Gaps())
		}
	}
}

func TestAttrRef(t *testing.T) {
	cases := []struct {
		refs []string
		want string // "address.attr|selector", "" for nil
	}{
		{[]string{"aws_kms_key.pii.arn", "aws_kms_key.pii"}, "m.aws_kms_key.pii.arn|"},
		{[]string{"data.aws_iam_policy_document.t.json", "data.aws_iam_policy_document.t"}, "m.data.aws_iam_policy_document.t.json|"},
		{[]string{"aws_iam_role.r", "each.key"}, "m.aws_iam_role.r.|each.key"},
		{[]string{"aws_iam_role.r", "count.index"}, "m.aws_iam_role.r.|count.index"},
		{[]string{"aws_iam_role.r", "var.k"}, "m.aws_iam_role.r.|var.k"},
		{[]string{"aws_kms_key.a.arn", "aws_kms_key.b.arn"}, ""},          // two attributes
		{[]string{"aws_kms_key.a.arn", "aws_kms_key.b"}, ""},              // two resources
		{[]string{"aws_s3_bucket.b.arn", "aws_s3_bucket.b", "var.p"}, ""}, // template
		{[]string{"aws_iam_role.a", "aws_iam_role.b", "each.key"}, ""},    // which resource?
		{[]string{"aws_iam_role.r", "module.m.out"}, ""},                  // module output
		{[]string{"aws_iam_role.r"}, ""},                                  // whole resource
		{[]string{"var.x"}, ""},                                           // no resource
		{[]string{"aws_iam_role.r.inline_policy.0.name"}, ""},             // deeper path
	}
	for _, c := range cases {
		got := ""
		if r := attrRef(&tfjson.Expression{ExpressionData: &tfjson.ExpressionData{References: c.refs}}, "m"); r != nil {
			got = r.String() + "|" + r.Selector
		}
		if got != c.want {
			t.Errorf("attrRef(%q) = %q, want %q", c.refs, got, c.want)
		}
	}
	if attrRef(nil, "") != nil || attrRef(&tfjson.Expression{}, "") != nil {
		t.Error("no expression")
	}
}

func TestBinaryPlanWithoutTerraform(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "plan.tfplan"), []byte("PK\x03\x04binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	if _, _, err := collectFile(t, root, "plan.tfplan", &Options{}); !errors.Is(err, ErrNotJSON) {
		t.Fatalf("got %v, want ErrNotJSON", err)
	}
	if _, _, err := collectFile(t, root, "plan.tfplan", &Options{TerraformBin: filepath.Join(root, "no-such-terraform")}); err == nil {
		t.Fatal("a missing terraform binary must fail")
	}
}

func TestRejectsBadInput(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"bad.json":     `{"format_version": "1.2", "planned_values": [}`,
		"version.json": `{"format_version": "99.0"}`,
		"deep.json":    "{" + strings.Repeat(`"a":{`, 80) + strings.Repeat("}", 81),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := collectFile(t, root, name, &Options{}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, _, err := collectFile(t, root, "missing.json", &Options{}); err == nil {
		t.Error("missing file must fail")
	}
}

func TestCappedWriter(t *testing.T) {
	c := &capped{max: 4}
	if n, _ := c.Write([]byte("abc")); n != 3 || c.overflow {
		t.Fatal("within limit")
	}
	if n, _ := c.Write([]byte("defg")); n != 4 || !c.overflow || c.buf.String() != "abcd" {
		t.Fatalf("overflow: %q", c.buf.String())
	}
}
