package plan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/tfraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/safeio"
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
