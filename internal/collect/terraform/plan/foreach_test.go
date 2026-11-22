package plan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/safeio"
)

func TestForEachSetSources(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("cfg/main.tf", `
variable "names" { type = set(string) }
variable "list"  { type = list(string) }
resource "aws_iam_role" "typed_set"  { for_each = var.names }
resource "aws_iam_role" "typed_list" { for_each = var.list }
resource "aws_iam_role" "toset"      { for_each = toset(var.list) }
resource "aws_iam_role" "map"        { for_each = { for n in var.list : n => n } }
resource "aws_iam_role" "local"      { for_each = local.names }
resource "aws_iam_role" "untyped"    { for_each = var.missing }
resource "aws_iam_role" "none"       {}
`)
	write("cfg/sub/ignored.tf", `resource "aws_iam_role" "nested" { for_each = toset([]) }`)
	write("cfg/broken/main.tf", `resource "aws_iam_role" "x" {`)
	cfg := &tfjson.Config{RootModule: &tfjson.ConfigModule{ModuleCalls: map[string]*tfjson.ModuleCall{
		"registry": {Source: "terraform-aws-modules/iam/aws"},
		"broken":   {Source: "./broken"},
		"escape":   {Source: "../../outside"},
		"sub":      {Source: "./sub", Module: &tfjson.ConfigModule{ModuleCalls: map[string]*tfjson.ModuleCall{"deeper": {Source: "git::https://example.com/m"}}}},
	}}}
	rec := &coverage.Recorder{}
	s := newConfigSource(root, "cfg", safeio.DefaultLimits(), cfg, rec)
	cases := []struct {
		module, name string
		set          bool
		why          string
	}{
		{"", "typed_set", true, ""},
		{"", "toset", true, ""},
		{"", "typed_list", false, "is not toset(...)"},
		{"", "map", false, "is not toset(...)"},
		{"", "local", false, "is not toset(...)"},
		{"", "untyped", false, "is not toset(...)"},
		{"", "none", false, "is not in cfg"},
		{"module.sub", "nested", true, ""}, // its own directory, cfg/sub
		{"module.registry", "x", false, "is not a local directory"},
		{"module.sub.module.deeper", "x", false, "is not a local directory"},
		{"module.broken", "x", false, "is not in cfg/broken"},
		{"module.unknown", "x", false, "is not in the plan"},
		{"module.escape", "x", false, "is not in ../outside"},
	}
	for _, c := range cases {
		kind, why := s.kind(c.module, "aws_iam_role", c.name)
		if (kind == forEachSet) != c.set || !strings.Contains(why, c.why) {
			t.Errorf("%s.%s: set=%v %q, want set=%v %q", c.module, c.name, kind == forEachSet, why, c.set, c.why)
		}
	}
	gaps := map[string]bool{}
	for _, g := range rec.Gaps() {
		gaps[g.File] = true
	}
	if !gaps["cfg/broken/main.tf"] || !gaps["../outside"] {
		t.Errorf("parse error and escaping directory must be reported: %+v", rec.Gaps())
	}
	if s2 := newConfigSource(root, "", safeio.DefaultLimits(), nil, rec); len(s2.dirs) != 0 {
		t.Error("no configuration in the plan")
	}
}
