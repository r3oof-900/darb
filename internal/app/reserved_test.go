package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/safeio"
)

// Reserved placeholder text written into input files (docs/DESIGN.md
// section 4.6) is rejected as invalid input, reported with its file:line,
// and never reaches the inventory as a placeholder: the value it was in is
// unknown like any other unresolvable value, and the scan goes on.

// bs is a backslash, built so that no tool writing this file can turn the
// escapes below into the characters they stand for.
const bs = string(rune(0x5c))

const forged = "${clapa:unresolved:forged}"

const roleHCL = `resource "aws_iam_role" "app" {
  name               = "app"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
`

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func loadTree(t *testing.T, files map[string]string, mutate func(*Inputs)) *Loaded {
	t.Helper()
	cfg, err := config.Parse([]byte("version: 1\nterraform: {account: \"111122223333\", region: us-east-1}\nclusters:\n  - {name: prod}\n"))
	if err != nil {
		t.Fatal(err)
	}
	in := &Inputs{Root: writeTree(t, files), Config: cfg, Limits: safeio.DefaultLimits()}
	mutate(in)
	l, err := Load(context.Background(), in)
	if err != nil {
		t.Fatalf("the scan must go on: %v", err)
	}
	return l
}

// noForgedPlaceholder: nothing in the inventory carries the forged id.
func noForgedPlaceholder(t *testing.T, inv *model.Inventory) {
	t.Helper()
	js, err := Summary(&Loaded{Inventory: inv})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), "forged") {
		t.Errorf("forged placeholder reached the inventory: %s", js)
	}
}

func reservedGap(t *testing.T, gaps []coverage.Gap, file string, line int) {
	t.Helper()
	for i := range gaps {
		g := &gaps[i]
		if g.Kind == coverage.KindParseError && strings.Contains(g.Detail, "reserved text") &&
			filepath.ToSlash(g.File) == file && (line == 0 || g.Line == line) {
			return
		}
	}
	t.Errorf("no reserved-text parse error at %s:%d in %+v", file, line, gaps)
}

func TestReservedTextInTerraform(t *testing.T) {
	policy := func(resource string) string {
		return `resource "aws_iam_role_policy" "p" {
  role   = aws_iam_role.app.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Deny", Action = "s3:*", Resource = "` + resource + `" }] })
}
`
	}
	cases := []struct {
		name, hcl string
		line      int
	}{
		{"HCL $$ escape", roleHCL + policy("$$"+forged[1:]), 7},
		{"HCL backslash-u escape", roleHCL + policy(bs+"u0024"+forged[1:]), 7},
		{"assembled by a template", roleHCL + `resource "aws_s3_bucket" "b" {
  bucket = "pa:unresolved:"
}
` + policy("$${cla${aws_s3_bucket.b.bucket}forged}"), 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := loadTree(t, map[string]string{"terraform/main.tf": c.hcl}, func(in *Inputs) { in.TerraformDirs = []string{"terraform"} })
			reservedGap(t, l.Gaps, "terraform/main.tf", c.line)
			noForgedPlaceholder(t, l.Inventory)
			if len(l.Inventory.Principals) != 1 {
				t.Error("the rest of the file is still loaded")
			}
		})
	}
}

func TestReservedTextInPlan(t *testing.T) {
	// The policy string carries a JSON escape that only parsing the policy
	// reveals; the bucket tag carries the text in a key.
	escaped := `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"s3:*\",\"Resource\":\"` + bs + bs + `u0024{clapa:unresolved:forged}\"}]}`
	planJSON := `{"format_version": "1.2", "terraform_version": "1.17.1", "planned_values": {"root_module": {"resources": [
  {"address": "aws_iam_role.app", "mode": "managed", "type": "aws_iam_role", "name": "app", "provider_name": "registry.terraform.io/hashicorp/aws",
   "values": {"name": "app", "assume_role_policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"}},
  {"address": "aws_iam_role_policy.p", "mode": "managed", "type": "aws_iam_role_policy", "name": "p", "provider_name": "registry.terraform.io/hashicorp/aws",
   "values": {"name": "p", "role": "app", "policy": "` + escaped + `"}},
  {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": "registry.terraform.io/hashicorp/aws",
   "values": {"bucket": "b", "tags": {"` + forged + `": "x"}}}
]}}}`
	l := loadTree(t, map[string]string{"plan.json": planJSON}, func(in *Inputs) { in.TerraformPlans = []PlanInput{{Path: "plan.json"}} })
	noForgedPlaceholder(t, l.Inventory)
	found := map[string]bool{}
	for _, g := range l.Gaps {
		if g.Kind == coverage.KindParseError && strings.Contains(g.Detail, "reserved text") {
			found[g.Address] = true
		}
	}
	if !found["aws_iam_role_policy.p"] || !found["aws_s3_bucket.b"] {
		t.Errorf("plan: reserved text not reported for both resources: %v (%+v)", found, l.Gaps)
	}
}

func TestReservedTextInManifests(t *testing.T) {
	sa := func(annotation string) string {
		return "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: api\n  namespace: payments\n  annotations:\n    eks.amazonaws.com/role-arn: " + annotation + "\n"
	}
	for name, annotation := range map[string]string{
		"plain":               `"` + forged + `"`,
		"YAML escape":         `"` + bs + `x24{clapa:unresolved:forged}"`,
		"YAML unicode escape": `"` + bs + `u0024{clapa:unresolved:forged}"`,
	} {
		t.Run(name, func(t *testing.T) {
			l := loadTree(t, map[string]string{"k8s/sa.yaml": sa(annotation)}, func(in *Inputs) {
				in.K8sDirs = []K8sDir{{Path: "k8s", Cluster: "prod"}}
			})
			reservedGap(t, l.Gaps, "k8s/sa.yaml", 7)
			noForgedPlaceholder(t, l.Inventory)
			if len(l.Inventory.ServiceAccounts) != 0 {
				t.Error("the document is rejected")
			}
		})
	}
}

func TestReservedTextInSnapshot(t *testing.T) {
	inner := `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"` + bs + bs + `u0024{clapa:unresolved:forged}\"}]}`
	l := loadTree(t, map[string]string{
		"snap/manifest.json":                              `{"format": "clapa-snapshot/v1", "accounts": [{"id": "111122223333", "partition": "aws"}], "calls": []}`,
		"snap/111122223333/s3/b/get-bucket-location.json": `{"LocationConstraint": "us-east-1"}`,
		"snap/111122223333/s3/b/get-bucket-policy.json":   "{\n  \"Policy\": \"" + inner + "\"\n}",
	}, func(in *Inputs) { in.AWSSnapshots = []string{"snap"} })
	reservedGap(t, l.Gaps, "snap/111122223333/s3/b/get-bucket-policy.json", 2)
	noForgedPlaceholder(t, l.Inventory)
}

func TestReservedTextInConfig(t *testing.T) {
	_, err := config.Parse([]byte("version: 1\nterraform: {account: \"111122223333\", region: us-east-1}\nclusters:\n  - {name: prod, oidc_issuer: \"" + forged + "\"}\n"))
	if !errors.Is(err, config.ErrInvalid) || !strings.Contains(err.Error(), "clapa.yaml:4") {
		t.Errorf("clapa.yaml: %v", err)
	}
}
