package patch

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/remediate"
)

// memSource is a Source over files in memory.
type memSource map[string][]byte

func (m memSource) Read(p string) ([]byte, error) {
	if b, ok := m[p]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}

func (m memSource) List(dir string) ([]string, error) {
	var out []string
	for p := range m {
		if dirOf(p) == dir {
			out = append(out, p)
		}
	}
	return out, nil
}

func (m memSource) Walk(dir string) ([]string, error) { return m.List(dir) }

// fuzzInventory: one role policy aws_iam_role_policy.x of tf/main.tf with
// one statement reading bucket b, and the bucket.
func fuzzInventory(t testing.TB) *model.Inventory {
	src := model.FileLocation("tf/main.tf", 1, 1, "aws_iam_role_policy.x")
	doc, err := model.NewPolicyDocument(&model.PolicyInput{
		ID: "aws_iam_role_policy.x", Kind: model.PolicyIdentity, Version: model.Version2012, Source: src,
		Statements: []*model.StatementInput{{Effect: model.EffectAllow, Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::b/*"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bsrc := model.FileLocation("tf/main.tf", 1, 1, "aws_s3_bucket.b")
	return &model.Inventory{
		Policies:  []*model.AttachedPolicy{{Target: "role", Doc: doc}},
		Resources: []*model.Resource{model.NewResource(&model.ResourceInput{Kind: model.KindS3Bucket, ARN: "arn:aws:s3:::b", Source: bsrc})},
	}
}

func fuzzEdits() [][]remediate.Edit {
	deny := &model.StatementInput{Sid: "DarbCut00000000", Effect: model.EffectDeny, Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::b/*"}}
	return [][]remediate.Edit{
		{{Op: remediate.OpAddStatement, Policy: "aws_iam_role_policy.x", Statement: deny}},
		{{Op: remediate.OpRemoveValues, Policy: "aws_iam_role_policy.x", Index: 0, Element: "Resource", Values: []string{"arn:aws:s3:::b/*"}}},
		{{Op: remediate.OpRemoveStatement, Policy: "aws_iam_role_policy.x", Index: 0}},
	}
}

var fuzzSeeds = []string{
	`resource "aws_s3_bucket" "b" { bucket = "b" }
resource "aws_iam_role_policy" "x" {
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.b.arn}/*" },
    ]
  })
}
`,
	`resource "aws_iam_role_policy" "x" {
  policy = jsonencode({ Statement = { Effect = "Allow", Action = "s3:GetObject", Resource = ["arn:aws:s3:::b/*", "arn:aws:s3:::c/*"] } })
}`,
	"resource \"aws_iam_role_policy\" \"x\" {\r\n  policy = <<EOF\r\n{\"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"s3:GetObject\", \"Resource\": \"arn:aws:s3:::b/*\"}]}\r\nEOF\r\n}\r\n",
	`data "aws_iam_policy_document" "d" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::b/*", "arn:aws:s3:::c/*"]
  }
}
resource "aws_iam_role_policy" "x" { policy = data.aws_iam_policy_document.d.json }
`,
	`resource "aws_iam_role_policy" "x" { policy = var.p }`,
	`resource "aws_iam_role_policy" "x" { policy = jsonencode({ Statement = [ { Resource = "${var.b}/*" } ] }) }`,
	"\xef\xbb\xbfresource \"aws_iam_role_policy\" \"x\" { policy = jsonencode({ Statement = [] }) }",
	`resource "aws_iam_role_policy" "x" {`,
	`}}}`,
	"",
}

// The patcher on arbitrary Terraform: it either patches, and every file it
// returns parses again, or refuses (an error or a TODO). It never panics
// and never returns a broken file.
func FuzzPatchTerraform(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	inv := fuzzInventory(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, edits := range fuzzEdits() {
			res, err := Render(inv, edits, memSource{"tf/main.tf": data}, nil)
			if err != nil {
				if errors.Is(err, errTODO) {
					t.Fatalf("a TODO must be reported in the result, not as an error: %v", err)
				}
				continue
			}
			for _, fc := range res.Files {
				src := fc.After
				if bytes.HasPrefix(src, bom) {
					src = src[3:]
				}
				if _, diags := hclsyntax.ParseConfig(src, fc.Path, hcl.InitialPos); diags.HasErrors() {
					t.Fatalf("the patched file does not parse: %s%s%s", diags.Error(), "\n", fc.After)
				}
				if !bytes.Equal(fc.Before, data) {
					t.Fatal("Before is not the input")
				}
			}
			if len(res.Files) == 0 && len(res.TODO) == 0 && strings.TrimSpace(string(data)) != "" && edits[0].Op == remediate.OpAddStatement {
				// No file and no TODO: only possible when nothing was placed.
				t.Fatalf("an add placed nothing and reported nothing for %q", data)
			}
		}
	})
}

// The seeds, as a plain test: each form patches as expected.
func TestPatchSeeds(t *testing.T) {
	inv := fuzzInventory(t)
	for i, s := range fuzzSeeds[:4] {
		for j, edits := range fuzzEdits() {
			res, err := Render(inv, edits, memSource{"tf/main.tf": []byte(s)}, nil)
			if err != nil {
				t.Fatalf("seed %d edit %d: %v", i, j, err)
			}
			if len(res.Files) != 1 && len(res.TODO) == 0 {
				t.Errorf("seed %d edit %d: no file and no TODO", i, j)
			}
		}
	}
}
