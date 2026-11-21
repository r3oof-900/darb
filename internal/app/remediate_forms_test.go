package app

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/graph"
)

// The three ways a Terraform policy is written, each patched for a narrow
// fix (a Deny added) and a revoke (the explicit read removed, with the PII
// bucket made SSE-S3 so the read is the whole path).
const (
	heredocPolicy = `resource "aws_iam_role" "payments_api" {
  name               = "payments-api"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

resource "aws_iam_role_policy" "payments_api" {
  name   = "data-access"
  role   = aws_iam_role.payments_api.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "ReadCustomerData", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "${aws_s3_bucket.customer_pii.arn}/*"},
    {"Sid": "DecryptAnything", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "*"}
  ]
}
EOF
}
`
	dataPolicy = `resource "aws_iam_role" "payments_api" {
  name               = "payments-api"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

# The role's permissions, as a policy document data source.
data "aws_iam_policy_document" "data_access" {
  statement {
    sid       = "ReadCustomerData"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.customer_pii.arn}/*"]
  }
  statement {
    sid       = "DecryptAnything"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "payments_api" {
  name   = "data-access"
  role   = aws_iam_role.payments_api.id
  policy = data.aws_iam_policy_document.data_access.json
}
`
)

func sseS3(t *testing.T, dir string) {
	t.Helper()
	replaceIn(t, filepath.Join(dir, "terraform", "pii_kms_bucket.tf"),
		`      sse_algorithm     = "aws:kms"`+lf+`      kms_master_key_id = aws_kms_key.pii.arn`, `      sse_algorithm = "AES256"`)
}

func TestPolicyForms(t *testing.T) {
	for _, c := range []struct {
		form, policy string
		narrow       []string // lines the narrow fix adds
		revoke       []string // lines the revoke removes
	}{
		{
			"jsonencode", "",
			[]string{`+      { Sid = "ClapaCut`, `Effect = "Deny", Action = ["kms:Decrypt"], Resource = [aws_kms_key.pii.arn]`},
			[]string{`-      { Sid = "ReadCustomerData"`},
		},
		{
			"heredoc", heredocPolicy,
			[]string{`+    {"Sid": "ClapaCut`, `"Resource": ["${aws_kms_key.pii.arn}"]`, `["${aws_s3_bucket.customer_pii.arn}", "${aws_s3_bucket.customer_pii.arn}/*"]`},
			[]string{`-    {"Sid": "ReadCustomerData"`},
		},
		{
			"data source", dataPolicy,
			[]string{`+  statement {`, `+    effect    = "Deny"`, `+    resources = [aws_kms_key.pii.arn]`, `+      variable = "kms:EncryptionContext:aws:s3:arn"`},
			[]string{`-  statement {`, `-    sid       = "ReadCustomerData"`},
		},
	} {
		setPolicy := func(dir string) {
			if c.policy != "" {
				writeFile(t, filepath.Join(dir, "terraform", "role.tf"), c.policy)
			}
		}
		for _, kind := range []string{graph.FixNarrow, graph.FixRevoke} {
			edit := setPolicy
			if kind == graph.FixRevoke {
				edit = func(dir string) { setPolicy(dir); sseS3(t, dir) }
			}
			in, l, a := scanFixture(t, "01_classic/vulnerable", edit)
			f := findingFor(a, "CLAPA-PATH-001", piiBucket)
			if f == nil || len(f.Fix) != 1 || f.Fix[0].Kind != kind {
				t.Fatalf("%s %s: the cut: %+v", c.form, kind, f)
			}
			r, err := Remediate(t.Context(), in, l, a, f.Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Accepted() {
				t.Fatalf("%s %s: not accepted: %v %v %v", c.form, kind, r.Memory.Reasons, r.Files.Reasons, r.Patch)
			}
			want := c.narrow
			if kind == graph.FixRevoke {
				want = c.revoke
			}
			diff := r.Patch.Diff()
			for _, w := range want {
				if !strings.Contains(diff, w) {
					t.Errorf("%s %s: the diff lacks %q:%s%s", c.form, kind, w, lf, diff)
				}
			}
			noInventedNames(t, l.Inventory, r)
		}
	}
}

// The patched file keeps its form: CRLF line endings, a UTF-8 BOM, the
// comments and spacing of every line it does not touch.
func TestPatchKeepsFileForm(t *testing.T) {
	for _, c := range []struct {
		name string
		form func(string) string
	}{
		{"crlf", func(s string) string { return strings.ReplaceAll(s, lf, crlf) }},
		{"bom+crlf", func(s string) string { return string([]byte{0xEF, 0xBB, 0xBF}) + strings.ReplaceAll(s, lf, crlf) }},
		{"comments", func(s string) string {
			return "# owned by team-payments" + lf + strings.Replace(s, "  policy = jsonencode", "  # the API's data access"+lf+"  policy   =   jsonencode", 1)
		}},
	} {
		var original string
		in, l, a := scanFixture(t, "01_classic/vulnerable", func(dir string) {
			file := filepath.Join(dir, "terraform", "role.tf")
			original = c.form(readFile(t, file))
			writeFile(t, file, original)
		})
		f := findingFor(a, "CLAPA-PATH-001", piiBucket)
		r, err := Remediate(t.Context(), in, l, a, f.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Accepted() || len(r.Patch.Files) != 1 {
			t.Fatalf("%s: not accepted: %v %v %+v", c.name, r.Memory.Reasons, r.Files.Reasons, r.Patch)
		}
		after := string(r.Patch.Files[0].After)
		if strings.HasPrefix(original, string([]byte{0xEF, 0xBB, 0xBF})) != strings.HasPrefix(after, string([]byte{0xEF, 0xBB, 0xBF})) {
			t.Errorf("%s: the BOM changed", c.name)
		}
		if strings.Contains(original, crlf) && strings.Count(after, lf) != strings.Count(after, crlf) {
			t.Errorf("%s: a line ending is not CRLF:%s%q", c.name, lf, after)
		}
		// Every original line is still there, in order; one line is added.
		sep := lf
		if strings.Contains(original, crlf) {
			sep = crlf
		}
		was, now := strings.Split(original, sep), strings.Split(after, sep)
		if len(now) != len(was)+1 {
			t.Fatalf("%s: %d lines became %d", c.name, len(was), len(now))
		}
		for i, j := 0, 0; i < len(was); j++ {
			if now[j] == was[i] {
				i++
			} else if j-i > 1 {
				t.Fatalf("%s: line %d changed: %q", c.name, i+1, was[i])
			}
		}
	}
}
