package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/rules"
)

// Documented keys end to end (DESIGN.md §6.2), on scenario 1 (api reads the
// PII bucket, 729 critical, confirmed). Expected results written before the
// builder used the key table.
func TestDocumentedKeysOnScenario1(t *testing.T) {
	cases := []struct {
		name, tf      string
		status, undec string
	}{
		{ // The attacker uses TLS: a bucket policy denying insecure transport never stops the read.
			name: "secure-transport deny", status: rules.StatusConfirmed,
			tf: `resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.customer_pii.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*",
      Resource = ["${aws_s3_bucket.customer_pii.arn}", "${aws_s3_bucket.customer_pii.arn}/*"],
      Condition = { Bool = { "aws:SecureTransport" = "false" } } } ] })
}`,
		},
		{ // A role session: aws:MultiFactorAuthPresent absent or false is undocumented; Bool false may deny.
			name: "mfa bool false", status: rules.StatusConfirmedUnlessDenied, undec: "aws:MultiFactorAuthPresent",
			tf: denyPolicy(`{ Sid = "DenyNoMFA", Effect = "Deny", Action = "s3:*", Resource = "*", Condition = { Bool = { "aws:MultiFactorAuthPresent" = "false" } } }`),
		},
		{ // BoolIfExists false denies in both cases: no path at all.
			name: "mfa bool-if-exists false", status: "",
			tf: denyPolicy(`{ Sid = "DenyNoMFA", Effect = "Deny", Action = "s3:*", Resource = "*", Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } } }`),
		},
		{ // S3 calls KMS from us-east-1: a Deny on any other kms:ViaService does not apply.
			name: "via-service deny", status: rules.StatusConfirmed,
			tf: denyPolicy(`{ Sid = "OnlyViaS3", Effect = "Deny", Action = "kms:Decrypt", Resource = "*", Condition = { StringNotEquals = { "kms:ViaService" = "s3.us-east-1.amazonaws.com" } } }`),
		},
		{ // aws:CalledVia on S3's call to KMS is undocumented: a Deny on it may apply.
			name: "called-via deny", status: rules.StatusConfirmedUnlessDenied, undec: "aws:CalledVia",
			tf: denyPolicy(`{ Sid = "NotThroughS3", Effect = "Deny", Action = "kms:Decrypt", Resource = "*", Condition = { "ForAnyValue:StringEquals" = { "aws:CalledVia" = "s3.amazonaws.com" } } }`),
		},
		{ // aws:ViaAWSService is false on the direct read and true on S3's call to KMS.
			name: "via-aws-service", status: rules.StatusConfirmed,
			tf: denyPolicy(`{ Sid = "DecryptOnlyViaService", Effect = "Deny", Action = "kms:Decrypt", Resource = "*", Condition = { Bool = { "aws:ViaAWSService" = "false" } } }`),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := analyzeVariant(t, "01_classic/vulnerable", func(dir string) {
				if err := os.WriteFile(filepath.Join(dir, "terraform", "extra.tf"), []byte(c.tf+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			})
			f := findingFor(a, "DARB-PATH-001", piiBucket)
			if c.status == "" {
				if f != nil {
					t.Fatalf("no path expected: %+v", f.Path)
				}
				return
			}
			if f == nil || f.Status != c.status || f.Factors.Score != 729 {
				t.Fatalf("want %s at 729: %+v", c.status, f)
			}
			if c.undec != "" && !strings.Contains(strings.Join(f.Undecided, " "), c.undec) {
				t.Errorf("undecided names %s: %v", c.undec, f.Undecided)
			}
		})
	}
}

func denyPolicy(statement string) string {
	return `resource "aws_iam_role_policy" "extra" {
  name   = "extra"
  role   = aws_iam_role.payments_api.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [ ` + statement + ` ] })
}`
}
