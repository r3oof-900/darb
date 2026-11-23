package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/config"
	"github.com/r3oof-900/darb/internal/eval"
	"github.com/r3oof-900/darb/internal/eval/condition"
	"github.com/r3oof-900/darb/internal/eval/match"
	"github.com/r3oof-900/darb/internal/graph"
	"github.com/r3oof-900/darb/internal/iampolicy"
	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/normalize"
)

// KMS grants (DESIGN.md §6, decided after v0.1.0-rc.1).

// crossAccountHCL: the PII bucket and its key in 111122223333, whose key
// policy names only role/key-admin; role/reader in 444455556666 may read
// the objects (its identity policy and the bucket policy). The grant gives
// it Decrypt. extra is added to reader's identity statements; keyDeny to
// the key policy.
func crossAccountHCL(extra, keyDeny string) map[string]string {
	return map[string]string{"terraform/main.tf": `
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["111122223333"]
}
provider "aws" {
  alias               = "b"
  region              = "us-east-1"
  allowed_account_ids = ["444455556666"]
}
resource "aws_kms_key" "pii" {
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::111122223333:role/key-admin" }, Action = "kms:*", Resource = "*" }` + keyDeny + `]
  })
}
resource "aws_s3_bucket" "pii" {
  bucket = "acme-customer-pii"
  tags   = { DataClass = "pii" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "pii" {
  bucket = aws_s3_bucket.pii.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.pii.arn
    }
  }
}
resource "aws_s3_bucket_policy" "pii" {
  bucket = aws_s3_bucket.pii.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::444455556666:role/reader" }, Action = "s3:GetObject", Resource = "${aws_s3_bucket.pii.arn}/*" }]
  })
}
resource "aws_iam_role" "reader" {
  provider           = aws.b
  name               = "reader"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}
resource "aws_iam_role_policy" "reader" {
  provider = aws.b
  role     = aws_iam_role.reader.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::acme-customer-pii/*" }` + extra + `]
  })
}
resource "aws_kms_grant" "reader" {
  key_id            = aws_kms_key.pii.arn
  grantee_principal = "arn:aws:iam::444455556666:role/reader"
  operations        = ["Decrypt"]
}
`}
}

func decryptEdge(t *testing.T, a *Analysis) *graph.Edge {
	t.Helper()
	g := a.AccessGraph
	for id := graph.EdgeID(0); int(id) < g.NumEdges(); id++ {
		e := g.Edge(id)
		if e.Kind == graph.CanDecrypt && g.Node(e.From).Identity == "arn:aws:iam::444455556666:role/reader" {
			return e
		}
	}
	return nil
}

// A grant to a principal of another account: without an IAM allow in that
// account the decision is UNKNOWN, and undecided names the grant; with
// one, it is allowed; an explicit Deny in the key policy refuses it.
func TestCrossAccountGrant(t *testing.T) {
	analyze := func(extra, keyDeny string) *Analysis {
		var cfg *config.Config
		l := loadTree(t, crossAccountHCL(extra, keyDeny), func(in *Inputs) { tfOnly(in); cfg = in.Config })
		a, err := Analyze(l, cfg, DefaultFailOn)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	e := decryptEdge(t, analyze("", ""))
	if e == nil || e.Verdict != eval.Unknown || len(e.Unresolved) == 0 || e.Unresolved[0].Element != "KMSGrant" {
		t.Fatalf("no IAM allow in the grantee's account: %+v", e)
	}
	f := findingFor(analyze("", ""), "DARB-PATH-001", "arn:aws:s3:::acme-customer-pii")
	if f != nil && (f.Confirmed || !strings.Contains(strings.Join(f.Undecided, " "), "aws_kms_grant.reader")) {
		t.Fatalf("an unconfirmed finding names the grant: %+v", f.Undecided)
	}
	if got := decryptEdge(t, analyze(`, { Effect = "Allow", Action = "kms:Decrypt", Resource = "*" }`, "")); got == nil || got.Verdict != eval.Allow {
		t.Fatalf("with an IAM allow in the grantee's account: %+v", got)
	}
	deny := `, { Effect = "Deny", Principal = { AWS = "arn:aws:iam::444455556666:role/reader" }, Action = "kms:Decrypt", Resource = "*" }`
	if got := decryptEdge(t, analyze(`, { Effect = "Allow", Action = "kms:Decrypt", Resource = "*" }`, deny)); got != nil {
		t.Fatalf("a Deny in the key policy refuses the grant: %+v", got)
	}
	if got := decryptEdge(t, analyze("", deny)); got != nil {
		t.Fatalf("a Deny in the key policy refuses the cross-account grant too: %+v", got)
	}
	// An explicit Deny in the grantee's own identity policy: no edge, no path.
	a := analyze(`, { Effect = "Deny", Action = "kms:Decrypt", Resource = "*" }`, "")
	if got := decryptEdge(t, a); got != nil {
		t.Fatalf("a Deny in the grantee's identity policy refuses the grant: %+v", got)
	}
	if f := findingFor(a, "DARB-PATH-001", "arn:aws:s3:::acme-customer-pii"); f != nil {
		t.Fatalf("no path: %+v", f)
	}
	// The decrypt's only side is the grant (the grantee's identity
	// policies grant nothing): resource, revoke.
	e = decryptEdge(t, analyze("", ""))
	if len(e.Fixes) != 1 || e.Fixes[0].Side != graph.SideResource || e.Fixes[0].Kind != graph.FixRevoke {
		t.Fatalf("fixes of the cross-account grant: %+v", e.Fixes)
	}
}

// With the read declared uncuttable, the cut of scenario 25 is the grant:
// the generator says to delete its aws_kms_grant, with no patch (a grant
// cannot be edited).
func TestGrantCutIsRevoked(t *testing.T) {
	a := analyzeVariant(t, "25_kms_grant/vulnerable", func(dir string) {
		appendConfig(t, dir, "remediation:", "  uncuttable_edges:",
			"    - {kind: CAN_READ, from: \"arn:aws:iam::111122223333:role/payments-api\", to: \"arn:aws:s3:::acme-customer-pii\", reason: needed}")
	})
	f := findingFor(a, "DARB-PATH-001", "arn:aws:s3:::acme-customer-pii")
	if f == nil || len(f.Fix) != 1 || f.Fix[0].Kind != graph.FixRevoke || f.Fix[0].Cost != 4 || !strings.Contains(f.Fix[0].Policy, "#grant/aws_kms_grant.payments_api") {
		t.Fatalf("the grant is the cut, revoke, 4: %+v", f)
	}
	in, l, a := scanFixture(t, "25_kms_grant/vulnerable", func(dir string) {
		appendConfig(t, dir, "remediation:", "  uncuttable_edges:",
			"    - {kind: CAN_READ, from: \"arn:aws:iam::111122223333:role/payments-api\", to: \"arn:aws:s3:::acme-customer-pii\", reason: needed}")
	})
	f = findingFor(a, "DARB-PATH-001", "arn:aws:s3:::acme-customer-pii")
	r, err := Remediate(t.Context(), in, l, a, f.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if r.Patch != nil && r.Patch.Complete() {
		t.Fatalf("a grant gets no complete patch")
	}
	var out bytes.Buffer
	WriteRemediation(&out, r)
	if !strings.Contains(out.String(), "delete the Terraform resource aws_kms_grant.payments_api") {
		t.Fatalf("the advice names the resource: %s", out.String())
	}
}

// Grant constraints (KMS API Reference › GrantConstraints): Equals is an
// exact match of every pair, no other key; Subset allows other keys; both
// compare values with case.
func TestGrantConstraints(t *testing.T) {
	const role = "arn:aws:iam::111122223333:role/r"
	decide := func(g *normalize.Grant, ctx map[string]string) eval.Verdict {
		doc, err := iampolicy.Parse([]byte(normalize.GrantPolicy(g)), &iampolicy.Options{ID: "k#grant/g", Kind: model.PolicyResource})
		if err != nil {
			t.Fatal(err)
		}
		present := map[string][]string{}
		for k, v := range ctx {
			present["kms:EncryptionContext:"+k] = []string{v}
			present["kms:EncryptionContextKeys"] = append(present["kms:EncryptionContextKeys"], k)
		}
		req := &eval.Request{
			Principal: match.RequestPrincipal{Kind: match.KindAssumedRole, ARN: "arn:aws:sts::111122223333:assumed-role/r/s", SourceARN: role, Account: "111122223333"},
			Action:    "kms:Decrypt", Resource: "arn:aws:kms:us-east-1:111122223333:key/k", ResourceAccount: "111122223333",
			Context: condition.NewContext(&condition.Input{Present: present, Default: condition.StateAbsent}),
		}
		return eval.Evaluate(req, &eval.PolicySet{Resource: []*model.PolicyDocument{doc}, ResourcePolicyRequired: true}).Verdict
	}
	const a, b = "arn:aws:s3:::a", "arn:aws:s3:::b"
	dept := func(eq bool) *normalize.Grant {
		g := &normalize.Grant{Grantee: role, Operations: []string{"Decrypt"}}
		if eq {
			g.Equals = map[string]string{"department": "x"}
		} else {
			g.Subset = map[string]string{"department": "x"}
		}
		return g
	}
	equals := &normalize.Grant{Grantee: role, Operations: []string{"Decrypt"}, Equals: map[string]string{"aws:s3:arn": a}}
	subset := &normalize.Grant{Grantee: role, Operations: []string{"Decrypt"}, Subset: map[string]string{"aws:s3:arn": a}}
	for _, c := range []struct {
		name  string
		g     *normalize.Grant
		ctx   map[string]string
		allow bool
	}{
		{"equals, same pair", equals, map[string]string{"aws:s3:arn": a}, true},
		{"equals, other value", equals, map[string]string{"aws:s3:arn": b}, false},
		{"equals, value case differs", equals, map[string]string{"aws:s3:arn": "arn:aws:s3:::A"}, false},
		{"equals, an extra pair", equals, map[string]string{"aws:s3:arn": a, "x": "y"}, false},
		{"equals, no context", equals, map[string]string{}, false},
		{"subset, an extra pair", subset, map[string]string{"aws:s3:arn": a, "x": "y"}, true},
		{"subset, other value", subset, map[string]string{"aws:s3:arn": b}, false},
		{"no constraint", &normalize.Grant{Grantee: role, Operations: []string{"Decrypt"}}, map[string]string{"aws:s3:arn": b}, true},
		{"another operation", &normalize.Grant{Grantee: role, Operations: []string{"Encrypt"}}, map[string]string{}, false},
		// Keys without case, values with case (GrantConstraints).
		{"equals, key case differs", dept(true), map[string]string{"Department": "x"}, true},
		{"equals, value case differs", dept(true), map[string]string{"department": "X"}, false},
		{"subset, key case differs", dept(false), map[string]string{"Department": "x", "other": "y"}, true},
		{"subset, value case differs", dept(false), map[string]string{"department": "X"}, false},
	} {
		if got := decide(c.g, c.ctx); (got == eval.Allow) != c.allow {
			t.Errorf("%s: %s", c.name, got)
		}
	}
}
