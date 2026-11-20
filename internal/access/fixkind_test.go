package access

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/iampolicy"
	"github.com/r3oof-900/clapa/internal/model"
)

// The boundaries of "explicit" (revoke) and "broad" (narrow), one case per
// rule of SCORING.md §4.1.

const (
	fkBucket = "arn:aws:s3:::b"
	fkRole   = "arn:aws:iam::111111111111:role/app"
	fkAdmin  = "arn:aws:iam::222222222222:role/admin"
	fkSub    = "system:serviceaccount:payments:api"
)

// statement parses one statement (a JSON object) of a policy of the kind.
func statement(t *testing.T, kind model.PolicyKind, js string) *model.Statement {
	t.Helper()
	doc := `{"Version":"2012-10-17","Statement":[` + js + `]}`
	d, err := iampolicy.Parse([]byte(doc), &iampolicy.Options{ID: "p", Kind: kind, Placeholders: true})
	if err != nil {
		t.Fatalf("%v: %s", err, js)
	}
	return d.Statements()[0]
}

func TestExplicitBoundaries(t *testing.T) {
	read := &grantTarget{action: "s3:GetObject", prefix: fkBucket + "/", principal: fkRole}
	assume := &grantTarget{action: "sts:AssumeRole", resource: fkAdmin, principal: fkRole}
	decrypt := &grantTarget{action: "kms:Decrypt", principal: fkRole, context: fkBucket}
	web := &grantTarget{action: "sts:AssumeRoleWithWebIdentity", sub: fkSub}
	service := &grantTarget{action: "sts:AssumeRole", principal: "lambda.amazonaws.com"}
	placeholder := model.UnresolvedPlaceholder("aws_s3_bucket.x.arn")
	id, res := model.PolicyIdentity, model.PolicyResource
	cases := []struct {
		name string
		kind model.PolicyKind
		side string
		t    *grantTarget
		js   string
		want bool
	}{
		// Action: named without a wildcard (any case), even beside a wildcard.
		{"action literal", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, true},
		{"action case", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"S3:getobject","Resource":"arn:aws:s3:::b/*"}`, true},
		{"action beside a wildcard", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":["s3:*","s3:GetObject"],"Resource":"arn:aws:s3:::b/*"}`, true},
		{"action prefix wildcard", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:Get*","Resource":"arn:aws:s3:::b/*"}`, false},
		{"action star", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b/*"}`, false},
		{"NotAction", id, graph.SideIdentity, read, `{"Effect":"Allow","NotAction":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}`, false},
		// S3 resource: the bucket name literal; wildcards only in the object key.
		{"bucket objects", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, true},
		{"narrow key prefix", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/reports/*"}`, true},
		{"exact object", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/k.csv"}`, true},
		{"wildcard in bucket name", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b*/*"}`, false},
		{"all buckets", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::*"}`, false},
		{"resource star", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`, false},
		{"other bucket sharing a prefix", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bb/*"}`, false},
		{"NotResource", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::x/*"}`, false},
		{"unresolved resource", id, graph.SideIdentity, read, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"` + placeholder + `/*"}`, true},
		// Role resource: the exact ARN only.
		{"exact role", id, graph.SideIdentity, assume, `{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"` + fkAdmin + `"}`, true},
		{"role name wildcard", id, graph.SideIdentity, assume, `{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::222222222222:role/adm*"}`, false},
		{"any role", id, graph.SideIdentity, assume, `{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}`, false},
		// Principal: the exact ARN or service; never "*", an account or its root.
		{"exact principal", res, graph.SideResource, read, `{"Effect":"Allow","Principal":{"AWS":"` + fkRole + `"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, true},
		{"other principal", res, graph.SideResource, read, `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/other"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, false},
		{"account root", res, graph.SideResource, read, `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, false},
		{"account ID", res, graph.SideResource, read, `{"Effect":"Allow","Principal":{"AWS":"111111111111"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, false},
		{"AWS star", res, graph.SideResource, read, `{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, false},
		{"bare star", res, graph.SideResource, read, `{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, false},
		{"NotPrincipal", res, graph.SideResource, read, `{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::111111111111:role/x"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`, false},
		{"exact service", res, graph.SideTrust, service, `{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}`, true},
		{"trust names the role", res, graph.SideTrust, assume, `{"Effect":"Allow","Principal":{"AWS":"` + fkRole + `"},"Action":"sts:AssumeRole"}`, true},
		// Web identity: an exact :sub; a wildcard or negated operator is broad.
		{"exact sub", res, graph.SideTrust, web, webTrust(`"StringEquals":{"oidc.example/id/X:sub":"` + fkSub + `"}`), true},
		{"literal StringLike sub", res, graph.SideTrust, web, webTrust(`"StringLike":{"oidc.example/id/X:sub":"` + fkSub + `"}`), true},
		{"wildcard sub", res, graph.SideTrust, web, webTrust(`"StringLike":{"oidc.example/id/X:sub":"system:serviceaccount:payments:*"}`), false},
		{"negated sub", res, graph.SideTrust, web, webTrust(`"StringNotEquals":{"oidc.example/id/X:sub":"` + fkSub + `"}`), false},
		{"aud only", res, graph.SideTrust, web, webTrust(`"StringEquals":{"oidc.example/id/X:aud":"sts.amazonaws.com"}`), false},
		// Decrypt: the encryption context must name bucket b (or its objects).
		{"context bucket", id, graph.SideIdentity, decrypt, decryptGrant(`"StringEquals":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::b"}`), true},
		{"context objects", id, graph.SideIdentity, decrypt, decryptGrant(`"StringLike":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::b/*"}`), true},
		{"no context", id, graph.SideIdentity, decrypt, `{"Effect":"Allow","Action":"kms:Decrypt","Resource":"arn:aws:kms:us-east-1:111111111111:key/k"}`, false},
		{"context wildcard", id, graph.SideIdentity, decrypt, decryptGrant(`"StringLike":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::*"}`), false},
		{"context also another bucket", id, graph.SideIdentity, decrypt, decryptGrant(`"ForAnyValue:StringEquals":{"kms:EncryptionContext:aws:s3:arn":["arn:aws:s3:::b","arn:aws:s3:::c"]}`), false},
		{"context negated", id, graph.SideIdentity, decrypt, decryptGrant(`"StringNotEquals":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::b"}`), false},
		{"key policy names role and context", res, graph.SideResource, decrypt, `{"Effect":"Allow","Principal":{"AWS":"` + fkRole + `"},"Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::b"}}}`, true},
		{"key policy names role only", res, graph.SideResource, decrypt, `{"Effect":"Allow","Principal":{"AWS":"` + fkRole + `"},"Action":"kms:Decrypt","Resource":"*"}`, false},
	}
	for _, c := range cases {
		if got := explicit(statement(t, c.kind, c.js), c.side, c.t); got != c.want {
			t.Errorf("%s: explicit = %v, want %v", c.name, got, c.want)
		}
	}
}

func webTrust(condition string) string {
	return `{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/oidc.example/id/X"},` +
		`"Action":"sts:AssumeRoleWithWebIdentity","Condition":{` + condition + `}}`
}

func decryptGrant(condition string) string {
	return `{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*","Condition":{` + condition + `}}`
}

// fixKind: revoke when any granting statement is explicit, narrow when all
// are broad, revoke when none was found (it cannot be shown to be broad).
func TestFixKind(t *testing.T) {
	read := &grantTarget{action: "s3:GetObject", prefix: fkBucket + "/"}
	broad := statement(t, model.PolicyIdentity, `{"Effect":"Allow","Action":"s3:*","Resource":"*"}`)
	named := statement(t, model.PolicyIdentity, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`)
	for _, c := range []struct {
		name  string
		stmts []*model.Statement
		want  string
	}{
		{"all broad", []*model.Statement{broad}, graph.FixNarrow},
		{"one explicit", []*model.Statement{broad, named}, graph.FixRevoke},
		{"none found", nil, graph.FixRevoke},
	} {
		if got := fixKind(c.stmts, graph.SideIdentity, read); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
