package access

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/graph"
	"github.com/r3oof-900/clapa/internal/model"
)

// policyFixes prices each side of a policy-decided edge (SCORING.md §4).
func TestPolicyFixesSides(t *testing.T) {
	const (
		bucket = "arn:aws:s3:::b"
		roleA  = "arn:aws:iam::111111111111:role/r"
	)
	bucketPolicy := trust(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
		"Principal":{"AWS":"arn:aws:iam::111111111111:role/r"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`)
	role := model.NewPrincipal(model.KindIAMRole, roleA, "111111111111", &model.SourceLocation{})
	anyPerm := model.NewPrincipal(model.KindIAMRoleAnyPermission, roleA, "111111111111", &model.SourceLocation{})
	request := func(account string) *eval.Request {
		return &eval.Request{
			Principal: match.RequestPrincipal{Kind: match.KindAssumedRole, ARN: "arn:aws:sts::111111111111:assumed-role/r/s", Account: "111111111111", SourceARN: roleA},
			Action:    "s3:GetObject", Resource: bucket + "/k", ResourceAccount: account,
		}
	}
	identityOnly := &eval.PolicySet{Identity: []*model.PolicyDocument{allowAll()}}
	both := &eval.PolicySet{Identity: []*model.PolicyDocument{allowAll()}, Resource: []*model.PolicyDocument{bucketPolicy}}
	cases := []struct {
		name       string
		who        *model.Principal
		account    string
		set        *eval.PolicySet
		canRewrite bool
		want       []string
	}{
		// Same account, identity grant only: the identity side.
		{"identity", role, "111111111111", identityOnly, false, []string{graph.SideIdentity}},
		// Same account and it can rewrite the bucket policy: it writes the
		// grant back on the bucket; nothing holds.
		{"same-account re-grant", role, "111111111111", identityOnly, true, nil},
		// Cross account: both grants are needed, so each side breaks it.
		{"cross-account", role, "222222222222", both, false, []string{graph.SideIdentity, graph.SideResource}},
		// Cross account and it can rewrite the bucket policy: the identity
		// grant is still required, so that side holds; the resource side does not.
		{"cross-account rewrite", role, "222222222222", both, true, []string{graph.SideIdentity}},
		// A role with any permission grants itself again: no identity side.
		{"any permission", anyPerm, "222222222222", both, false, []string{graph.SideResource}},
		// No known principal: no identity side.
		{"no principal", nil, "222222222222", both, false, []string{graph.SideResource}},
	}
	b := &builder{}
	for _, c := range cases {
		got := b.policyFixes(graph.CanRead, request(c.account), c.set, c.who, bucket, "bucket policy", c.canRewrite)
		var sides []string
		for _, f := range got {
			sides = append(sides, f.Side)
		}
		if len(sides) != len(c.want) {
			t.Errorf("%s: sides %v, want %v", c.name, sides, c.want)
			continue
		}
		for i := range sides {
			if sides[i] != c.want[i] {
				t.Errorf("%s: sides %v, want %v", c.name, sides, c.want)
			}
		}
		for _, f := range got {
			if f.Side == graph.SideResource && (f.Resource != bucket || f.Policy != bucket+" bucket policy" || f.Cost != 2) {
				t.Errorf("%s: resource fix %+v", c.name, f)
			}
			if f.Side == graph.SideIdentity && (f.Policy != "clapa:any-permission" || f.Cost != 1) {
				t.Errorf("%s: identity fix %+v", c.name, f)
			}
		}
	}
}
