package eval

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/eval/condition"
	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/iampolicy"
	"github.com/r3oof-900/clapa/internal/model"
)

// FuzzEvaluate: any parsable policy, used as identity, resource and boundary
// policy, with any action and resource, must evaluate without panicking and
// yield a valid verdict.
func FuzzEvaluate(f *testing.F) {
	f.Add([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::${aws:username}/*","Condition":{"ForAnyValue:StringLike":{"aws:TagKeys":["${aws:PrincipalTag/x, 'd'}*"]}}}]}`),
		"s3:GetObject", "arn:aws:s3:::alice/k", uint8(0))
	f.Add([]byte(`{"Statement":{"Effect":"Deny","NotPrincipal":{"AWS":["111122223333","arn:aws:sts::111122223333:assumed-role/r/s"]},"NotAction":"iam:*","NotResource":"*"}}`),
		"kms:Decrypt", "*", uint8(3))
	f.Fuzz(func(t *testing.T, policy []byte, action, resource string, kind uint8) {
		if len(action) > 256 || len(resource) > 512 {
			return
		}
		ps := &PolicySet{ResourcePolicyRequired: kind%2 == 0}
		if d, err := iampolicy.Parse(policy, &iampolicy.Options{ID: "id", Kind: model.PolicyIdentity, Placeholders: true}); err == nil {
			ps.Identity = []*model.PolicyDocument{d}
			ps.Boundary = d
		}
		if d, err := iampolicy.Parse(policy, &iampolicy.Options{ID: "res", Kind: model.PolicyResource, Placeholders: true}); err == nil {
			ps.Resource = []*model.PolicyDocument{d}
		}
		kinds := []match.PrincipalKind{
			match.KindAssumedRole, match.KindIAMUser, match.KindFederatedUser,
			match.KindAccountRoot, match.KindService, match.KindWebIdentity, match.KindAnonymous,
		}
		req := &Request{
			Principal: match.RequestPrincipal{
				Kind: kinds[int(kind)%len(kinds)], ARN: "arn:aws:sts::111122223333:assumed-role/r/s",
				Account: "111122223333", SourceARN: "arn:aws:iam::111122223333:role/r",
			},
			Action: action, Resource: resource, ResourceAccount: "111122223333",
			Context: condition.NewContext(&condition.Input{Present: map[string][]string{"aws:username": {"alice"}, "aws:TagKeys": {"a", "b"}}}),
		}
		d := Evaluate(req, ps)
		if d.Verdict.String() == "INVALID" {
			t.Fatalf("invalid verdict %d", d.Verdict)
		}
	})
}
