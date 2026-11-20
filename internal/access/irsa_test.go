package access

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/eval"
	"github.com/r3oof-900/clapa/internal/iampolicy"
	"github.com/r3oof-900/clapa/internal/model"
)

func trust(t *testing.T, js string) *model.PolicyDocument {
	t.Helper()
	d, err := iampolicy.Parse([]byte(js), &iampolicy.Options{ID: "trust", Kind: model.PolicyResource})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestIRSARequestContext(t *testing.T) {
	sa := &model.ServiceAccount{Namespace: "payments", Name: "api", Audience: "sts.amazonaws.com"}
	c := &model.Cluster{Name: "prod", OIDCIssuer: "https://oidc.eks.us-east-1.amazonaws.com/id/X/"}
	req := IRSARequest(sa, c, "arn:aws:iam::111122223333:role/r", "111122223333", "aws")
	if req.Principal.ARN != "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/X" {
		t.Errorf("provider ARN %q", req.Principal.ARN)
	}
	if v := req.Context.Lookup("oidc.eks.us-east-1.amazonaws.com/id/X:sub"); v.Values[0] != "system:serviceaccount:payments:api" {
		t.Errorf("sub %+v", v)
	}
	doc := trust(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
		"Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/X"},
		"Action":"sts:AssumeRoleWithWebIdentity",
		"Condition":{"StringEquals":{"oidc.eks.us-east-1.amazonaws.com/id/X:sub":"system:serviceaccount:payments:api",
		"oidc.eks.us-east-1.amazonaws.com/id/X:amr":"x"}}}]}`)
	// :amr is not part of the IRSA request context, so it is unknown: never guessed.
	if d := eval.Evaluate(req, TrustPolicySet(doc)); d.Verdict != eval.Unknown {
		t.Errorf("unknown context keys must stay unknown: %s", d.Verdict)
	}
}

func TestPodIdentityRequest(t *testing.T) {
	doc := trust(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},
		"Action":["sts:AssumeRole","sts:TagSession"]}]}`)
	for _, action := range []string{"sts:AssumeRole", "sts:TagSession"} {
		req := PodIdentityRequest("arn:aws:iam::111122223333:role/r", "111122223333", action)
		if d := eval.Evaluate(req, TrustPolicySet(doc)); d.Verdict != eval.Allow {
			t.Errorf("%s: %s", action, d.Verdict)
		}
	}
	other := trust(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	if d := eval.Evaluate(PodIdentityRequest("arn:aws:iam::111122223333:role/r", "111122223333", "sts:AssumeRole"), TrustPolicySet(other)); d.Verdict != eval.ImplicitDeny {
		t.Errorf("a role not trusting pods.eks.amazonaws.com: %s", d.Verdict)
	}
}
