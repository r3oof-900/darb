package eval

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/eval/match"
	"github.com/r3oof-900/clapa/internal/model"
)

func TestNilContextMeansEveryKeyUnknown(t *testing.T) {
	ps := &PolicySet{Identity: []*model.PolicyDocument{mustDoc(t, "id", model.PolicyIdentity, []map[string]any{{
		"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
		"Condition": map[string]any{"Bool": map[string]any{"aws:SecureTransport": "true"}},
	}})}}
	req := &Request{
		Principal: match.RequestPrincipal{Kind: match.KindIAMUser, ARN: "arn:aws:iam::111122223333:user/a", Account: "111122223333"},
		Action:    "s3:GetObject", Resource: "arn:aws:s3:::b/k", ResourceAccount: "111122223333",
	}
	if d := Evaluate(req, ps); d.Verdict != Unknown {
		t.Fatalf("nil context: got %s, want UNKNOWN", d.Verdict)
	}
}

func TestEnumStringsAndInvalidValues(t *testing.T) {
	for v, want := range map[Verdict]string{Allow: "ALLOW", Deny: "DENY", Unknown: "UNKNOWN", ImplicitDeny: "IMPLICIT_DENY", Verdict(9): "INVALID"} {
		if v.String() != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", v, v.String(), want)
		}
	}
	for v, want := range map[Verdict]int{Allow: 2, Unknown: 1, Deny: 0, ImplicitDeny: 0, Verdict(9): 0} {
		if v.Grants() != want {
			t.Errorf("Verdict(%d).Grants() = %d, want %d", v, v.Grants(), want)
		}
	}
	for c, want := range map[Component]string{
		CompIdentity: "identity policy", CompResource: "resource-based policy", CompBoundary: "permissions boundary",
		CompSession: "session policy", CompSCP: "service control policy", CompRCP: "resource control policy", Component(0): "invalid",
	} {
		if c.String() != want {
			t.Errorf("Component(%d).String() = %q, want %q", c, c.String(), want)
		}
	}
}

func TestUnknownMatchKindFallsIntoMostPermissiveBucket(t *testing.T) {
	g := grantSet{resUnlimited: model.False}
	g.addResource(model.True, match.Via(99))
	if g.resUnlimited != model.True {
		t.Fatal("a grant with an unrecognised match kind must not be dropped")
	}
}
