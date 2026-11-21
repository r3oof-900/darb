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

// Granting: the Allow statements that apply (TRUE or UNKNOWN); never a Deny,
// never an Allow that does not apply.
func TestGranting(t *testing.T) {
	d := mustDoc(t, "id", model.PolicyIdentity, []map[string]any{
		{"Sid": "Applies", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
		{
			"Sid": "Unknown", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
			"Condition": map[string]any{"Bool": map[string]any{"aws:SecureTransport": "true"}},
		},
		{"Sid": "OtherAction", "Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"},
		{"Sid": "Deny", "Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"},
	})
	req := &Request{
		Principal: match.RequestPrincipal{Kind: match.KindIAMUser, ARN: "arn:aws:iam::111122223333:user/a", Account: "111122223333"},
		Action:    "s3:GetObject", Resource: "arn:aws:s3:::b/k", ResourceAccount: "111122223333",
	}
	var sids []string
	for _, s := range Granting(req, []*model.PolicyDocument{d}) {
		sids = append(sids, s.Sid())
	}
	if len(sids) != 2 || sids[0] != "Applies" || sids[1] != "Unknown" {
		t.Fatalf("granting statements: %v", sids)
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

// DenyOnly (DESIGN.md 6.2): an UNKNOWN whose required allows all hold is
// deny-only; one that needs an unknown allow is not; no other verdict is.
func TestDenyOnly(t *testing.T) {
	unknown := map[string]any{"Bool": map[string]any{"aws:SecureTransport": "true"}}
	allow := map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
	unknownAllow := map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": unknown}
	unknownDeny := map[string]any{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*", "Condition": unknown}
	req := &Request{
		Principal: match.RequestPrincipal{Kind: match.KindIAMUser, ARN: "arn:aws:iam::111122223333:user/a", Account: "111122223333"},
		Action:    "s3:GetObject", Resource: "arn:aws:s3:::b/k", ResourceAccount: "111122223333",
	}
	for name, c := range map[string]struct {
		stmts    []map[string]any
		verdict  Verdict
		denyOnly bool
	}{
		"allow and unknown deny":      {[]map[string]any{allow, unknownDeny}, Unknown, true},
		"only an unknown allow":       {[]map[string]any{unknownAllow}, Unknown, false},
		"unknown allow, unknown deny": {[]map[string]any{unknownAllow, unknownDeny}, Unknown, false},
		"allow":                       {[]map[string]any{allow}, Allow, false},
		"unknown deny, nothing else":  {[]map[string]any{unknownDeny}, ImplicitDeny, false},
	} {
		d := Evaluate(req, &PolicySet{Identity: []*model.PolicyDocument{mustDoc(t, "id", model.PolicyIdentity, c.stmts)}})
		if d.Verdict != c.verdict || d.DenyOnly != c.denyOnly {
			t.Errorf("%s: %s deny-only=%v, want %s %v", name, d.Verdict, d.DenyOnly, c.verdict, c.denyOnly)
		}
	}
}
