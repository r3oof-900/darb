package match

import (
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/arn"
	"github.com/r3oof-900/clapa/internal/model"
)

type stubExpander struct{}

func (stubExpander) ExpandPattern(s string, m arn.Mode) (arn.Pattern, model.Tri) {
	switch {
	case strings.Contains(s, "${unknown}"):
		return arn.Pattern{}, model.Unknown
	case strings.Contains(s, "${absent}"):
		return arn.Pattern{}, model.False
	}
	return arn.Compile(s, m), model.True
}

func TestAction(t *testing.T) {
	cases := []struct {
		patterns []string
		action   string
		want     bool
	}{
		{[]string{"s3:GetObject"}, "s3:getobject", true},
		{[]string{"S3:GET*"}, "s3:GetObject", true},
		{[]string{"kms:*"}, "kms:Decrypt", true},
		{[]string{"kms:Decrypt*"}, "kms:Decrypt", true},
		{[]string{"kms:Decrypt*"}, "kms:ReEncryptFrom", false},
		{[]string{"*"}, "iam:PassRole", true},
		{[]string{"s3:Get?bject"}, "s3:GetObject", true},
		{[]string{"s3:GetObject", "kms:Decrypt"}, "kms:Decrypt", true},
		{[]string{"ec2:*"}, "s3:GetObject", false},
	}
	for _, c := range cases {
		if got := Action(c.patterns, c.action); got != model.TriOf(c.want) {
			t.Errorf("Action(%v, %q) = %v, want %v", c.patterns, c.action, got, c.want)
		}
	}
}

func TestResource(t *testing.T) {
	x := stubExpander{}
	cases := []struct {
		patterns []string
		resource string
		want     model.Tri
	}{
		{[]string{"arn:aws:s3:::b/*"}, "arn:aws:s3:::b/k", model.True},
		{[]string{"arn:aws:s3:::b"}, "arn:aws:s3:::b/k", model.False},
		{[]string{"arn:aws:s3:::${unknown}/*"}, "arn:aws:s3:::b/k", model.Unknown},
		{[]string{"arn:aws:s3:::${unknown}/*", "arn:aws:s3:::b/*"}, "arn:aws:s3:::b/k", model.True},
		{[]string{"arn:aws:s3:::${absent}/*"}, "arn:aws:s3:::b/k", model.False},
	}
	for _, c := range cases {
		if got := Resource(c.patterns, c.resource, x); got != c.want {
			t.Errorf("Resource(%v, %q) = %v, want %v", c.patterns, c.resource, got, c.want)
		}
	}
}

const (
	acct    = "111122223333"
	other   = "444455556666"
	roleARN = "arn:aws:iam::111122223333:role/path/app"
	session = "arn:aws:sts::111122223333:assumed-role/app/s1"
	userARN = "arn:aws:iam::111122223333:user/alice"
	fedARN  = "arn:aws:sts::111122223333:federated-user/bob"
	oidc    = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/X"
)

func principals() map[string]*RequestPrincipal {
	return map[string]*RequestPrincipal{
		"session":   {Kind: KindAssumedRole, ARN: session, Account: acct, SourceARN: roleARN},
		"user":      {Kind: KindIAMUser, ARN: userARN, Account: acct},
		"federated": {Kind: KindFederatedUser, ARN: fedARN, Account: acct, SourceARN: userARN},
		"root":      {Kind: KindAccountRoot, ARN: arn.AccountRoot("aws", acct), Account: acct},
		"service":   {Kind: KindService, ARN: "s3.amazonaws.com"},
		"oidc":      {Kind: KindWebIdentity, ARN: oidc},
		"anonymous": {Kind: KindAnonymous},
		"canonical": {Kind: KindAnonymous, CanonicalUser: "c0ffee"},
		"foreign":   {Kind: KindAssumedRole, ARN: "arn:aws:sts::444455556666:assumed-role/x/s", Account: other, SourceARN: "arn:aws:iam::444455556666:role/x"},
	}
}

func spec(refs ...model.PrincipalRef) *model.PrincipalSpec {
	return model.NewPrincipalSpec(false, refs)
}

func aws(v string) model.PrincipalRef { return model.PrincipalRef{Type: model.PrincipalAWS, Value: v} }

func TestPrincipal(t *testing.T) {
	ps := principals()
	cases := []struct {
		name   string
		spec   *model.PrincipalSpec
		caller string
		want   model.Tri
		via    Via
	}{
		{"wildcard-string", model.NewPrincipalSpec(true, nil), "anonymous", model.True, ViaWildcard},
		{"aws-wildcard-session", spec(aws("*")), "session", model.True, ViaWildcard},
		{"aws-wildcard-anonymous", spec(aws("*")), "anonymous", model.True, ViaWildcard},
		{"aws-wildcard-service-unknown", spec(aws("*")), "service", model.Unknown, ViaNone},
		{"account-id", spec(aws(acct)), "session", model.True, ViaAccount},
		{"account-root-arn", spec(aws(arn.AccountRoot("aws", acct))), "user", model.True, ViaAccount},
		{"account-other", spec(aws(other)), "session", model.False, ViaNone},
		{"account-does-not-match-service", spec(aws(acct)), "service", model.False, ViaNone},
		{"role-arn-matches-its-sessions", spec(aws(roleARN)), "session", model.True, ViaRoleARN},
		{"role-arn-other-role", spec(aws("arn:aws:iam::111122223333:role/other")), "session", model.False, ViaNone},
		{"session-arn", spec(aws(session)), "session", model.True, ViaSessionARN},
		{"user-arn", spec(aws(userARN)), "user", model.True, ViaUserARN},
		{"user-arn-for-federated-session", spec(aws(userARN)), "federated", model.True, ViaFederatedUserCreator},
		{"federated-user-arn", spec(aws(fedARN)), "federated", model.True, ViaSessionARN},
		{"assumed-role-arn-not-user", spec(aws(session)), "user", model.False, ViaNone},
		{"federated-arn-not-session", spec(aws(fedARN)), "session", model.False, ViaNone},
		{"unique-id-unknown", spec(aws("AROAEXAMPLEID")), "session", model.Unknown, ViaNone},
		{"other-arn-kind", spec(aws("arn:aws:iam::111122223333:group/g")), "user", model.False, ViaNone},
		{"service", spec(model.PrincipalRef{Type: model.PrincipalService, Value: "S3.amazonaws.com"}), "service", model.True, ViaService},
		{"federated-oidc", spec(model.PrincipalRef{Type: model.PrincipalFederated, Value: oidc}), "oidc", model.True, ViaFederated},
		{"canonical-user", spec(model.PrincipalRef{Type: model.PrincipalCanonicalUser, Value: "c0ffee"}), "canonical", model.True, ViaCanonicalUser},
		{"canonical-user-empty-caller", spec(model.PrincipalRef{Type: model.PrincipalCanonicalUser, Value: "c0ffee"}), "anonymous", model.False, ViaNone},
		{"strongest-via-wins", spec(aws(acct), aws(roleARN)), "session", model.True, ViaRoleARN},
		{"true-beats-unknown", spec(aws("AROAX"), aws(acct)), "session", model.True, ViaAccount},
		{"partial-wildcard-is-literal", spec(aws("arn:aws:iam::111122223333:role/*")), "session", model.False, ViaNone},
		{"unrecognised-type-matches-nobody", spec(model.PrincipalRef{Type: "Bogus", Value: session}), "session", model.False, ViaNone},
		{"non-iam-arn-matches-nobody", spec(aws("arn:aws:s3:::bucket")), "session", model.False, ViaNone},
		{"other-sts-arn-matches-nobody", spec(aws("arn:aws:sts::111122223333:other/x")), "session", model.False, ViaNone},
	}
	for _, c := range cases {
		got := Principal(c.spec, ps[c.caller])
		if got.Value != c.want || got.Via != c.via {
			t.Errorf("%s: got %v via %d, want %v via %d", c.name, got.Value, got.Via, c.want, c.via)
		}
		if got.Value == model.Unknown && got.Reason == "" {
			t.Errorf("%s: Unknown without reason", c.name)
		}
	}
}

func TestNotPrincipal(t *testing.T) {
	ps := principals()
	cases := []struct {
		name   string
		spec   *model.PrincipalSpec
		caller string
		want   model.Tri
	}{
		{"wildcard-excludes-everyone", model.NewPrincipalSpec(true, nil), "session", model.False},
		{"aws-wildcard-excludes-everyone", spec(aws("*")), "session", model.False},
		{"session-role-and-account-excluded", spec(aws(session), aws(roleARN), aws(acct)), "session", model.False},
		{"session-and-account-without-role-unknown", spec(aws(session), aws(acct)), "session", model.Unknown},
		{"not-listed-applies", spec(aws(userARN)), "session", model.True},
		{"role-arn-does-not-exclude-session", spec(aws(roleARN), aws(acct)), "session", model.True},
		{"session-without-account-not-excluded", spec(aws(session)), "session", model.True},
		{"account-alone-does-not-exclude-user", spec(aws(acct)), "user", model.True},
		{"user-and-root-excluded", spec(aws(userARN), aws(arn.AccountRoot("aws", acct))), "user", model.False},
		{"root-listed-excludes-root", spec(aws(acct)), "root", model.False},
		{"service-listed", spec(model.PrincipalRef{Type: model.PrincipalService, Value: "s3.amazonaws.com"}), "service", model.False},
		{"service-not-listed", spec(aws(acct)), "service", model.True},
		{"oidc-listed", spec(model.PrincipalRef{Type: model.PrincipalFederated, Value: oidc}), "oidc", model.False},
		{"canonical-listed", spec(model.PrincipalRef{Type: model.PrincipalCanonicalUser, Value: "c0ffee"}), "canonical", model.False},
		{"foreign-not-listed", spec(aws(session), aws(acct)), "foreign", model.True},
		{"unrecognised-type-identifies-nobody", spec(model.PrincipalRef{Type: "Bogus", Value: "s3.amazonaws.com"}), "service", model.True},
	}
	for _, c := range cases {
		got := NotPrincipal(c.spec, ps[c.caller])
		if got.Value != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got.Value, c.want)
		}
		if got.Value == model.Unknown && got.Reason == "" {
			t.Errorf("%s: Unknown without reason", c.name)
		}
	}
}

func TestUnresolvedSourceValues(t *testing.T) {
	u := model.UnresolvedPlaceholder("var.x")
	if got := Action([]string{u}, "s3:GetObject"); got != model.Unknown {
		t.Errorf("unresolved action: %v", got)
	}
	if got := Action([]string{u, "s3:*"}, "s3:GetObject"); got != model.True {
		t.Errorf("a resolved match decides: %v", got)
	}
	ps := principals()
	if m := Principal(spec(model.PrincipalRef{Type: model.PrincipalService, Value: u}), ps["service"]); m.Value != model.Unknown || m.Reason == "" {
		t.Errorf("unresolved principal: %+v", m)
	}
	if m := NotPrincipal(spec(aws(u), aws(acct)), ps["session"]); m.Value != model.Unknown {
		t.Errorf("unresolved NotPrincipal entry: %+v", m)
	}
	excluded := spec(aws(session), aws(roleARN), aws(acct), aws(u))
	if m := NotPrincipal(excluded, ps["session"]); m.Value != model.False {
		t.Errorf("already excluded: %+v", m)
	}
}

func TestUnresolvedCaller(t *testing.T) {
	caller := &RequestPrincipal{Kind: KindWebIdentity, ARN: model.UnresolvedPlaceholder("oidc_provider")}
	fed := spec(model.PrincipalRef{Type: model.PrincipalFederated, Value: oidc})
	if m := Principal(fed, caller); m.Value != model.Unknown || m.Reason == "" {
		t.Errorf("unresolved caller vs Principal: %+v", m)
	}
	if m := NotPrincipal(fed, caller); m.Value != model.Unknown {
		t.Errorf("unresolved caller vs NotPrincipal: %+v", m)
	}
	if m := NotPrincipal(model.NewPrincipalSpec(true, nil), caller); m.Value != model.False {
		t.Errorf("NotPrincipal * excludes everyone, resolved or not: %+v", m)
	}
}

func TestValueWithUnresolvedParts(t *testing.T) {
	u := model.UnresolvedPlaceholder("var.env")
	cases := []struct {
		pattern, value string
		want           model.Tri
	}{
		{"arn:aws:s3:::prod-pii/*", "arn:aws:s3:::" + u + "-pii/report.csv", model.Unknown}, // could be prod, could be dev
		{"arn:aws:s3:::*", "arn:aws:s3:::" + u + "-pii/report.csv", model.True},             // matches whatever it is
		{"arn:aws:kms:*", "arn:aws:s3:::" + u + "-pii/report.csv", model.False},             // can never match
		{"arn:aws:s3:::data/*", "arn:aws:s3:::data/k", model.True},                          // known value: exact
		{"arn:aws:s3:::data/x", "arn:aws:s3:::data/k", model.False},
	}
	for _, c := range cases {
		if got := Value(arn.Compile(c.pattern, arn.Resource), c.value); got != c.want {
			t.Errorf("Value(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
	if got := Resource([]string{"arn:aws:s3:::prod-pii/*"}, "arn:aws:s3:::"+u+"-pii/k", stubExpander{}); got != model.Unknown {
		t.Errorf("Resource with an unresolved request resource: %v", got)
	}
}
