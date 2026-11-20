package condition

import (
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/arn"
	"github.com/r3oof-900/clapa/internal/model"
)

// stubExpander treats "${absent}" as a reference to an absent key and
// "${unknown}" as an unresolved one; everything else is literal/wildcard text.
type stubExpander struct{}

func (stubExpander) ExpandString(s string) (string, model.Tri) {
	switch {
	case strings.Contains(s, "${unknown}"):
		return "", model.Unknown
	case strings.Contains(s, "${absent}"):
		return "", model.False
	}
	return s, model.True
}

func (stubExpander) ExpandPattern(s string, m arn.Mode) (arn.Pattern, model.Tri) {
	str, ok := stubExpander{}.ExpandString(s)
	return arn.Compile(str, m), ok
}

func ctx() *Context {
	return NewContext(&Input{
		Default: StateAbsent,
		Present: map[string][]string{
			"aws:username":         {"alice"},
			"aws:SourceIp":         {"203.0.113.7"},
			"aws:SourceIpV6":       {"2001:db8::1"},
			"aws:MultiFactorAge":   {"300"},
			"aws:CurrentTime":      {"2026-11-20T10:00:00Z"},
			"aws:SecureTransport":  {"true"},
			"aws:SourceArn":        {"arn:aws:s3:::bucket-a"},
			"aws:TagKeys":          {"team", "env"},
			"aws:EmptySet":         {},
			"blob":                 {"aGVsbG8="},
			"bad:number":           {"twelve"},
			"bad:ip":               {"not-an-ip"},
			"aws:PrincipalOrgPath": {"o-1/r-1/ou-a/"},
		},
		Unknown: []string{"aws:PrincipalOrgID"},
	})
}

func eval(op, key string, values ...string) model.Tri {
	c := model.NewCondition(op, key, values)
	return Evaluate(&c, ctx(), stubExpander{}).Value
}

func TestOperators(t *testing.T) {
	T, F, U := model.True, model.False, model.Unknown
	cases := []struct {
		name, op, key string
		values        []string
		want          model.Tri
	}{
		// String family.
		{"string-equals", "StringEquals", "aws:username", []string{"alice"}, T},
		{"string-equals-is-case-sensitive", "StringEquals", "aws:username", []string{"Alice"}, F},
		{"string-equals-multiple-values-or", "StringEquals", "aws:username", []string{"bob", "alice"}, T},
		{"string-not-equals-nor", "StringNotEquals", "aws:username", []string{"bob", "alice"}, F},
		{"string-not-equals-true", "StringNotEquals", "aws:username", []string{"bob"}, T},
		{"string-equals-ignore-case", "StringEqualsIgnoreCase", "aws:username", []string{"ALICE"}, T},
		{"string-not-equals-ignore-case", "StringNotEqualsIgnoreCase", "aws:username", []string{"ALICE"}, F},
		{"string-like-wildcard", "StringLike", "aws:username", []string{"al*"}, T},
		{"string-like-question", "StringLike", "aws:username", []string{"alic?"}, T},
		{"string-not-like", "StringNotLike", "aws:username", []string{"bo*"}, T},
		{"string-equals-star-is-literal", "StringEquals", "aws:username", []string{"*"}, F},
		// Absent keys (Default: absent).
		{"absent-positive-false", "StringEquals", "aws:missing", []string{"x"}, F},
		{"absent-negated-true", "StringNotEquals", "aws:missing", []string{"x"}, T},
		{"absent-ifexists-true", "StringEqualsIfExists", "aws:missing", []string{"x"}, T},
		{"present-ifexists-compares", "StringEqualsIfExists", "aws:username", []string{"bob"}, F},
		// Unknown key, operator, values.
		{"unknown-key", "StringEquals", "aws:PrincipalOrgID", []string{"o-1"}, U},
		{"unknown-key-ifexists-still-unknown", "StringEqualsIfExists", "aws:PrincipalOrgID", []string{"o-1"}, U},
		{"unsupported-operator", "StringEqualz", "aws:username", []string{"alice"}, U},
		{"empty-value-list", "StringEquals", "aws:username", nil, U},
		{"multivalued-without-qualifier", "StringEquals", "aws:TagKeys", []string{"team"}, U},
		{"unresolved-variable", "StringEquals", "aws:username", []string{"${unknown}"}, U},
		{"absent-variable-matches-nothing", "StringEquals", "aws:username", []string{"${absent}"}, F},
		{"unresolved-variable-like", "StringLike", "aws:username", []string{"${unknown}*"}, U},
		{"unresolved-variable-but-other-value-matches", "StringEquals", "aws:username", []string{"${unknown}", "alice"}, T},
		// Numeric.
		{"numeric-less-than", "NumericLessThan", "aws:MultiFactorAge", []string{"3600"}, T},
		{"numeric-less-than-equals", "NumericLessThanEquals", "aws:MultiFactorAge", []string{"300"}, T},
		{"numeric-greater-than", "NumericGreaterThan", "aws:MultiFactorAge", []string{"300"}, F},
		{"numeric-greater-than-equals", "NumericGreaterThanEquals", "aws:MultiFactorAge", []string{"300"}, T},
		{"numeric-equals-float", "NumericEquals", "aws:MultiFactorAge", []string{"300.0"}, T},
		{"numeric-not-equals", "NumericNotEquals", "aws:MultiFactorAge", []string{"300"}, F},
		{"numeric-bad-policy-value", "NumericEquals", "aws:MultiFactorAge", []string{"x"}, U},
		{"numeric-bad-request-value", "NumericEquals", "bad:number", []string{"12"}, U},
		// Date.
		{"date-less-than", "DateLessThan", "aws:CurrentTime", []string{"2027-01-01T00:00:00Z"}, T},
		{"date-greater-than-plain-date", "DateGreaterThan", "aws:CurrentTime", []string{"2026-11-20"}, T},
		{"date-epoch", "DateGreaterThanEquals", "aws:CurrentTime", []string{"1700000000"}, T},
		{"date-minutes-layout", "DateEquals", "aws:CurrentTime", []string{"2026-11-20T10:00Z"}, T},
		{"date-not-equals", "DateNotEquals", "aws:CurrentTime", []string{"2026-11-20T10:00:00Z"}, F},
		{"date-less-than-equals", "DateLessThanEquals", "aws:CurrentTime", []string{"2026-11-20T10:00:00Z"}, T},
		{"date-bad", "DateEquals", "aws:CurrentTime", []string{"yesterday"}, U},
		// Bool, Binary.
		{"bool-true", "Bool", "aws:SecureTransport", []string{"true"}, T},
		{"bool-case-insensitive", "Bool", "aws:SecureTransport", []string{"TRUE"}, T},
		{"bool-false", "Bool", "aws:SecureTransport", []string{"false"}, F},
		{"bool-bad", "Bool", "aws:SecureTransport", []string{"yes"}, U},
		{"bool-absent", "Bool", "aws:missing", []string{"true"}, F},
		{"bool-ifexists-absent", "BoolIfExists", "aws:missing", []string{"false"}, T},
		{"binary-equals", "BinaryEquals", "blob", []string{"aGVsbG8="}, T},
		{"binary-differs", "BinaryEquals", "blob", []string{"d29ybGQ="}, F},
		{"binary-bad", "BinaryEquals", "blob", []string{"!!"}, U},
		// IP.
		{"ip-in-cidr", "IpAddress", "aws:SourceIp", []string{"203.0.113.0/24"}, T},
		{"ip-not-in-cidr", "IpAddress", "aws:SourceIp", []string{"198.51.100.0/24"}, F},
		{"ip-single-host", "IpAddress", "aws:SourceIp", []string{"203.0.113.7"}, T},
		{"ip-non-canonical-cidr", "IpAddress", "aws:SourceIp", []string{"203.0.113.9/24"}, T},
		{"not-ip-address", "NotIpAddress", "aws:SourceIp", []string{"203.0.113.0/24"}, F},
		{"ipv6", "IpAddress", "aws:SourceIpV6", []string{"2001:db8::/32"}, T},
		{"ipv4-not-in-ipv6", "IpAddress", "aws:SourceIp", []string{"2001:db8::/32"}, F},
		{"ip-bad-policy", "IpAddress", "aws:SourceIp", []string{"300.1.1.1/8"}, U},
		{"ip-bad-request", "IpAddress", "bad:ip", []string{"10.0.0.0/8"}, U},
		// ARN.
		{"arn-equals", "ArnEquals", "aws:SourceArn", []string{"arn:aws:s3:::bucket-a"}, T},
		{"arn-like-wildcard-segment", "ArnLike", "aws:SourceArn", []string{"arn:aws:s3:::bucket-*"}, T},
		{"arn-equals-accepts-wildcards", "ArnEquals", "aws:SourceArn", []string{"arn:aws:*:::bucket-a"}, T},
		{"arn-like-case-sensitive", "ArnLike", "aws:SourceArn", []string{"arn:aws:s3:::Bucket-a"}, F},
		{"arn-not-like", "ArnNotLike", "aws:SourceArn", []string{"arn:aws:s3:::other"}, T},
		{"arn-not-equals", "ArnNotEquals", "aws:SourceArn", []string{"arn:aws:s3:::bucket-a"}, F},
		{"arn-like-not-an-arn", "ArnLike", "aws:username", []string{"arn:aws:s3:::*"}, F},
		{"arn-like-short-pattern", "ArnLike", "aws:SourceArn", []string{"arn:aws:s3"}, F},
		{"arn-star-does-not-cross-segments", "ArnLike", "aws:SourceArn", []string{"arn:*:bucket-a"}, F},
		// Null.
		{"null-true-absent", "Null", "aws:missing", []string{"true"}, T},
		{"null-true-present", "Null", "aws:username", []string{"true"}, F},
		{"null-false-present", "Null", "aws:username", []string{"false"}, T},
		{"null-empty-set-is-absent", "Null", "aws:EmptySet", []string{"true"}, T},
		{"null-unknown", "Null", "aws:PrincipalOrgID", []string{"true"}, U},
		{"null-bad-value", "Null", "aws:username", []string{"maybe"}, U},
		{"null-ifexists-invalid", "NullIfExists", "aws:username", []string{"true"}, U},
		{"null-set-qualifier-invalid", "ForAnyValue:Null", "aws:username", []string{"true"}, U},
	}
	for _, c := range cases {
		if got := eval(c.op, c.key, c.values...); got != c.want {
			t.Errorf("%s: %s %s %v = %v, want %v", c.name, c.op, c.key, c.values, got, c.want)
		}
	}
}

func TestSetOperators(t *testing.T) {
	T, F, U := model.True, model.False, model.Unknown
	cases := []struct {
		name, op, key string
		values        []string
		want          model.Tri
	}{
		{"for-any-value-match", "ForAnyValue:StringEquals", "aws:TagKeys", []string{"team"}, T},
		{"for-any-value-no-match", "ForAnyValue:StringEquals", "aws:TagKeys", []string{"cost"}, F},
		{"for-any-value-absent-false", "ForAnyValue:StringEquals", "aws:missing", []string{"team"}, F},
		{"for-any-value-ifexists-absent-true", "ForAnyValue:StringEqualsIfExists", "aws:missing", []string{"x"}, T},
		{"for-any-value-empty-set-false", "ForAnyValue:StringEquals", "aws:EmptySet", []string{"x"}, F},
		{"for-any-value-negated", "ForAnyValue:StringNotEquals", "aws:TagKeys", []string{"team"}, T},
		{"for-all-values-subset", "ForAllValues:StringEquals", "aws:TagKeys", []string{"team", "env", "cost"}, T},
		{"for-all-values-not-subset", "ForAllValues:StringEquals", "aws:TagKeys", []string{"team"}, F},
		{"for-all-values-absent-true", "ForAllValues:StringEquals", "aws:missing", []string{"team"}, T},
		{"for-all-values-empty-set-true", "ForAllValues:StringEquals", "aws:EmptySet", []string{"team"}, T},
		{"for-all-values-like", "ForAllValues:StringLike", "aws:TagKeys", []string{"*"}, T},
		{"for-all-values-unknown", "ForAllValues:StringEquals", "aws:TagKeys", []string{"${unknown}"}, U},
		{"for-any-value-unknown", "ForAnyValue:StringEquals", "aws:TagKeys", []string{"${unknown}"}, U},
		{"for-any-value-single-valued-key", "ForAnyValue:StringLike", "aws:PrincipalOrgPath", []string{"o-1/*"}, T},
	}
	for _, c := range cases {
		if got := eval(c.op, c.key, c.values...); got != c.want {
			t.Errorf("%s: %s %s %v = %v, want %v", c.name, c.op, c.key, c.values, got, c.want)
		}
	}
}

func TestUnknownCarriesReason(t *testing.T) {
	c := model.NewCondition("StringEquals", "aws:PrincipalOrgID", []string{"o-1"})
	res := Evaluate(&c, ctx(), stubExpander{})
	if res.Value != model.Unknown || !strings.Contains(res.Reason, "aws:PrincipalOrgID") {
		t.Fatalf("got %+v", res)
	}
	c = model.NewCondition("ForAnyValue:StringEquals", "aws:TagKeys", []string{"${unknown}"})
	if res = Evaluate(&c, ctx(), stubExpander{}); res.Reason == "" {
		t.Fatal("set-operator Unknown must keep a reason")
	}
	c = model.NewCondition("StringEquals", "aws:username", []string{"alice"})
	if res = Evaluate(&c, ctx(), stubExpander{}); res.Reason != "" {
		t.Fatalf("decided results carry no reason, got %q", res.Reason)
	}
}

func TestContextSemantics(t *testing.T) {
	c := NewContext(&Input{
		Default: StatePresent, // invalid default degrades to Unknown
		Present: map[string][]string{"K": {"v"}, "both": {"x"}},
		Absent:  []string{"both", "gone"},
		Unknown: []string{"k"},
	})
	if c.Lookup("other").State != StateUnknown {
		t.Error("invalid default must become Unknown")
	}
	if c.Lookup("k").State != StateUnknown {
		t.Error("Unknown must win over Present for the same (case-insensitive) key")
	}
	if v := c.Lookup("BOTH"); v.State != StatePresent || v.Values[0] != "x" {
		t.Error("Present must win over Absent")
	}
	if c.Lookup("gone").State != StateAbsent {
		t.Error("absent key")
	}
}

func TestParseOperator(t *testing.T) {
	op, ok := ParseOperator("ForAllValues:NumericGreaterThanEqualsIfExists")
	if !ok || op.Set != SetAllValues || !op.IfExists || op.Family != FamilyNumeric || op.Cmp != CmpGreaterEquals {
		t.Fatalf("got %+v %v", op, ok)
	}
	for _, bad := range []string{"", "stringequals", "NumericFoo", "DateBar", "ForAnyValue:", "IfExists", "Numeric"} {
		if _, ok := ParseOperator(bad); ok {
			t.Errorf("%q must not parse", bad)
		}
	}
}

func TestUnresolvedConditionKey(t *testing.T) {
	c := model.NewCondition("StringEquals", model.UnresolvedPlaceholder("local.oidc")+":sub", []string{"x"})
	if res := Evaluate(&c, ctx(), stubExpander{}); res.Value != model.Unknown || res.Reason == "" {
		t.Fatalf("got %+v", res)
	}
}

func TestUnresolvedRequestValue(t *testing.T) {
	c := NewContext(&Input{Default: StateAbsent, Present: map[string][]string{
		"aws:SourceArn": {"arn:aws:eks:us-east-1:" + model.UnresolvedPlaceholder("account") + ":cluster/prod"},
	}})
	cond := model.NewCondition("ArnLike", "aws:SourceArn", []string{"arn:aws:eks:us-east-1:111122223333:cluster/*"})
	if res := Evaluate(&cond, c, stubExpander{}); res.Value != model.Unknown || res.Reason == "" {
		t.Fatalf("got %+v", res)
	}
}

// A request value with unresolved parts is decided by the case-sensitive
// string operators on its known parts (DESIGN.md §4.6, scenario 3).
func TestPartlyUnknownRequestValue(t *testing.T) {
	obj := "arn:aws:s3:::pii/" + model.UnresolvedPlaceholder("object-key")
	c := NewContext(&Input{Default: StateAbsent, Present: map[string][]string{"ctx": {obj}, "num": {model.UnresolvedPlaceholder("n")}}})
	cases := []struct {
		op, key, value string
		want           model.Tri
	}{
		{"StringEquals", "ctx", "arn:aws:s3:::receipts", model.False},
		{"StringEquals", "ctx", "arn:aws:s3:::pii/a.csv", model.Unknown},
		{"StringNotEquals", "ctx", "arn:aws:s3:::receipts", model.True},
		{"StringLike", "ctx", "arn:aws:s3:::pii/*", model.True},
		{"StringLike", "ctx", "arn:aws:s3:::receipts/*", model.False},
		{"StringLike", "ctx", "arn:aws:s3:::pii/2026/*", model.Unknown},
		{"StringEquals", "ctx", "${unknown}", model.Unknown},
		{"StringLike", "ctx", "${unknown}/*", model.Unknown},
		{"StringEqualsIgnoreCase", "ctx", "arn:aws:s3:::receipts", model.Unknown},
		{"NumericEquals", "num", "1", model.Unknown},
	}
	for _, tc := range cases {
		cond := model.NewCondition(tc.op, tc.key, []string{tc.value})
		res := Evaluate(&cond, c, stubExpander{})
		if res.Value != tc.want || (res.Value == model.Unknown) != (res.Reason != "") {
			t.Errorf("%s %s %q: %+v, want %s", tc.op, tc.key, tc.value, res, tc.want)
		}
	}
}
