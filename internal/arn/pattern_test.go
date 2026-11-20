package arn

import (
	"strings"
	"testing"
)

func TestResourcePatterns(t *testing.T) {
	// Each case names the documented rule it encodes
	// (IAM User Guide › "IAM JSON policy elements: Resource").
	cases := []struct {
		name, pattern, value string
		want                 bool
	}{
		{"bucket-arn-is-not-object-arn", "arn:aws:s3:::b", "arn:aws:s3:::b/k", false},
		{"object-wildcard-does-not-match-bucket", "arn:aws:s3:::b/*", "arn:aws:s3:::b", false},
		{"object-wildcard-matches-object", "arn:aws:s3:::b/*", "arn:aws:s3:::b/a/b/c", true},
		{"arns-are-case-sensitive", "arn:aws:s3:::B/*", "arn:aws:s3:::b/k", false},
		{"star-alone-matches-everything", "*", "arn:aws:kms:us-east-1:111122223333:key/k", true},
		{"star-in-middle-stays-in-segment", "arn:aws:iam::1*3:role/r", "arn:aws:iam::1:2:3:role/r", false},
		{"star-at-segment-end-spans-colons", "arn:aws:logs:us-east-1:111122223333:log-group:*", "arn:aws:logs:us-east-1:111122223333:log-group:g:log-stream:s", true},
		{"star-before-colon-spans", "arn:aws:ec2:*:111122223333:instance/i", "arn:aws:ec2:us-east-1:111122223333:instance/i", true},
		{"question-matches-one-character", "arn:aws:s3:::b?/k", "arn:aws:s3:::b1/k", true},
		{"question-does-not-match-colon", "arn:aws:iam::11112222333?:root", "arn:aws:iam::11112222333::root", false},
		{"question-needs-exactly-one", "arn:aws:s3:::b?", "arn:aws:s3:::b", false},
		{"empty-region-segment", "arn:aws:s3:::*", "arn:aws:s3:::any/key", true},
		{"other-service-not-matched", "arn:aws:s3:::*", "arn:aws:kms:us-east-1:1:key/k", false},
		{"multiple-stars", "arn:aws:s3:::b/*/x/*", "arn:aws:s3:::b/a/x/y", true},
		{"literal-mismatch-after-star", "arn:aws:s3:::b/*.csv", "arn:aws:s3:::b/a.txt", false},
	}
	for _, c := range cases {
		if got := Compile(c.pattern, Resource).Match(c.value); got != c.want {
			t.Errorf("%s: Compile(%q).Match(%q) = %v, want %v", c.name, c.pattern, c.value, got, c.want)
		}
	}
}

func TestPlainPatterns(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"s3:get*", "s3:getobject", true},
		{"*", "", true},
		{"", "", true},
		{"", "a", false},
		{"kms:decrypt*", "kms:decrypt", true},
		{"kms:decrypt*", "kms:reencryptfrom", false},
		{"*object", "s3:getobject", true},
		{"?", ":", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"é?", "éß", true},
	}
	for _, c := range cases {
		if got := Compile(c.pattern, Plain).Match(c.value); got != c.want {
			t.Errorf("Compile(%q, Plain).Match(%q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestLiteralAndAppend(t *testing.T) {
	lit := Literal("a*?", Plain)
	if lit.HasWildcard() {
		t.Error("Literal must have no wildcards")
	}
	if !lit.Match("a*?") || lit.Match("abc") {
		t.Error("Literal must match only itself")
	}
	p := Compile("arn:aws:s3:::", Resource).Append(Literal("team*", Resource)).Append(Compile("/*", Resource))
	if !p.HasWildcard() {
		t.Error("appended pattern lost its wildcard")
	}
	if !p.Match("arn:aws:s3:::team*/k") || p.Match("arn:aws:s3:::teamX/k") {
		t.Error("Append must keep literal '*' from Literal")
	}
	if got := p.String(); got != "arn:aws:s3:::team${*}/*" {
		t.Errorf("String() = %q", got)
	}
	if got := Compile("a?b", Plain).String(); got != "a?b" {
		t.Errorf("String() = %q", got)
	}
	if got := Literal("?", Plain).String(); got != "${?}" {
		t.Errorf("String() = %q", got)
	}
}

func TestSplitN(t *testing.T) {
	parts := Compile("arn:aws:iam::*:role/a:b", Plain).SplitN(':', 6)
	want := []string{"arn", "aws", "iam", "", "*", "role/a:b"}
	if len(parts) != len(want) {
		t.Fatalf("got %d parts", len(parts))
	}
	for i, p := range parts {
		if p.String() != want[i] {
			t.Errorf("part %d = %q, want %q", i, p.String(), want[i])
		}
	}
	if got := Compile("a:b", Plain).SplitN(':', 6); len(got) != 2 {
		t.Errorf("short pattern: %d parts", len(got))
	}
	if got := Compile("*?", Plain).SplitN('*', 3); len(got) != 1 {
		t.Error("wildcards must not split")
	}
}

// unknownValue builds a value pattern where "#" marks unknown content.
func unknownValue(s string) Pattern {
	v := Literal("", Plain)
	for i, part := range strings.Split(s, "#") {
		if i > 0 {
			v = v.Append(Compile("*", Plain))
		}
		v = v.Append(Literal(part, Plain))
	}
	return v
}

func TestIntersects(t *testing.T) {
	cases := []struct {
		pattern string
		mode    Mode
		value   string // '#' = unknown run
		want    bool
	}{
		{"arn:aws:s3:::prod-pii/*", Resource, "arn:aws:s3:::#-pii/report.csv", true},     // # = "prod"
		{"arn:aws:s3:::other-bucket/*", Resource, "arn:aws:s3:::#-pii/report.csv", true}, // # = "other-bucket/x": unknown content is unconstrained
		{"arn:aws:s3:::other-bucket", Resource, "arn:aws:s3:::#-pii", false},             // must end in "-pii"
		{"arn:aws:kms:*", Resource, "arn:aws:s3:::#-pii/x", false},
		{"arn:aws:kms:us-east-1:111122223333:key/*", Resource, "arn:aws:kms:us-east-1:#:key/k1", true},
		{"arn:aws:kms:us-east-1:111122223333:key/k2", Resource, "arn:aws:kms:us-east-1:#:key/k1", false},
		{"*", Resource, "#", true},
		{"a?c", Plain, "a#c", true},
		{"a?c", Resource, "a:c", false},   // '?' does not match ':' in Resource mode
		{"a*c", Resource, "a:b#c", false}, // a non-spanning '*' cannot absorb a known ':'
		{"a*c", Resource, "a#c", true},    // ... but unknown content can avoid ':'
		{"a*:c", Resource, "a:b:c", true}, // a '*' before ':' spans
		{"abc", Plain, "abc", true},
		{"abc", Plain, "abd", false},
		{"ab", Plain, "a", false},
	}
	for _, c := range cases {
		if got := Compile(c.pattern, c.mode).Intersects(unknownValue(c.value)); got != c.want {
			t.Errorf("%q ∩ %q = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
	// A value '?' is one unknown character.
	q := Literal("a", Plain).Append(Compile("?", Plain)).Append(Literal("c", Plain))
	if !Compile("abc", Plain).Intersects(q) || !Compile("a?c", Plain).Intersects(q) || Compile("ac", Plain).Intersects(q) {
		t.Error("value '?' semantics")
	}
}

func TestMatchIsPolynomialOnHostileInput(t *testing.T) {
	// Classic exponential case for backtracking matchers.
	pattern := strings.Repeat("a*", 200) + "b"
	value := strings.Repeat("a", 2000)
	if Compile(pattern, Plain).Match(value) {
		t.Fatal("must not match")
	}
}

func TestMatchPieces(t *testing.T) {
	cases := []struct {
		pattern          string
		pieces           []string
		possible, always bool
	}{
		{"arn:aws:s3:::pii/*", []string{"arn:aws:s3:::pii/", ""}, true, true},
		{"arn:aws:s3:::receipts", []string{"arn:aws:s3:::pii/", ""}, false, false},
		{"arn:aws:s3:::pii/a.csv", []string{"arn:aws:s3:::pii/", ""}, true, false},
		{"exact", []string{"exact"}, true, true},
	}
	for _, c := range cases {
		possible, always := Compile(c.pattern, Plain).MatchPieces(c.pieces)
		if possible != c.possible || always != c.always {
			t.Errorf("%s %q: %v %v", c.pattern, c.pieces, possible, always)
		}
	}
}
