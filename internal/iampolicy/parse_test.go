package iampolicy

import (
	"errors"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/model"
)

func parse(t *testing.T, kind model.PolicyKind, js string) (*model.PolicyDocument, error) {
	t.Helper()
	return Parse([]byte(js), &Options{ID: "test", Kind: kind})
}

func TestParseFullDocument(t *testing.T) {
	d, err := parse(t, model.PolicyResource, `{
	  "Version": "2012-10-17", "Id": "key-policy",
	  "Statement": [{
	    "Sid": "S1", "Effect": "Allow",
	    "Principal": {"AWS": ["arn:aws:iam::111122223333:root", "arn:aws:iam::111122223333:role/r"], "Service": "s3.amazonaws.com"},
	    "Action": ["kms:Decrypt", "kms:GenerateDataKey*"], "Resource": "*",
	    "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com", "kms:CallerAccount": ["111122223333"]},
	                  "NumericLessThan": {"aws:MultiFactorAuthAge": 3600}, "Bool": {"aws:SecureTransport": true}}
	  }, {
	    "Effect": "Deny", "NotPrincipal": {"CanonicalUser": "abc"}, "NotAction": "kms:Describe*", "NotResource": ["arn:x"]
	  }]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version() != model.Version2012 || len(d.Statements()) != 2 {
		t.Fatalf("version %q, %d statements", d.Version(), len(d.Statements()))
	}
	s := d.Statements()[0]
	spec, neg := s.Principal()
	if neg || len(spec.Refs()) != 3 || spec.Refs()[2].Type != model.PrincipalService {
		t.Errorf("principal refs %+v", spec.Refs())
	}
	conds := s.Conditions()
	want := []string{
		"StringEquals kms:ViaService [s3.us-east-1.amazonaws.com]", "StringEquals kms:CallerAccount [111122223333]",
		"NumericLessThan aws:MultiFactorAuthAge [3600]", "Bool aws:SecureTransport [true]",
	}
	for i, c := range conds {
		if got := c.Operator() + " " + c.Key() + " [" + strings.Join(c.Values(), ",") + "]"; got != want[i] {
			t.Errorf("condition %d = %q, want %q (document order must be kept)", i, got, want[i])
		}
	}
	s2 := d.Statements()[1]
	_, negP := s2.Principal()
	acts, negA := s2.Actions()
	_, negR := s2.Resources()
	if !negP || !negA || !negR || acts[0] != "kms:Describe*" || s2.Effect() != model.EffectDeny {
		t.Error("negated elements of statement 2")
	}
}

func TestParseForms(t *testing.T) {
	// A single statement object instead of an array; a missing Version.
	d, err := parse(t, model.PolicyIdentity, `{"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}`)
	if err != nil || len(d.Statements()) != 1 || d.VariablesEnabled() {
		t.Fatalf("single statement form: %v", err)
	}
	// "Principal": "*" and an empty condition-value list.
	d, err = parse(t, model.PolicyResource, `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
		"Condition": {"StringEquals": {"aws:SourceVpce": []}}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := d.Statements()[0].Principal()
	if !spec.Wildcard() || len(d.Statements()[0].Conditions()[0].Values()) != 0 {
		t.Error("wildcard principal / empty value list")
	}
	if d, err = parse(t, model.PolicyIdentity, `{"Statement": []}`); err != nil || len(d.Statements()) != 0 {
		t.Errorf("empty statement list: %v", err)
	}
	d, err = parse(t, model.PolicyResource, `{"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
		"Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/oidc.example"}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if spec, _ := d.Statements()[0].Principal(); spec.Refs()[0].Type != model.PrincipalFederated {
		t.Error("Federated principal")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"not json":              `{`,
		"not an object":         `[]`,
		"trailing data":         `{"Statement": []} {}`,
		"duplicate key":         `{"Statement": [], "Statement": []}`,
		"duplicate in stmt":     `{"Statement": [{"Effect": "Allow", "Effect": "Deny", "Action": "a"}]}`,
		"unknown top-level":     `{"Statement": [], "Foo": 1}`,
		"missing statement":     `{"Version": "2012-10-17"}`,
		"version not string":    `{"Version": 1, "Statement": []}`,
		"id not string":         `{"Id": [], "Statement": []}`,
		"statement not object":  `{"Statement": ["x"]}`,
		"unknown element":       `{"Statement": [{"Effect": "Allow", "Action": "a", "Bogus": 1}]}`,
		"lowercase effect":      `{"Statement": [{"Effect": "allow", "Action": "a"}]}`,
		"effect not string":     `{"Statement": [{"Effect": true, "Action": "a"}]}`,
		"sid not string":        `{"Statement": [{"Sid": 1, "Effect": "Allow", "Action": "a"}]}`,
		"empty action list":     `{"Statement": [{"Effect": "Allow", "Action": []}]}`,
		"action not strings":    `{"Statement": [{"Effect": "Allow", "Action": [1]}]}`,
		"action object":         `{"Statement": [{"Effect": "Allow", "Action": {}}]}`,
		"no action":             `{"Statement": [{"Effect": "Allow", "Resource": "*"}]}`,
		"notaction bad":         `{"Statement": [{"Effect": "Allow", "NotAction": 1}]}`,
		"resource bad":          `{"Statement": [{"Effect": "Allow", "Action": "a", "Resource": 1}]}`,
		"notresource bad":       `{"Statement": [{"Effect": "Allow", "Action": "a", "NotResource": 1}]}`,
		"principal string":      `{"Statement": [{"Effect": "Allow", "Action": "a", "Principal": "arn:x"}]}`,
		"principal empty":       `{"Statement": [{"Effect": "Allow", "Action": "a", "Principal": {}}]}`,
		"principal number":      `{"Statement": [{"Effect": "Allow", "Action": "a", "Principal": 1}]}`,
		"principal type":        `{"Statement": [{"Effect": "Allow", "Action": "a", "Principal": {"Bogus": "x"}}]}`,
		"principal value":       `{"Statement": [{"Effect": "Allow", "Action": "a", "Principal": {"AWS": 1}}]}`,
		"notprincipal bad":      `{"Statement": [{"Effect": "Deny", "Action": "a", "NotPrincipal": "x"}]}`,
		"condition not object":  `{"Statement": [{"Effect": "Allow", "Action": "a", "Condition": []}]}`,
		"condition op bad":      `{"Statement": [{"Effect": "Allow", "Action": "a", "Condition": {"StringEquals": "x"}}]}`,
		"condition value null":  `{"Statement": [{"Effect": "Allow", "Action": "a", "Condition": {"Null": {"k": null}}}]}`,
		"condition value obj":   `{"Statement": [{"Effect": "Allow", "Action": "a", "Condition": {"Null": {"k": [{}]}}}]}`,
		"principal in identity": `{"Statement": [{"Effect": "Allow", "Action": "a", "Principal": "*"}]}`,
		"too deep":              `{"Statement": ` + strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1) + `}`,
		"bad element in array":  `{"Statement": [}`,
		"bad key":               `{"Statement": [], 1: 2}`,
		"truncated value":       `{"Statement": `,
	}
	for name, js := range cases {
		if _, err := parse(t, model.PolicyIdentity, js); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseSizeLimit(t *testing.T) {
	big := `{"Statement": [], "Id": "` + strings.Repeat("x", MaxBytes) + `"}`
	if _, err := parse(t, model.PolicyIdentity, big); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed for oversized input, got %v", err)
	}
}

// Reserved placeholder text in input is rejected (docs/DESIGN.md section
// 4.6); a caller that wrote placeholders itself may keep exactly those.
func TestReservedText(t *testing.T) {
	ph := model.UnresolvedPlaceholder("var.env")
	// JSON escapes are built here, so no tool that writes this file can turn
	// them into the characters they stand for.
	esc := func(hex string) string { return string(rune(0x5c)) + "u" + hex }
	dollar, brace := esc("0024"), esc("007b")
	doc := func(action, resource string) string {
		return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + action + `","Resource":"` + resource + `"}]}`
	}
	cases := []struct {
		name, text   string
		placeholders bool
		ok           bool
	}{
		{"no placeholder", doc("s3:GetObject", "*"), false, true},
		{"input placeholder", doc(ph, "*"), false, false},
		{"caller placeholder", doc(ph, "*"), true, true},
		{"JSON-escaped placeholder", doc(dollar+"{darb:unresolved:var.env}", "*"), true, false},
		{"escaped next to a caller one", doc(ph, dollar+"{darb:unresolved:var.env}"), true, false},
		{"escaped brace", doc("$"+brace+"darb:unresolved:x}", "*"), true, false},
		{"in a condition key", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",` +
			`"Condition":{"StringEquals":{"` + dollar + `{darb:unresolved:k}":"v"}}}]}`, true, false},
		{"in a principal list", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*",` +
			`"Principal":{"AWS":["arn:aws:iam::1:root","` + dollar + `{darb:unresolved:p}"]}}]}`, true, false},
	}
	if !strings.Contains(cases[3].text, string(rune(0x5c))+"u0024") {
		t.Fatal("the escape must reach the parser as an escape")
	}
	for _, c := range cases {
		kind := model.PolicyIdentity
		if strings.Contains(c.text, "Principal") {
			kind = model.PolicyResource
		}
		_, err := Parse([]byte(c.text), &Options{ID: "p", Kind: kind, Placeholders: c.placeholders})
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrReservedText)) {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
