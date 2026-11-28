package eval

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/eval/condition"
	"github.com/r3oof-900/darb/internal/eval/match"
	"github.com/r3oof-900/darb/internal/model"
)

func choiceReq(choices ...condition.Choice) *Request {
	return &Request{
		Principal: match.RequestPrincipal{Kind: match.KindAssumedRole, ARN: "arn:aws:sts::111122223333:assumed-role/app/s", Account: "111122223333", SourceARN: "arn:aws:iam::111122223333:role/app"},
		Action:    "s3:GetObject", Resource: "arn:aws:s3:::data/k", ResourceAccount: "111122223333",
		Context: condition.NewContext(&condition.Input{Default: condition.StateUnknown, Choices: choices}),
	}
}

func stmtDoc(t *testing.T, stmts string) *model.PolicyDocument {
	t.Helper()
	return doc(t, "identity", model.PolicyIdentity, json.RawMessage(stmts))
}

var (
	tlsChoice = condition.Choice{
		Keys: []string{"aws:SecureTransport"}, By: condition.ByAttacker,
		Options: []condition.Option{{"aws:SecureTransport": {"true"}}, {"aws:SecureTransport": {"false"}}},
	}
	mfaChoice = condition.Choice{
		Keys: []string{"aws:MultiFactorAuthPresent"}, By: condition.Undocumented, Source: "test",
		Options: []condition.Option{{}, {"aws:MultiFactorAuthPresent": {"false"}}},
	}
)

func applies(gs []GrantDetail) map[string]model.Tri {
	out := map[string]model.Tri{}
	for _, g := range gs {
		out[g.Statement.Sid()] = g.Applies
	}
	return out
}

// A statement grants when it applies under one of the attacker's options:
// every one of them must change for the edge to break.
func TestGrantingUnderAttackerChoice(t *testing.T) {
	d := stmtDoc(t, `[{"Sid":"OverTLS","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},
		{"Sid":"OverHTTP","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}},
		{"Sid":"Org","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}},
		{"Sid":"Other","Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]`)
	got := applies(GrantingDetail(choiceReq(tlsChoice), []*model.PolicyDocument{d}))
	want := map[string]model.Tri{"OverTLS": model.True, "OverHTTP": model.True, "Org": model.Unknown}
	if len(got) != len(want) || got["OverTLS"] != want["OverTLS"] || got["OverHTTP"] != want["OverHTTP"] || got["Org"] != want["Org"] {
		t.Fatalf("granting: %v", got)
	}
}

// A statement that grants under one undocumented option and not another is
// UNKNOWN and names the key; one that grants under every option stays
// decided; one that never grants is not listed.
func TestGrantingUnderUndocumentedChoice(t *testing.T) {
	d := stmtDoc(t, `[{"Sid":"IfExists","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"true"}}},
		{"Sid":"Never","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}},
		{"Sid":"Always","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]`)
	gs := GrantingDetail(choiceReq(mfaChoice), []*model.PolicyDocument{d})
	got := applies(gs)
	if len(got) != 2 || got["IfExists"] != model.Unknown || got["Always"] != model.True {
		t.Fatalf("granting: %v", got)
	}
	if !slices.ContainsFunc(gs[0].Unresolved, func(u Unresolved) bool { return u.Key == "aws:MultiFactorAuthPresent" }) {
		t.Errorf("the undocumented key is named: %+v", gs[0].Unresolved)
	}
	always := stmtDoc(t, `[{"Sid":"Plain","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":["true","false"]}}}]`)
	if got := applies(GrantingDetail(choiceReq(mfaChoice), []*model.PolicyDocument{always})); got["Plain"] != model.True {
		t.Errorf("granted under every option: %v", got)
	}
}

// Options that differ but never grant decide "no access" (DENY or
// IMPLICIT_DENY): not UNKNOWN.
func TestUndocumentedNoAccessIsDecided(t *testing.T) {
	d := stmtDoc(t, `[{"Sid":"Need","Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}},
		{"Sid":"Deny","Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}]`)
	if v := Evaluate(choiceReq(mfaChoice), &PolicySet{Identity: []*model.PolicyDocument{d}}).Verdict; v.Grants() != 0 || v == Unknown {
		t.Fatalf("no option grants: %s", v)
	}
}

// A free choice: its options, each policy value (no policy variable), and
// the fresh value; each once.
func TestFreeOptions(t *testing.T) {
	ch := condition.Choice{
		Keys: []string{"aws:UserAgent"}, Free: true, Fresh: "fresh",
		Options: []condition.Option{{}, {"aws:UserAgent": {"given"}}},
	}
	got := freeOptions(&ch, []string{"given", "${aws:username}", "named", "named", ""})
	var vals []string
	for _, o := range got {
		vals = append(vals, strings.Join(o["aws:UserAgent"], ","))
	}
	if !slices.Equal(vals, []string{"", "given", "named", "fresh"}) {
		t.Fatalf("options: %q", vals)
	}
	noFresh := condition.Choice{Keys: []string{"k"}, Free: true}
	if got := freeOptions(&noFresh, nil); len(got) != 0 {
		t.Errorf("no options without values: %v", got)
	}
}

// Too many combinations, or a choice with no option, leave the keys
// unknown: never a less certain decision than without choices.
func TestInfeasibleChoicesStayUnknown(t *testing.T) {
	var many []condition.Choice
	allow := `[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{`
	for i := range 10 {
		k := "test:k" + string(rune('a'+i))
		many = append(many, condition.Choice{
			Keys: []string{k}, By: condition.ByAttacker,
			Options: []condition.Option{{k: {"1"}}, {k: {"2"}}},
		})
		if i > 0 {
			allow += ","
		}
		allow += `"` + k + `":"1"`
	}
	d := stmtDoc(t, allow+`}}}]`)
	ps := &PolicySet{Identity: []*model.PolicyDocument{d}}
	if v := Evaluate(choiceReq(many...), ps).Verdict; v != Unknown {
		t.Fatalf("1024 combinations: %s", v)
	}
	if gs := GrantingDetail(choiceReq(many...), ps.Identity); len(gs) != 1 || gs[0].Applies != model.Unknown {
		t.Fatalf("granting over the cap: %+v", gs)
	}
	empty := condition.Choice{Keys: []string{"test:ka"}, By: condition.ByAttacker}
	if v := Evaluate(choiceReq(empty), ps).Verdict; v != Unknown {
		t.Fatalf("a choice with no option: %s", v)
	}
}
