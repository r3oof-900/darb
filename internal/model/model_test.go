package model

import (
	"errors"
	"strings"
	"testing"
)

func TestTriTruthTables(t *testing.T) {
	all := []Tri{False, True, Unknown}
	and := map[[2]Tri]Tri{
		{False, False}: False, {False, True}: False, {False, Unknown}: False,
		{True, True}: True, {True, Unknown}: Unknown, {Unknown, Unknown}: Unknown,
	}
	or := map[[2]Tri]Tri{
		{False, False}: False, {False, True}: True, {False, Unknown}: Unknown,
		{True, True}: True, {True, Unknown}: True, {Unknown, Unknown}: Unknown,
	}
	for _, a := range all {
		for _, b := range all {
			key := [2]Tri{a, b}
			if _, ok := and[key]; !ok {
				key = [2]Tri{b, a}
			}
			if got := a.And(b); got != and[key] {
				t.Errorf("%v AND %v = %v, want %v", a, b, got, and[key])
			}
			if got := a.Or(b); got != or[key] {
				t.Errorf("%v OR %v = %v, want %v", a, b, got, or[key])
			}
		}
	}
	if True.Not() != False || False.Not() != True || Unknown.Not() != Unknown || Tri(9).Not() != Unknown {
		t.Error("Not")
	}
	if TriOf(true) != True || TriOf(false) != False {
		t.Error("TriOf")
	}
	for tri, s := range map[Tri]string{False: "false", True: "true", Unknown: "unknown", Tri(9): "unknown"} {
		if tri.String() != s {
			t.Errorf("String(%d) = %q", tri, tri.String())
		}
	}
}

func TestIDsAreStableAndDoNotCollide(t *testing.T) {
	a := NewID(KindIAMRole, "arn:aws:iam::111111111111:role/app")
	b := NewID(KindIAMRole, "arn:aws:iam::222222222222:role/app")
	if a == b {
		t.Fatal("same role name in two accounts must not collide (scenario 14)")
	}
	if a != NewID(KindIAMRole, "arn:aws:iam::111111111111:role/app") {
		t.Fatal("IDs must be deterministic")
	}
	if NewID(KindIAMRole, "x") == NewID(KindIAMUser, "x") {
		t.Fatal("kind must be part of the ID")
	}
	// The NUL separator prevents ambiguity between kind and identity.
	if NewID("k8s:a", "b") == NewID("k8s:", "ab") {
		t.Fatal("kind/identity boundary must be unambiguous")
	}
	if len(a) != 64 {
		t.Fatalf("ID length %d, want 64 hex chars", len(a))
	}
	w1 := NewWorkload(&WorkloadInput{Cluster: "c1", Namespace: "n", Kind: "Deployment", Name: "api"})
	w2 := NewWorkload(&WorkloadInput{Cluster: "c2", Namespace: "n", Kind: "Deployment", Name: "api"})
	if w1.ID() == w2.ID() {
		t.Fatal("same workload in two clusters must not collide")
	}
	if w1.Identity() != "k8s:c1/n/Deployment/api" {
		t.Fatalf("Identity() = %q", w1.Identity())
	}
}

func TestSourceLocationString(t *testing.T) {
	cases := map[string]SourceLocation{
		"main.tf:3-9 (aws_iam_role.app)":        FileLocation("main.tf", 3, 9, "aws_iam_role.app"),
		"k.yaml:4":                              FileLocation("k.yaml", 4, 4, ""),
		"k.yaml":                                FileLocation("k.yaml", 0, 0, ""),
		"arn:aws:iam::1:role/r via iam:GetRole": APILocation("arn:aws:iam::1:role/r", "iam:GetRole"),
		"<unknown location>":                    {},
	}
	for want, loc := range cases {
		if got := loc.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
	loc := FileLocation("f", 1, 2, "a")
	if s, e := loc.Lines(); loc.File() != "f" || s != 1 || e != 2 || loc.Address() != "a" || loc.IsZero() {
		t.Error("FileLocation getters")
	}
	api := APILocation("arn", "api")
	if api.ARN() != "arn" || api.API() != "api" {
		t.Error("APILocation getters")
	}
}

func TestStatementValidation(t *testing.T) {
	p := NewPrincipalSpec(true, nil)
	bad := []StatementInput{
		{Action: []string{"s3:GetObject"}},
		{Effect: EffectAllow},
		{Effect: EffectAllow, Action: []string{"a"}, NotAction: []string{"b"}},
		{Effect: EffectAllow, Action: []string{"a"}, Resource: []string{"*"}, NotResource: []string{"x"}},
		{Effect: EffectAllow, Action: []string{"a"}, Principal: p, NotPrincipal: p},
	}
	for i := range bad {
		if _, err := NewStatement(i, &bad[i]); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("case %d: want ErrInvalidPolicy, got %v", i, err)
		}
	}
}

func TestStatementCopiesInput(t *testing.T) {
	in := StatementInput{
		Sid: "S", Effect: EffectDeny, NotAction: []string{"iam:*"}, NotResource: []string{"arn:x"},
		NotPrincipal: NewPrincipalSpec(false, []PrincipalRef{{PrincipalService, "b"}, {PrincipalAWS, "z"}, {PrincipalAWS, "a"}}),
		Conditions:   []Condition{NewCondition("Bool", "aws:SecureTransport", []string{"false"})},
	}
	s, err := NewStatement(2, &in)
	if err != nil {
		t.Fatal(err)
	}
	in.NotAction[0] = "mutated"
	in.Conditions[0].values[0] = "mutated"
	acts, negA := s.Actions()
	res, negR := s.Resources()
	spec, negP := s.Principal()
	conds := s.Conditions()
	switch {
	case acts[0] != "iam:*" || !negA, res[0] != "arn:x" || !negR, !negP:
		t.Fatal("negated elements not preserved")
	case conds[0].Values()[0] != "false" || conds[0].Operator() != "Bool" || conds[0].Key() != "aws:SecureTransport":
		t.Fatal("conditions not copied")
	case spec.Refs()[0].Type != PrincipalAWS || spec.Wildcard():
		t.Fatal("principal refs must be sorted by type")
	case s.Sid() != "S" || s.Index() != 2 || s.Effect() != EffectDeny || s.Label() != "S":
		t.Fatal("getters")
	}
	unnamed, _ := NewStatement(7, &StatementInput{Effect: EffectAllow, Action: []string{"a"}})
	if unnamed.Label() != "#7" {
		t.Fatalf("Label() = %q", unnamed.Label())
	}
}

func TestPolicyDocumentPrincipalRules(t *testing.T) {
	withP := &StatementInput{Effect: EffectAllow, Action: []string{"a"}, Principal: NewPrincipalSpec(true, nil)}
	noP := &StatementInput{Effect: EffectAllow, Action: []string{"a"}, Resource: []string{"*"}}
	cases := []struct {
		kind PolicyKind
		st   *StatementInput
		ok   bool
	}{
		{PolicyResource, withP, true},
		{PolicyResource, noP, false},
		{PolicyIdentity, noP, true},
		{PolicyIdentity, withP, false},
		{PolicyBoundary, withP, false},
		{PolicySCP, noP, true},
		{PolicySCP, withP, false},
		{PolicyRCP, withP, true},
		{PolicyRCP, noP, false},
		{PolicyKind(0), noP, false},
		{PolicyKind(99), noP, false},
	}
	for _, c := range cases {
		_, err := NewPolicyDocument(&PolicyInput{ID: "p", Kind: c.kind, Statements: []*StatementInput{c.st}})
		if (err == nil) != c.ok {
			t.Errorf("kind %v: err = %v, want ok=%v", c.kind, err, c.ok)
		}
	}
	if _, err := NewPolicyDocument(&PolicyInput{ID: "p", Kind: PolicyIdentity, Statements: []*StatementInput{{Effect: EffectAllow}}}); err == nil {
		t.Error("invalid statement must fail the document")
	}
	d, err := NewPolicyDocument(&PolicyInput{
		ID: "p", Kind: PolicyIdentity, Version: Version2012,
		Source: FileLocation("f", 1, 1, ""), Statements: []*StatementInput{noP},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.ID() != "p" || d.Kind() != PolicyIdentity || d.Version() != Version2012 || !d.VariablesEnabled() ||
		len(d.Statements()) != 1 || d.Source().File() != "f" {
		t.Error("document getters")
	}
	for k, s := range map[PolicyKind]string{
		PolicyIdentity: "identity", PolicyResource: "resource", PolicyBoundary: "boundary",
		PolicySession: "session", PolicySCP: "scp", PolicyRCP: "rcp", PolicyKind(0): "invalid",
	} {
		if k.String() != s {
			t.Errorf("%d.String() = %q", k, k.String())
		}
	}
	if EffectAllow.String() != "Allow" || EffectDeny.String() != "Deny" {
		t.Error("Effect.String")
	}
}

func TestNodes(t *testing.T) {
	src := FileLocation("main.tf", 1, 2, "x")
	p := NewPrincipal(KindIAMRole, "arn:aws:iam::1:role/r", "1", &src)
	if p.ID() != NewID(KindIAMRole, "arn:aws:iam::1:role/r") || p.Kind() != KindIAMRole ||
		p.Identity() != "arn:aws:iam::1:role/r" || p.Account() != "1" || p.Source().File() != "main.tf" {
		t.Error("principal getters")
	}
	r := NewResource(&ResourceInput{
		Kind: KindS3Bucket, ARN: "arn:aws:s3:::b", Account: "1", Region: "r",
		Tags: map[string]string{"z": "1", "DataClass": "pii"}, Classification: "pii", ClassifiedBy: "tag:DataClass", Source: src,
	})
	class, by := r.Classification()
	if r.Tags()[0].Key != "DataClass" || class != "pii" || by != "tag:DataClass" || r.Kind() != KindS3Bucket ||
		r.ARN() != "arn:aws:s3:::b" || r.Account() != "1" || r.Region() != "r" || r.ID() == "" || r.Source().IsZero() {
		t.Error("resource getters")
	}
	w := NewWorkload(&WorkloadInput{
		Cluster: "c", Namespace: "n", Kind: "Pod", Name: "p", ServiceAccount: "sa",
		HostNetwork: true, AutomountToken: Unknown, Source: src,
	})
	if w.Namespace() != "n" || w.ServiceAccount() != "sa" || !w.HostNetwork() || w.AutomountToken() != Unknown || w.Source().IsZero() {
		t.Error("workload getters")
	}
	doc, _ := NewPolicyDocument(&PolicyInput{ID: "trust", Kind: PolicyResource})
	tr := NewTrustRelationship(p.ID(), doc)
	if tr.Role() != p.ID() || tr.Policy() != doc {
		t.Error("trust getters")
	}
	e := NewNetworkExposure(w.ID(), "Ingress", True, &src)
	if e.Workload() != w.ID() || e.Via() != "Ingress" || e.Public() != True || e.Source().IsZero() {
		t.Error("exposure getters")
	}
}

func TestUnresolvedPlaceholder(t *testing.T) {
	p := UnresolvedPlaceholder("var.x")
	if p != "${clapa:unresolved:var.x}" || !ContainsUnresolved("arn:"+p+"/*") || ContainsUnresolved("${aws:username}") {
		t.Fatal("placeholder")
	}
	if !AnyUnresolved([]string{"a", p}) || AnyUnresolved([]string{"a"}) {
		t.Fatal("AnyUnresolved")
	}
}

func TestUnresolvedIDs(t *testing.T) {
	u := UnresolvedPlaceholder
	cases := map[string][]string{
		"plain":                            nil,
		"a" + u("x") + "b" + u("y.z"):      {"x", "y.z"},
		u("x") + UnresolvedPrefix + "open": {"x", "open"},
	}
	for in, want := range cases {
		if got := UnresolvedIDs(in); strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
			t.Errorf("UnresolvedIDs(%q) = %q, want %q", in, got, want)
		}
	}
	if CountUnresolved(u("a")+u("b")) != 2 || CountUnresolved("x") != 0 {
		t.Error("CountUnresolved")
	}
}

func TestSplitUnresolved(t *testing.T) {
	u := UnresolvedPlaceholder("x")
	cases := map[string][]string{
		"plain":                         {"plain"},
		"a" + u + "b":                   {"a", "b"},
		u + u:                           {"", "", ""},
		"a" + "${clapa:unresolved:open": {"a", ""},
	}
	for in, want := range cases {
		got := SplitUnresolved(in)
		if strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
			t.Errorf("SplitUnresolved(%q) = %q, want %q", in, got, want)
		}
	}
}
