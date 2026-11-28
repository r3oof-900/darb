package model

import (
	"slices"
	"testing"
)

func TestCredentials(t *testing.T) {
	var none *Credentials
	unknown := &Credentials{Known: Unknown}
	if none.ActiveKey() != Unknown || unknown.ActiveKey() != Unknown || none.Evidence() != nil || unknown.Evidence() != nil {
		t.Error("credentials not in the input are unknown and say nothing")
	}
	c := &Credentials{Principal: "u", Known: True, Generated: "2026-11-27T12:00:00Z", Keys: []AccessKey{
		{ID: "AKIAEXAMPLE0000001", Active: true, Created: "2026-01-01", LastUsed: "2026-11-01"},
		{Active: false, Created: "2026-02-01"},
	}}
	if c.ActiveKey() != True {
		t.Error("an active key")
	}
	want := []string{"credential report generated 2026-11-27T12:00:00Z", "active access key ****0001, created 2026-01-01, last used 2026-11-01"}
	if got := c.Evidence(); !slices.Equal(got, want) {
		t.Errorf("evidence: %q", got)
	}
	inactive := &Credentials{Known: True, Keys: []AccessKey{{Active: false}}}
	if inactive.ActiveKey() != False || len(inactive.Evidence()) != 0 {
		t.Error("an inactive key is no entry and no evidence")
	}
	if (AccessKey{Created: "d"}).Label() != "created d" || MaskedID("abc") != "abc" {
		t.Error("a key without ID or last use; a short ID")
	}
	inv := &Inventory{Credentials: []*Credentials{{Principal: "a"}, c}}
	if inv.CredentialsOf("u") != c || inv.CredentialsOf("missing") != nil {
		t.Error("CredentialsOf")
	}
}

func TestSyntheticPrincipalID(t *testing.T) {
	src := &SourceLocation{}
	a := NewSyntheticPrincipal(KindPolicyVersion, "arn:aws:iam::1:user/u", "p#v2", "1", src)
	b := NewSyntheticPrincipal(KindPolicyVersion, "arn:aws:iam::1:user/u", "p#v3", "1", src)
	if a.ID() == b.ID() || a.Identity() != b.Identity() || a.ID() == NewPrincipal(KindPolicyVersion, "arn:aws:iam::1:user/u", "1", src).ID() {
		t.Error("one ID per key, the identity kept")
	}
}
