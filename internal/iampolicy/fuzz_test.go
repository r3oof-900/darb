package iampolicy

import (
	"slices"
	"testing"

	"github.com/r3oof-900/darb/internal/model"
)

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
		`{"Statement":{"Effect":"Deny","NotPrincipal":{"AWS":["1","2"]},"NotAction":"a","Condition":{"Null":{"k":true}}}}`,
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":["a"],"Condition":{"NumericEquals":{"k":[1,2.5e3]}}}]}`,
		`[[[[[[`, `{"a":`, `null`, `"x"`,
	} {
		f.Add([]byte(s), uint8(1))
	}
	bs := string(rune(0x5c)) // a backslash, so the escapes stay escapes in this file
	for _, s := range []string{
		`{"Statement":[{"Effect":"Allow","Action":"${darb:unresolved:x}","Resource":"*"}]}`,
		`{"Statement":[{"Effect":"Allow","Action":"` + bs + `u0024{darb:unresolved:x}","Resource":"*"}]}`,
		`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Null":{"$` + bs + `u007bdarb:unresolved:k}":"true"}}}]}`,
	} {
		f.Add([]byte(s), uint8(0))
	}
	f.Fuzz(func(t *testing.T, data []byte, kind uint8) {
		k := model.PolicyKind(kind%7 + 1)
		// Input alone: a parsed document never carries a placeholder.
		if d, err := Parse(data, &Options{ID: "fuzz", Kind: k}); err == nil && countDoc(d) > 0 {
			t.Fatalf("input placeholder accepted: %q", data)
		}
		// A caller's own placeholders: never more than it wrote as plain text.
		if d, err := Parse(data, &Options{ID: "fuzz", Kind: k, Placeholders: true}); err == nil &&
			countDoc(d) > model.CountUnresolved(string(data)) {
			t.Fatalf("placeholder produced by decoding accepted: %q", data)
		}
	})
}

// countDoc counts the placeholders in every string a statement holds.
func countDoc(d *model.PolicyDocument) int {
	n := 0
	for _, s := range d.Statements() {
		acts, _ := s.Actions()
		res, _ := s.Resources()
		strs := slices.Concat(acts, res)
		if p, _ := s.Principal(); p != nil {
			for _, r := range p.Refs() {
				strs = append(strs, r.Value)
			}
		}
		for _, c := range s.Conditions() {
			strs = append(append(strs, c.Key(), c.Operator()), c.Values()...)
		}
		for _, x := range append(strs, s.Sid()) {
			n += model.CountUnresolved(x)
		}
	}
	return n
}
