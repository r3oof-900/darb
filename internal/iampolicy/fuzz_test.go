package iampolicy

import (
	"testing"

	"github.com/r3oof-900/clapa/internal/model"
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
	f.Fuzz(func(_ *testing.T, data []byte, kind uint8) {
		_, _ = Parse(data, &Options{ID: "fuzz", Kind: model.PolicyKind(kind%7 + 1)})
	})
}
