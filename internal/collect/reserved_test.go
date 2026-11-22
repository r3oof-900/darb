package collect

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/r3oof-900/darb/internal/model"
)

func TestReservedTextMatchesModel(t *testing.T) {
	if ReservedText != model.UnresolvedPrefix {
		t.Fatalf("ReservedText %q != model.UnresolvedPrefix %q", ReservedText, model.UnresolvedPrefix)
	}
}

func TestContainsReserved(t *testing.T) {
	cases := map[string]bool{
		"arn:aws:s3:::b":                false,
		"${darb:unresolved:x}":          true,
		"%24%7Bdarb:unresolved:x%7D":    true,  // URL-encoded (IAM policy documents)
		"%24%7Bd%61rb%3Aunresolved%3Ax": true,  // any byte may be encoded
		"100%":                          false, // not valid percent-encoding
		"${darb:resolved:x}":            false,
		"$${darb:unresolved:x}":         true, // the text is still there
	}
	for s, want := range cases {
		if got := ContainsReserved(s); got != want {
			t.Errorf("ContainsReserved(%q) = %v, want %v", s, got, want)
		}
	}
}

// nest wraps a JSON document with reserved text in n levels of JSON strings,
// with the innermost occurrence escaped so that only decoding reveals it.
func nest(n int) string {
	doc := `{"a":"$` + string(rune(0x5c)) + `u007bdarb:unresolved:x}"}`
	for range n {
		b, _ := json.Marshal(map[string]string{"p": doc})
		doc = string(b)
	}
	return doc
}

func TestFindReservedJSON(t *testing.T) {
	esc := func(hex string) string { return string(rune(0x5c)) + "u" + hex }
	cases := []struct {
		data string
		line int
		ok   bool
	}{
		{`{"a": "b"}`, 0, false},
		{"{\n  \"a\": \"${darb:unresolved:x}\"\n}", 2, true},
		{"{\n\n  \"" + esc("0024") + "{darb:unresolved:k}\": 1}", 3, true}, // a key, JSON-escaped
		{"[1,\n\"%24%7Bdarb:unresolved:x%7D\"]", 2, true},
		{`{"a": `, 0, false}, // invalid JSON: the decoder reports it
		// A policy document inside a JSON string, escape decoded only there.
		{"{\n\"Policy\": \"{\\\"Action\\\":\\\"" + esc("0024") + "{darb:unresolved:x}\\\"}\"}", 2, true},
		// URL-encoded (IAM), with the escape inside.
		{`{"Document": "%7B%22Action%22%3A%22%5Cu0024%7Bdarb%3Aunresolved%3Ax%7D%22%7D"}`, 1, true},
		{`{"Document": "%7B%22Action%22%3A%22s3%3AGetObject%22%7D"}`, 0, false},
		{`{"Policy": "{\"a\": \"b\"}"}`, 0, false},
		// Nesting is bounded: three embedded levels are searched, not four.
		{nest(4), 0, false},
		{nest(3), 1, true},
	}
	for _, c := range cases {
		line, ok := FindReservedJSON([]byte(c.data))
		if line != c.line || ok != c.ok {
			t.Errorf("FindReservedJSON(%q) = %d, %v; want %d, %v", c.data, line, ok, c.line, c.ok)
		}
	}
	err := error(&ReservedTextError{Line: 7})
	if !errors.Is(err, ErrReservedText) || err.Error() != "line 7: "+ErrReservedText.Error() {
		t.Errorf("ReservedTextError: %v", err)
	}
}
