package awssnapshot

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestEscapeName(t *testing.T) {
	for name, want := range map[string]string{
		"pii-data": "pii-data", "db/password": "db%2Fpassword", "/app/DB": "%2Fapp%2F!d!b", "..": "%2E.",
		".hidden": "%2Ehidden", "a.b": "a.b", "Prod": "!prod", "x!y%z": "x%21y%25z",
	} {
		if got := escapeName(name); got != want {
			t.Errorf("escape(%q) = %q, want %q", name, got, want)
		}
		if back, err := unescapeName(want); err != nil || back != name {
			t.Errorf("unescape(%q) = %q, %v", want, back, err)
		}
	}
	for _, bad := range []string{"%2f", "A", "%2", "!1", "%41", "a/b", "."} {
		if _, err := unescapeName(bad); err == nil {
			t.Errorf("unescape(%q) accepted", bad)
		}
	}
}

func TestEscapeNameProperties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.String().Draw(t, "a")
		b := rapid.String().Draw(t, "b")
		ea, eb := escapeName(a), escapeName(b)
		if back, err := unescapeName(ea); err != nil || back != a {
			t.Fatalf("round trip %q: %q, %v", a, back, err)
		}
		if strings.ContainsAny(ea, `/\:*?"<>|`) || ea == "." || ea == ".." || strings.HasPrefix(ea, ".") {
			t.Fatalf("%q is not a safe path component", ea)
		}
		if a != b && strings.EqualFold(ea, eb) {
			t.Fatalf("%q and %q collide on a case-insensitive file system", a, b)
		}
	})
}
