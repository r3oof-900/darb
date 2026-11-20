package arn

import "testing"

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"arn:aws:s3:::b/k", "arn:aws:iam::111122223333:role/r", "arn::::::", "arn:aws:s3", "", "arn:a:b:c:d:e:f:g",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := Parse(s)
		if err != nil {
			return
		}
		if a.String() != s {
			t.Fatalf("round trip: Parse(%q).String() = %q", s, a.String())
		}
		_ = a.IsAccountRoot()
	})
}

func FuzzMatch(f *testing.F) {
	f.Add("arn:aws:s3:::b/*", "arn:aws:s3:::b/k", true)
	f.Add("*:*?", "a:b", false)
	f.Add("", "", true)
	f.Fuzz(func(t *testing.T, pattern, value string, resource bool) {
		if len(pattern) > 512 || len(value) > 512 {
			return
		}
		m := Plain
		if resource {
			m = Resource
		}
		_ = Compile(pattern, m).Match(value)
		if !Literal(value, m).Match(value) {
			t.Fatalf("Literal(%q) does not match itself", value)
		}
		if !Compile("*", m).Match(value) {
			t.Fatalf("'*' does not match %q", value)
		}
		// A fully known value intersects a pattern exactly when it matches it.
		p := Compile(pattern, m)
		if p.Intersects(Literal(value, Plain)) != p.Match(value) {
			t.Fatalf("Intersects and Match disagree on %q / %q", pattern, value)
		}
	})
}
