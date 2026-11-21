package app

import (
	"bytes"
	"html"
	"path/filepath"
	"strings"
	"testing"
)

// Every step of a finding's cheapest fix is drawn: in each scenario's HTML
// report, the edge the step changes (the decrypt or the read a derived read
// stands for, an escalation, a trust) is an edge of the path view, marked ✂
// when the fix changes it and ? when it only resolves unknowns on it.
func TestEveryFixStepIsDrawnWithItsMark(t *testing.T) {
	checked := 0
	for _, v := range propertyVariants(t) {
		in := scansFor(t, copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(v))))["normalized.golden.json"]
		l, err := Load(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(l, in.Config, DefaultFailOn)
		if err != nil {
			t.Fatal(err)
		}
		r := Report(a, in.Config, DefaultFailOn)
		var page bytes.Buffer
		if werr := Write(&page, "html", r); werr != nil {
			t.Fatal(werr)
		}
		out := page.String()
		for _, f := range r.Findings {
			// The mark an edge gets: ✂ when any of its steps changes something.
			marks := map[string]string{}
			for _, s := range f.Fix {
				left, to, ok := strings.Cut(s.Edge, " -> ")
				sp := strings.LastIndexByte(left, ' ')
				if !ok || sp < 0 {
					t.Fatalf("%s: fix step edge %q", v, s.Edge)
				}
				from := left[sp+1:]
				kind, _, _ := strings.Cut(left[:sp], "[")
				key := kind + "|" + from + "|" + to
				if s.Kind == "resolve" && marks[key] != "cut" {
					marks[key] = "resolve"
				} else {
					marks[key] = "cut"
				}
			}
			for key, mark := range marks {
				parts := strings.SplitN(key, "|", 3)
				drawn := `<g class="edge ` + mark + `" data-kind="` + parts[0]
				attrs := `data-from="` + html.EscapeString(parts[1]) + `" data-to="` + html.EscapeString(parts[2]) + `"`
				if !strings.Contains(out, drawn) || !drawnWith(out, drawn, attrs) {
					t.Errorf("%s %s: the fix step on %s is not drawn with its %s mark", v, f.Rule, key, mark)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no fix step was checked")
	}
}

// drawnWith: some edge group opening with prefix carries attrs.
func drawnWith(page, prefix, attrs string) bool {
	for rest := page; ; {
		i := strings.Index(rest, prefix)
		if i < 0 {
			return false
		}
		tag := rest[i:]
		tag = tag[:strings.IndexByte(tag, '>')]
		if strings.Contains(tag, attrs) {
			return true
		}
		rest = rest[i+len(prefix):]
	}
}
