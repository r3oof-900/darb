package htmlreport

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// An explanation is shown as text under its label: AI-generated with the
// model, or template text with the note.
func TestExplanationsAreLabelledText(t *testing.T) {
	out := render(t, hostileReport())
	doc, err := html.Parse(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	var asides []string
	walk(doc, func(n *html.Node) {
		if n.Data == "aside" {
			var b strings.Builder
			var all func(*html.Node)
			all = func(m *html.Node) {
				if m.Type == html.TextNode {
					b.WriteString(m.Data)
				}
				for c := m.FirstChild; c != nil; c = c.NextSibling {
					all(c)
				}
			}
			all(n)
			asides = append(asides, b.String())
		}
	})
	if len(asides) != 2 {
		t.Fatalf("%d explanations shown, want the summary and one finding", len(asides))
	}
	if !strings.Contains(asides[0], "Explanation (template text: "+scriptName+")") || !strings.Contains(asides[0], endOfData) {
		t.Errorf("summary: %q", asides[0])
	}
	if !strings.Contains(asides[1], "AI-generated explanation ("+templateText+"; it does not change the verdict") ||
		!strings.Contains(asides[1], scriptName) || !strings.Contains(asides[1], "The attack: "+breakout) {
		t.Errorf("finding: %q", asides[1])
	}
}
