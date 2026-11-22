package markdown

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/pkg/schema"
)

func render(t *testing.T, r *schema.Report, limit int) string {
	t.Helper()
	var b bytes.Buffer
	if err := (Reporter{Limit: limit}).Write(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A name from the input stays a code span: it cannot end the span, split a
// table cell, mention a user, link or add markup.
func TestNamesAreInert(t *testing.T) {
	hostile := "a`b`` | @admin [x](https://evil.example) <img src=x>\n# heading"
	r := &schema.Report{
		Summary:  schema.Summary{Findings: 2, BySeverity: map[string]int{"high": 2}},
		Coverage: schema.Coverage{Collected: 1},
		Findings: []schema.Finding{
			{Rule: "DARB-PATH-001", Title: "t", Severity: "high", Score: 600, Status: "confirmed", Entry: hostile, Jewel: "arn:aws:s3:::b", Fingerprint: "f1"},
			{Rule: "DARB-POST-008", Title: "t", Severity: "high", Score: 600, Status: "confirmed", Resource: hostile, Fingerprint: "f2"},
		},
	}
	out := render(t, r, 0)
	want := "``` a`b`` \\| @admin [x](https://evil.example) <img src=x> # heading ```"
	if strings.Count(out, want) != 2 {
		t.Fatalf("not one inert code span each:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "# ") {
			t.Errorf("a name became a heading: %q", line)
		}
	}
}

// Paths come first, most severe first; over the limit, a line counts the
// findings left out, and the output stays within the limit.
func TestOrderAndLimit(t *testing.T) {
	r := &schema.Report{Summary: schema.Summary{BySeverity: map[string]int{}}, Coverage: schema.Coverage{Collected: 1}}
	for i := range 300 {
		sev := []string{"low", "critical", "medium"}[i%3]
		r.Findings = append(r.Findings, schema.Finding{
			Rule: "DARB-PATH-001", Title: "A workload can read crown-jewel data", Severity: sev, Score: 100 + i, Status: "confirmed",
			Entry: fmt.Sprintf("k8s:prod/ns/Deployment/w%03d", i), Jewel: "arn:aws:s3:::pii", Fingerprint: fmt.Sprint(i),
		})
	}
	r.Summary.Findings = len(r.Findings)
	full := render(t, r, 1<<30)
	if strings.Contains(full, "more findings") || strings.Index(full, "**CRITICAL") > strings.Index(full, "**MEDIUM") ||
		strings.Index(full, "**MEDIUM") > strings.Index(full, "**LOW") {
		t.Fatal("not every finding, or not in severity order")
	}
	short := render(t, r, 8000)
	if len(short) > 8000 || !strings.Contains(short, "more findings in the full report") || !strings.Contains(short, "### Coverage") {
		t.Fatalf("%d bytes:\n%s", len(short), short[len(short)-400:])
	}
	shown := strings.Count(short, "**CRITICAL") + strings.Count(short, "**MEDIUM") + strings.Count(short, "**LOW")
	if !strings.Contains(short, fmt.Sprintf("**%d more findings", 300-shown)) {
		t.Errorf("%d shown, the count line is wrong", shown)
	}
	if len(render(t, r, 0)) > MaxBytes {
		t.Error("the default limit is not kept")
	}
}

// Nothing scanned is said, never shown as clean.
func TestNothingScanned(t *testing.T) {
	out := render(t, &schema.Report{Summary: schema.Summary{BySeverity: map[string]int{}}}, 0)
	if !strings.Contains(out, "Nothing was scanned: this is not a clean result.") {
		t.Fatal(out)
	}
}
