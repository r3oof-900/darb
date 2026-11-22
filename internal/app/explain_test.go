package app

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// An explained report (template text: no provider) still matches the
// schema; path findings and the summary carry an explanation, the
// misconfigurations none; the verdicts are those of the unexplained report.
func TestExplainedReportMatchesTheSchema(t *testing.T) {
	sch, _ := reportSchema(t)
	dir := copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", "01_classic", "vulnerable"))
	in := scansFor(t, dir)["normalized.golden.json"]
	l, err := Load(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Analyze(l, in.Config, DefaultFailOn)
	if err != nil {
		t.Fatal(err)
	}
	r := Report(a, in.Config, DefaultFailOn)
	var before bytes.Buffer
	if werr := Write(&before, "json", r); werr != nil {
		t.Fatal(werr)
	}
	ExplainReport(t.Context(), r, nil, true)
	if r.ExecutiveSummary == nil || r.ExecutiveSummary.AIGenerated || !strings.Contains(r.ExecutiveSummary.Note, "no LLM provider") {
		t.Fatalf("summary: %+v", r.ExecutiveSummary)
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		if (f.Resource == "") != (f.Explanation != nil) {
			t.Errorf("%s: explanation %+v", f.Rule, f.Explanation)
		}
	}
	var out bytes.Buffer
	if werr := Write(&out, "json", r); werr != nil {
		t.Fatal(werr)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if verr := sch.Validate(doc); verr != nil {
		t.Fatalf("schema: %v", verr)
	}
	for i := range r.Findings {
		r.Findings[i].Explanation = nil
	}
	r.ExecutiveSummary = nil
	var after bytes.Buffer
	if werr := Write(&after, "json", r); werr != nil || after.String() != before.String() {
		t.Fatal("explaining changed something else in the report")
	}
	if _, err := ExplainFinding(t.Context(), r, "", nil, false); err == nil {
		t.Error("an empty prefix matches one finding")
	}
}
