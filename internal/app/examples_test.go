package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// docs/examples holds HTML reports made by the tool (scan --fixes --format
// html), for review and demonstration without running it. They must be
// what the tool makes now: a change of the engine or the report that
// changes them fails here until they are made again with
// go test ./internal/app -run TestExampleReports -update.
func TestExampleReports(t *testing.T) {
	examples := map[string]string{
		"report-scenario-01.html": "01_classic/vulnerable",
		"report-scenario-22.html": "22_direct_and_escalation/vulnerable",
	}
	for file, fixture := range examples {
		in := scansFor(t, copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(fixture))))["normalized.golden.json"]
		l, err := Load(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(l, in.Config, DefaultFailOn)
		if err != nil {
			t.Fatal(err)
		}
		r := Report(a, in.Config, DefaultFailOn)
		if ferr := AttachFixes(t.Context(), in, l, a, r); ferr != nil {
			t.Fatal(ferr)
		}
		var got bytes.Buffer
		if werr := Write(&got, "html", r); werr != nil {
			t.Fatal(werr)
		}
		path := filepath.Join(repoRoot(t), "docs", "examples", file)
		if *update {
			if werr := os.WriteFile(path, got.Bytes(), 0o600); werr != nil {
				t.Fatal(werr)
			}
			continue
		}
		want, rerr := os.ReadFile(path) //nolint:gosec // G304: a file of this repository
		if rerr != nil {
			t.Fatalf("%s: %v (run: go test ./internal/app -run TestExampleReports -update)", file, rerr)
		}
		if !bytes.Equal(want, got.Bytes()) {
			t.Errorf("docs/examples/%s is not what the tool makes from %s now: %s (run: go test ./internal/app -run TestExampleReports -update)",
				file, fixture, firstDiff(want, got.Bytes()))
		}
	}
}
