package app

import (
	"bytes"
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The JUnit and Markdown reports of every fixture variant: the XML parses,
// has one case per finding, and failures exactly when the exit code is 1
// (findings at or above --fail-on, which outrank an incomplete scan); the Markdown stays within its limit. With DARB_JUNIT_OUT set, the
// XML files are written there, and CI validates them against the JUnit 10
// XSD in internal/report/junit/testdata with xmllint (DESIGN.md §11).
func TestJUnitAndMarkdownReports(t *testing.T) {
	out := os.Getenv("DARB_JUNIT_OUT")
	variants, err := filepath.Glob(filepath.Join(repoRoot(t), "tests", "fixtures", "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, variant := range variants {
		if fi, err := os.Stat(variant); err != nil || !fi.IsDir() {
			continue
		}
		name := filepath.Base(filepath.Dir(variant)) + "_" + filepath.Base(variant)
		for golden, in := range scansFor(t, copyTree(t, variant)) {
			l, err := Load(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			a, err := Analyze(l, in.Config, DefaultFailOn)
			if err != nil {
				t.Fatal(err)
			}
			r := Report(a, in.Config, DefaultFailOn)
			var x bytes.Buffer
			if err := Write(&x, "junit", r); err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Tests    int `xml:"tests,attr"`
				Failures int `xml:"failures,attr"`
			}
			if err := xml.Unmarshal(x.Bytes(), &doc); err != nil || doc.Tests != len(r.Findings) || (doc.Failures > 0) != (r.ExitCode == 1) {
				t.Errorf("%s (%s): %v %+v exit %d", name, golden, err, doc, r.ExitCode)
			}
			if out != "" {
				file := filepath.Join(out, name+"_"+strings.TrimSuffix(golden, ".json")+".xml")
				if err := os.WriteFile(file, x.Bytes(), 0o600); err != nil { //nolint:gosec // G703: a folder CI names (DARB_JUNIT_OUT), test only.
					t.Fatal(err)
				}
			}
			var md bytes.Buffer
			if err := Write(&md, "markdown", r); err != nil || md.Len() > 60000 || !strings.Contains(md.String(), "### Coverage") {
				t.Errorf("%s (%s): markdown %v, %d bytes", name, golden, err, md.Len())
			}
			n++
		}
	}
	if n < 40 {
		t.Fatalf("only %d variants", n)
	}
}
