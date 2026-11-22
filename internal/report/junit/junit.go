package junit

import (
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/pkg/schema"
)

// Reporter writes JUnit XML for CI systems that show test results: one
// test case per finding, a failure for each finding at or above the
// report's --fail-on threshold; the others pass, so the run lists them
// without failing on them. Every string is XML-escaped by encoding/xml.
type Reporter struct{}

var severities = []string{"critical", "high", "medium", "low", "info"}

func atOrAbove(sev, threshold string) bool {
	s, t := slices.Index(severities, sev), slices.Index(severities, threshold)
	return s >= 0 && t >= 0 && s <= t
}

type suites struct {
	XMLName  xml.Name `xml:"testsuites"`
	Name     string   `xml:"name,attr"`
	Tests    int      `xml:"tests,attr"`
	Failures int      `xml:"failures,attr"`
	Errors   int      `xml:"errors,attr"`
	Suites   []suite  `xml:"testsuite"`
}

type suite struct {
	Name       string     `xml:"name,attr"`
	Tests      int        `xml:"tests,attr"`
	Failures   int        `xml:"failures,attr"`
	Errors     int        `xml:"errors,attr"`
	Properties properties `xml:"properties"`
	Cases      []testcase `xml:"testcase"`
}

type properties struct {
	Props []property `xml:"property"`
}

type property struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type testcase struct {
	Name      string   `xml:"name,attr"`
	Classname string   `xml:"classname,attr"`
	Failure   *failure `xml:"failure,omitempty"`
	SystemOut string   `xml:"system-out,omitempty"`
}

type failure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// Write renders r: one suite per kind of rule (attack paths,
// misconfigurations), cases in the report's order.
func (Reporter) Write(w io.Writer, r *schema.Report) error {
	threshold := r.ThreatModel.FailOn
	byKind := map[string]*suite{
		"path":    {Name: "darb attack paths"},
		"posture": {Name: "darb misconfigurations"},
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		kind := "path"
		target := f.Entry + " -> " + f.Jewel
		if f.Resource != "" {
			kind, target = "posture", f.Resource
		}
		s := byKind[kind]
		c := testcase{Name: f.Rule + " " + target, Classname: "darb." + f.Rule}
		switch {
		case atOrAbove(f.Severity, threshold):
			c.Failure = &failure{
				Message: fmt.Sprintf("%s %d: %s", strings.ToUpper(f.Severity), f.Score, f.Title),
				Type:    f.Severity,
				Text:    details(f),
			}
			s.Failures++
		default:
			c.SystemOut = details(f)
		}
		s.Tests++
		s.Cases = append(s.Cases, c)
	}
	out := suites{Name: "darb"}
	for _, k := range []string{"path", "posture"} {
		s := byKind[k]
		s.Properties.Props = []property{
			{"fail_on", threshold},
			{"tool_version", r.Tool.Version},
			{"rule_catalog", r.Tool.RuleCatalog},
			{"inputs_collected", fmt.Sprint(r.Coverage.Collected)},
			{"gaps_over_tolerance", fmt.Sprint(r.Coverage.GapsOverTolerance)},
		}
		out.Tests += s.Tests
		out.Failures += s.Failures
		out.Suites = append(out.Suites, *s)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// details is what a reader needs to act: status, path or resource, the
// cheapest fix and the fingerprint.
func details(f *schema.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %d (%s)\n", f.Rule, strings.ToUpper(f.Severity), f.Score, strings.ReplaceAll(f.Status, "_", " "))
	for _, p := range f.Path {
		fmt.Fprintf(&b, "  %s\n", p)
	}
	if len(f.Chokepoints) > 0 {
		fmt.Fprintf(&b, "cheapest fix (cost %d): %s\n", f.CutCost, strings.Join(f.Chokepoints, "; "))
	}
	fmt.Fprintf(&b, "fingerprint %s\n", f.Fingerprint)
	return b.String()
}
