package junit

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/pkg/schema"
)

// One case per finding; a failure for each finding at or above --fail-on;
// counts that add up; any name read back exactly as it was.
func TestCasesAndFailures(t *testing.T) {
	hostile := `"]]><x>&amp;</testcase>` + "\x00ok"
	r := &schema.Report{
		ThreatModel: schema.ThreatModel{FailOn: "high"},
		Findings: []schema.Finding{
			{Rule: "DARB-PATH-001", Title: "t", Severity: "critical", Score: 729, Status: "confirmed", Entry: hostile, Jewel: "arn:aws:s3:::b", Fingerprint: "f1"},
			{Rule: "DARB-PATH-002", Title: "t", Severity: "medium", Score: 300, Status: "unconfirmed", Entry: "e", Jewel: "j", Fingerprint: "f2"},
			{Rule: "DARB-POST-008", Title: "t", Severity: "high", Score: 600, Status: "confirmed", Resource: "r", Fingerprint: "f3"},
			{Rule: "DARB-POST-007", Title: "t", Severity: "low", Score: 245, Status: "confirmed", Resource: "n", Fingerprint: "f4"},
		},
	}
	var b bytes.Buffer
	if err := (Reporter{}).Write(&b, r); err != nil {
		t.Fatal(err)
	}
	var doc suites
	if err := xml.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("%v:\n%s", err, b.String())
	}
	if doc.Tests != 4 || doc.Failures != 2 || len(doc.Suites) != 2 || doc.Suites[0].Failures != 1 || doc.Suites[1].Failures != 1 {
		t.Fatalf("counts %+v", doc)
	}
	c := doc.Suites[0].Cases[0]
	if c.Failure == nil || c.Failure.Type != "critical" || !strings.HasPrefix(c.Name, "DARB-PATH-001 "+`"]]><x>&amp;</testcase>`) {
		t.Errorf("case %+v", c)
	}
	if doc.Suites[0].Cases[1].Failure != nil || !strings.Contains(doc.Suites[0].Cases[1].SystemOut, "unconfirmed") {
		t.Errorf("a medium finding failed at --fail-on high: %+v", doc.Suites[0].Cases[1])
	}
}
