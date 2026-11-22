package sarif

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/r3oof-900/darb/pkg/schema"
)

// A path finding is a result with its location under %SRCROOT% and a code
// flow: the entry, then one location per hop. A misconfiguration has no
// flow. Names are JSON text, whatever they contain.
func TestCodeFlows(t *testing.T) {
	hostile := `"><script>alert(1)</script>`
	r := &schema.Report{
		Tool: schema.Tool{Name: "darb", Version: "test"},
		Findings: []schema.Finding{
			{
				Rule: "DARB-PATH-001", Severity: "critical", Score: 729, Entry: "k8s:w", Jewel: hostile, Fingerprint: "f1",
				Location: &schema.Location{File: "k8s/app.yaml", StartLine: 14},
				Hops: []schema.Hop{
					{Kind: "RUNS_AS", From: "k8s:w", To: "k8s:sa"},
					{Kind: "ASSUMES", From: "k8s:sa", To: "arn:aws:iam::1:role/r"},
					{Kind: "CAN_READ_PLAINTEXT", From: "arn:aws:iam::1:role/r", To: hostile},
				},
			},
			{Rule: "DARB-POST-007", Severity: "low", Score: 245, Resource: "ns", Fingerprint: "f2"},
		},
	}
	var b bytes.Buffer
	if err := (Reporter{}).Write(&b, r); err != nil {
		t.Fatal(err)
	}
	var doc log
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	res := doc.Runs[0].Results
	if len(res) != 2 || len(res[1].CodeFlows) != 0 {
		t.Fatalf("results %+v", res)
	}
	if a := res[0].Locations[0].PhysicalLocation.ArtifactLocation; a.URI != "k8s/app.yaml" || a.URIBaseID != "%SRCROOT%" {
		t.Errorf("location %+v", a)
	}
	locs := res[0].CodeFlows[0].ThreadFlows[0].Locations
	if len(locs) != 4 || locs[0].Location.PhysicalLocation == nil || locs[0].Location.PhysicalLocation.Region.StartLine != 14 {
		t.Fatalf("flow %+v", locs)
	}
	if m := locs[3].Location.Message.Text; m != "CAN_READ_PLAINTEXT arn:aws:iam::1:role/r -> "+hostile || locs[3].Location.LogicalLocations[0].FullyQualifiedName != hostile {
		t.Errorf("last hop %q", m)
	}
}
