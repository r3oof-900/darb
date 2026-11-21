package htmlreport

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/r3oof-900/clapa/pkg/schema"
)

// hostile: names an input could carry (a resource named <script>, an
// attribute breakout, an end of the JSON block), THREAT_MODEL.md.
const (
	scriptName   = `<script>alert(1)</script>`
	breakout     = `"><img src=x onerror=alert(2)>`
	endOfData    = `</script><script>alert(3)</script>`
	templateText = `{{.CSP}}`
)

func hostileReport() *schema.Report {
	steps := []schema.FixStep{
		{Edge: "CAN_READ " + breakout, Side: "identity", Kind: "revoke", Policy: scriptName, Cost: 3},
		{Edge: "CAN_DECRYPT " + endOfData, Side: "identity", Kind: "resolve", Policy: templateText, Resolve: scriptName},
	}
	also := []schema.FindingRef{{Rule: "CLAPA-PATH-002", Entry: scriptName, Jewel: breakout}}
	unc := []schema.UncuttableEdge{{Edge: endOfData, Reason: "no single change breaks it"}}
	return &schema.Report{
		Schema: "clapa-report/v1",
		Tool:   schema.Tool{Name: "clapa", Version: "test", RuleCatalog: "1"},
		Summary: schema.Summary{
			Findings: 2, BySeverity: map[string]int{"critical": 1, "high": 1},
			Unconfirmed: 1,
		},
		Findings: []schema.Finding{
			{
				Rule: "CLAPA-PATH-001", Kind: "path", Title: "A workload can read crown-jewel data", Severity: "critical", Score: 729,
				Status: "unconfirmed", Confidence: "low", Undecided: []string{scriptName},
				Entry: breakout, Jewel: scriptName, Path: []string{"RUNS_AS " + scriptName, "CAN_READ_PLAINTEXT " + endOfData},
				PathsFound: 2, PathsTruncated: true, WorstCasePath: []string{"ASSUMES " + breakout},
				Chokepoints: []string{"CAN_READ " + breakout}, CutCost: 3, Fix: steps, OtherSideFix: steps[:1], AlternativeFixDetail: steps[1:],
				SharedFixPossible: []string{scriptName}, AlsoFixes: &also, Uncuttable: &unc, RemediationStatus: "partial_pending_resolution",
				DefaultsUsed: []schema.Default{{Key: "k", Setting: scriptName, Value: breakout, ValueSource: "default", Reference: endOfData}},
				Evidence:     []string{endOfData}, Location: &schema.Location{File: scriptName, StartLine: 1, Address: breakout, ARN: endOfData},
				Fingerprint: "f1",
			},
			{Rule: "CLAPA-POST-001", Kind: "posture", Title: breakout, Severity: "high", Score: 600, Status: "confirmed", Resource: scriptName, NoFix: true, Fingerprint: "f2"},
		},
		IntendedAccess: []schema.IntendedAccess{{Principal: scriptName, Action: "s3:GetObject", Resource: breakout, Status: "verified", Detail: endOfData}},
		Coverage: schema.Coverage{
			Collected: 3, Gaps: []schema.Gap{{Kind: "unresolved", Source: scriptName, File: breakout, Line: 2, Detail: endOfData}},
			Notes: []schema.Note{{Kind: "not-modelled", Subject: scriptName, Detail: breakout}},
		},
		Rules:               []schema.Rule{{ID: "CLAPA-PATH-001", Version: "1.0.0", Title: scriptName, Techniques: []string{"T1530"}}},
		Suppressed:          []schema.SuppressedFinding{{Fingerprint: "f3", Rule: "CLAPA-PATH-001", Severity: "low", Entry: scriptName, Jewel: breakout, Reason: endOfData, Owner: scriptName, Expires: "2027-01-01"}},
		ExpiredSuppressions: []schema.ExpiredSuppression{{Fingerprint: "f4", Reason: scriptName, Owner: breakout, Expires: "2026-01-01", Fires: true}},
		Baseline:            &schema.Baseline{File: scriptName, New: 1, Unchanged: 1, Resolved: []schema.ResolvedItem{{Fingerprint: "f5", Rule: "CLAPA-PATH-001", Entry: scriptName, Jewel: breakout}}},
		ExitCode:            1,
	}
}

func render(t *testing.T, r *schema.Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := (Reporter{}).Write(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// walk visits every element of the document.
func walk(n *html.Node, f func(*html.Node)) {
	if n.Type == html.ElementNode {
		f(n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, f)
	}
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func text(n *html.Node) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
		}
	}
	return b.String()
}

// Untrusted names never become markup: the only scripts are the data block
// and the embedded script, no element carries an event handler, no image or
// frame appears, and each hostile name is shown as text.
func TestHostileNamesAreText(t *testing.T) {
	out := render(t, hostileReport())
	doc, err := html.Parse(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	js := mustAsset(t, "report.js")
	var scripts []*html.Node
	var visible strings.Builder
	walk(doc, func(n *html.Node) {
		switch n.Data {
		case "script":
			scripts = append(scripts, n)
		case "img", "iframe", "object", "embed", "link", "base":
			t.Errorf("unexpected element <%s>", n.Data)
		}
		for _, a := range n.Attr {
			if strings.HasPrefix(strings.ToLower(a.Key), "on") || strings.Contains(strings.ToLower(a.Val), "javascript:") {
				t.Errorf("<%s> carries %s=%q", n.Data, a.Key, a.Val)
			}
		}
		if n.Data != "script" && n.Data != "style" {
			visible.WriteString(text(n))
		}
	})
	if len(scripts) != 2 {
		t.Fatalf("%d script elements, want the data block and the embedded script", len(scripts))
	}
	if typ, _ := attr(scripts[0], "type"); typ != "application/json" {
		t.Errorf("the first script is the data block, type %q", typ)
	}
	if text(scripts[1]) != js {
		t.Error("the second script is exactly the embedded asset")
	}
	for _, s := range []string{scriptName, breakout, endOfData, templateText} {
		if !strings.Contains(visible.String(), s) {
			t.Errorf("%q is not shown as text", s)
		}
	}
	if strings.Contains(out, "<script>alert") || strings.Contains(out, "<img") {
		t.Error("a hostile name reached the markup unescaped")
	}
}

// The policy forbids everything but the inline style and script, each by
// the SHA-256 of exactly the bytes in the page.
func TestCSPHashesTheInlineAssets(t *testing.T) {
	out := render(t, hostileReport())
	doc, err := html.Parse(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	var policy, style, script string
	walk(doc, func(n *html.Node) {
		switch n.Data {
		case "meta":
			if v, _ := attr(n, "http-equiv"); v == "Content-Security-Policy" {
				policy, _ = attr(n, "content")
			}
		case "style":
			style = text(n)
		case "script":
			if _, typed := attr(n, "type"); !typed {
				script = text(n)
			}
		}
	})
	if policy != CSP(style, script) {
		t.Fatalf("policy %q does not hash the page's style and script", policy)
	}
	for _, want := range []string{"default-src 'none'", "base-uri 'none'", "form-action 'none'", "img-src 'none'"} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy lacks %s", want)
		}
	}
	if strings.Contains(policy, "unsafe-inline") || strings.Contains(policy, "http") {
		t.Errorf("policy allows too much: %s", policy)
	}
}

// The data block is the report, as JSON, and the page is deterministic.
func TestDataBlockIsTheReport(t *testing.T) {
	r := hostileReport()
	out := render(t, r)
	doc, err := html.Parse(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	var data string
	walk(doc, func(n *html.Node) {
		if id, _ := attr(n, "id"); id == "clapa-report" {
			data = text(n)
		}
	})
	if strings.Contains(strings.ToLower(data), "</script") {
		t.Fatal("the data block can end early")
	}
	var got, want schema.Report
	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Fatalf("data block: %v", err)
	}
	b, _ := json.Marshal(r)
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Error("the data block is not the report")
	}
	if render(t, r) != out {
		t.Error("two renderings differ")
	}
}

// An empty scan says so: nothing collected is not a clean result.
func TestEmptyReport(t *testing.T) {
	out := render(t, &schema.Report{Summary: schema.Summary{BySeverity: map[string]int{}}})
	for _, want := range []string{"No finding.", "Nothing was collected", "No coverage gap."} {
		if !strings.Contains(out, want) {
			t.Errorf("empty report lacks %q", want)
		}
	}
}

func mustAsset(t *testing.T, name string) string {
	t.Helper()
	b, err := assets.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
