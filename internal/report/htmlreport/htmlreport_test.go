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
		Schema: "clapa-report/v1", GeneratedAt: "2026-11-22T00:00:00Z",
		Tool:   schema.Tool{Name: "clapa", Version: "test", RuleCatalog: "1"},
		Inputs: []schema.ScannedInput{{Kind: "terraform-dir", Path: scriptName, Digest: "sha256:00"}, {Kind: "aws-live", Accounts: []string{breakout}, Regions: []string{endOfData}, Digest: "sha256:01"}},
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
				Hops: []schema.Hop{
					{Kind: "RUNS_AS", From: breakout, To: scriptName, FromKind: "k8s:workload", ToKind: "k8s:serviceaccount"},
					{Kind: "ASSUMES" + scriptName, From: scriptName, To: endOfData, FromKind: "k8s:serviceaccount", ToKind: "aws:iam:role", Cut: "resolve"},
					{Kind: "CAN_ESCALATE[iam:modify-policy]", From: endOfData, To: endOfData, FromKind: "aws:iam:role", ToKind: "aws:iam:role:any-permission"},
					{Kind: "CAN_READ_PLAINTEXT", From: endOfData, To: templateText, FromKind: "aws:iam:role:any-permission", ToKind: "aws:s3:bucket", Cut: "cut"},
					{Kind: "CAN_READ_PLAINTEXT", From: templateText, To: scriptName, FromKind: "aws:s3:bucket", ToKind: "x:unknown"},
				},
				WorstCaseHops: []schema.Hop{{Kind: "ASSUMES", From: breakout, To: scriptName, FromKind: "k8s:workload", ToKind: "aws:iam:role", Cut: "cut"}},
				Remediation: &schema.Remediation{
					Pending: []string{scriptName}, Note: breakout,
					Fixes: []schema.Fix{
						{
							Strategy: "mitigation", Changes: []schema.Change{{Edge: endOfData, Side: "identity", Kind: "narrow", Cost: 1, Why: scriptName, TODO: breakout}},
							VerifiedInMemory: true, VerifiedOnFiles: true, Pending: scriptName,
							Diff: "--- a/" + scriptName + "\n+++ b/x\n@@ -1 +1 @@\n-" + breakout + "\n+" + endOfData + "\n " + templateText + "\n",
							TODO: []string{scriptName}, Policies: []schema.Policy{{ID: scriptName, Note: breakout, Document: endOfData}},
						},
						{Strategy: "root-cause", Suggestion: scriptName, Changes: []schema.Change{}, Reasons: []string{breakout}},
						{Strategy: "root-cause", Changes: []schema.Change{{Edge: endOfData, Side: "resource", Kind: "narrow", Cost: 2, Why: breakout}}, Reasons: []string{"a new finding appears"}},
					},
				},
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
		case "img", "iframe", "object", "embed", "link", "base", "foreignobject", "use", "image", "a":
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
	for _, want := range []string{"No attack path.", "No misconfiguration.", "Nothing was collected", "No coverage gap.", "0 attack paths", "0 objects collected"} {
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

// The path view is static SVG: no script in it, the cut edge dashed and
// marked, the resolve step marked, the worst-case path in <details>, and
// the same report gives the same bytes.
func TestPathViewIsStatic(t *testing.T) {
	r := hostileReport()
	out := render(t, r)
	figures := strings.Count(out, `<figure class="pathview">`)
	if figures != 2 {
		t.Fatalf("%d path views, want the path and the worst-case path", figures)
	}
	first := firstFigure(out)
	for _, want := range []string{`<g class="edge cut"`, `<g class="edge resolve"`, "✂", ">?<", `marker-end="url(#clapa-arrow-cut)"`} {
		if !strings.Contains(first, want) {
			t.Errorf("the path view lacks %s", want)
		}
	}
	if strings.Contains(first, "style=") || strings.Contains(strings.ToLower(first), "<script") {
		t.Error("the path view has an inline style or a script")
	}
	if !strings.Contains(out, "<details><summary>Worst-case path") {
		t.Error("the worst-case path is not in <details>")
	}
	if strings.Contains(first, scriptName) || !strings.Contains(first, "&lt;script&gt;") {
		t.Error("names in the SVG are not escaped text")
	}
	if firstFigure(render(t, r)) != first {
		t.Error("the same report gives a different path view")
	}
}

// firstFigure: the first path view of a page, or "".
func firstFigure(page string) string {
	_, rest, _ := strings.Cut(page, `<figure class="pathview">`)
	fig, _, _ := strings.Cut(rest, "</figure>")
	return fig
}

// The policy depends only on the embedded assets, never on the report.
func TestCSPDoesNotDependOnTheReport(t *testing.T) {
	csp := func(out string) string {
		i := strings.Index(out, `http-equiv="Content-Security-Policy" content="`)
		rest := out[i+len(`http-equiv="Content-Security-Policy" content="`):]
		return rest[:strings.IndexByte(rest, '"')]
	}
	a := csp(render(t, hostileReport()))
	b := csp(render(t, &schema.Report{Summary: schema.Summary{BySeverity: map[string]int{}}}))
	if a != b || a == "" {
		t.Fatalf("policy changes with the report: %q vs %q", a, b)
	}
}

// Fixes: the strategy, the mitigation warning, both verifications, the
// patch as classed lines, the advice.
func TestFixesSection(t *testing.T) {
	out := render(t, hostileReport())
	for _, want := range []string{
		"mitigation: blocks this path only; the broad grant remains",
		"✔ verified in memory", "✔ verified on patched files", "✘ not verified in memory", "suggestion, not verified",
		`<span class="add">`, `<span class="del">`, `<span class="hunk">`, `<span class="file">`,
		"Resolve first (no change)", "remediation status: partial, pending resolution",
		"Scanned inputs", "generated 2026-11-22T00:00:00Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q", want)
		}
	}
	if strings.Index(out, `class="strategy mitigation"`) > strings.Index(out, `class="strategy root-cause"`) {
		t.Error("the fixes are not in the order given (the app orders them, DESIGN.md 9.2)")
	}
	order := []string{"Recommended fix", "Other options", `<details class="chosen"><summary>How this fix was chosen`}
	for i := 1; i < len(order); i++ {
		if a, b := strings.Index(out, order[i-1]), strings.Index(out, order[i]); a < 0 || b < 0 || a > b {
			t.Errorf("%q must come before %q", order[i-1], order[i])
		}
	}
	// A suggestion is not a failure: one ✘ pair, for the fix whose
	// verification failed, none for the suggestion.
	if n := strings.Count(out, "✘ not verified in memory"); n != 1 {
		t.Errorf("%d failed verifications shown, want 1 (the suggestion is grey, not red)", n)
	}
}

// A cut of resolve steps only: decide first, then the known alternative.
func TestResolveOnlyFix(t *testing.T) {
	f := schema.Finding{
		Rule: "CLAPA-PATH-001", Kind: "path", Severity: "medium", Score: 291, Status: "unconfirmed", Fingerprint: "r",
		Chokepoints:          []string{"CAN_DECRYPT x -> k"},
		Fix:                  []schema.FixStep{{Edge: "CAN_DECRYPT x -> k", Side: "identity", Kind: "resolve", Policy: "p", Resolve: "-var-file (b)"}},
		AlternativeFixDetail: []schema.FixStep{{Edge: "CAN_READ x -> b", Side: "identity", Kind: "revoke", Policy: "p", Cost: 3}},
		RemediationStatus:    "partial_pending_resolution",
	}
	out := render(t, &schema.Report{Summary: schema.Summary{BySeverity: map[string]int{}}, Findings: []schema.Finding{f}})
	a, b := strings.Index(out, "<h4>Resolve first</h4>"), strings.Index(out, "Known alternative, to apply now")
	if a < 0 || b < a || !strings.Contains(out, "-var-file (b)") {
		t.Fatal("a resolve-only cut shows the command first, then the known alternative")
	}
	if strings.Contains(out, "<h4>Recommended fix</h4>") {
		t.Error("a resolve-only cut has no recommended change")
	}
}

// Attack paths come before misconfigurations, each by severity then score.
func TestAttackPathsFirst(t *testing.T) {
	fs := []schema.Finding{
		{Rule: "CLAPA-POST-001", Kind: "posture", Severity: "critical", Score: 900, Title: "post-critical", Fingerprint: "a"},
		{Rule: "CLAPA-PATH-001", Kind: "path", Severity: "medium", Score: 291, Title: "path-medium", Fingerprint: "b"},
		{Rule: "CLAPA-PATH-002", Kind: "path", Severity: "high", Score: 600, Title: "path-high-600", Fingerprint: "c"},
		{Rule: "CLAPA-PATH-003", Kind: "path", Severity: "high", Score: 700, Title: "path-high-700", Fingerprint: "d"},
	}
	out := render(t, &schema.Report{Summary: schema.Summary{BySeverity: map[string]int{}}, Findings: fs})
	want := []string{`id="paths-h"`, "path-high-700", "path-high-600", "path-medium", `id="posture-h"`, "post-critical"}
	for i := 1; i < len(want); i++ {
		if strings.Index(out, want[i-1]) > strings.Index(out, want[i]) {
			t.Errorf("%q must come before %q", want[i-1], want[i])
		}
	}
	if !strings.Contains(out, "3 attack paths") || !strings.Contains(out, "1 misconfiguration") {
		t.Error("the summary counts attack paths apart from misconfigurations")
	}
}
