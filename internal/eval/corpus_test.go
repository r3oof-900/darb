package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The corpus: testdata/eval/*.yaml. Format documented in testdata/eval/README.md.

const minCorpusCases = 150

// requiredFirst are the four cases DESIGN.md section 6.1 commits to, in order.
var requiredFirst = []string{
	"iam-ug.permissions-boundaries.resource-based-policies.iam-user-arn.not-limited-by-boundary",
	"iam-ug.permissions-boundaries.resource-based-policies.iam-role-arn.limited-by-boundary-and-session-policy",
	"iam-ug.permissions-boundaries.resource-based-policies.role-session-arn.not-limited",
	"iam-ug.permissions-boundaries.resource-based-policies.federated-user-session.limited-by-boundary-and-session-policy",
}

type corpusFile struct {
	Anchors  json.RawMessage `json:"anchors"` // YAML anchors live here; ignored
	Defaults caseSpec        `json:"defaults"`
	Cases    []caseSpec      `json:"cases"`
}

type caseSpec struct {
	Name            string         `json:"name"`
	Doc             string         `json:"doc"`
	Principal       *principalSpec `json:"principal"`
	Action          string         `json:"action"`
	Resource        string         `json:"resource"`
	ResourceAccount *string        `json:"resource_account"`
	Context         *contextSpec   `json:"context"`
	Policies        policiesSpec   `json:"policies"`
	Expect          string         `json:"expect"`
	// Optional checks. Statements are "kind:label" (label = Sid or #index);
	// unresolved entries are "Element" or "Element:key".
	ExpectContributing []string `json:"expect_contributing"`
	ExpectUnresolved   []string `json:"expect_unresolved"`
	ExpectMissing      []string `json:"expect_missing"`
}

type principalSpec struct {
	Kind      string `json:"kind"`
	ARN       string `json:"arn"`
	Account   string `json:"account"`
	Source    string `json:"source"`
	Canonical string `json:"canonical"`
}

type contextSpec struct {
	Default string                `json:"default"`
	Present map[string]stringList `json:"present"`
	Absent  []string              `json:"absent"`
	Unknown []string              `json:"unknown"`
}

// stringList accepts a string or a list of strings.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("context value must be a string or a list of strings: %w", err)
	}
	*s = many
	return nil
}

type policiesSpec struct {
	Identity []json.RawMessage   `json:"identity"`
	Resource []json.RawMessage   `json:"resource"`
	Boundary json.RawMessage     `json:"boundary"`
	Session  []json.RawMessage   `json:"session"`
	SCPs     [][]json.RawMessage `json:"scps"`
	RCPs     [][]json.RawMessage `json:"rcps"`
	Required *bool               `json:"resource_policy_required"`
}

// merge fills unset fields of c from the file defaults.
func (c *caseSpec) merge(d *caseSpec) {
	if c.Principal == nil {
		c.Principal = d.Principal
	}
	if c.Action == "" {
		c.Action = d.Action
	}
	if c.Resource == "" {
		c.Resource = d.Resource
	}
	if c.ResourceAccount == nil {
		c.ResourceAccount = d.ResourceAccount
	}
	if c.Context == nil {
		c.Context = d.Context
	}
	p, dp := &c.Policies, &d.Policies
	if p.Identity == nil {
		p.Identity = dp.Identity
	}
	if p.Resource == nil {
		p.Resource = dp.Resource
	}
	if p.Boundary == nil {
		p.Boundary = dp.Boundary
	}
	if p.Session == nil {
		p.Session = dp.Session
	}
	if p.SCPs == nil {
		p.SCPs = dp.SCPs
	}
	if p.RCPs == nil {
		p.RCPs = dp.RCPs
	}
	if p.Required == nil {
		p.Required = dp.Required
	}
}

func loadCorpus(t *testing.T) (files []string, cases []caseSpec) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "eval", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files: %v", err)
	}
	slices.Sort(files)
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // G304: f comes from a glob of testdata.
		if err != nil {
			t.Fatal(err)
		}
		var cf corpusFile
		if err := yaml.UnmarshalStrict(data, &cf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for i := range cf.Cases {
			cf.Cases[i].merge(&cf.Defaults)
			cases = append(cases, cf.Cases[i])
		}
	}
	return files, cases
}

func TestCorpus(t *testing.T) {
	_, cases := loadCorpus(t)
	defer func() {
		if len(cases) < minCorpusCases {
			t.Errorf("corpus has %d cases, need at least %d", len(cases), minCorpusCases)
		}
	}()
	for i, name := range requiredFirst {
		if cases[i].Name != name {
			t.Fatalf("corpus case %d is %q, DESIGN.md section 6.1 requires %q", i, cases[i].Name, name)
		}
	}
	seen := map[string]bool{}
	for i := range cases {
		c := &cases[i]
		if seen[c.Name] || c.Doc == "" || !strings.Contains(c.Name, ".") {
			t.Fatalf("case %q: names must be unique, dotted after the doc rule, and carry a doc reference", c.Name)
		}
		seen[c.Name] = true
		t.Run(c.Name, func(t *testing.T) { runCase(t, c) })
	}
}

func runCase(t *testing.T, c *caseSpec) {
	req, ps := buildCase(t, c)
	d := Evaluate(req, ps)
	if d.Verdict.String() != c.Expect {
		t.Fatalf("verdict %s, want %s\n  doc: %s\n  decision: %+v", d.Verdict, c.Expect, c.Doc, d)
	}
	checkList(t, "contributing", c.ExpectContributing, refLabels(d.Contributing))
	checkList(t, "unresolved", c.ExpectUnresolved, unresolvedLabels(d.Unresolved))
	checkList(t, "missing", c.ExpectMissing, componentLabels(d.Missing))
}

func checkList(t *testing.T, what string, want, got []string) {
	t.Helper()
	if want == nil {
		return
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("%s: want %q in %v", what, w, got)
		}
	}
}

func refLabels(refs []StatementRef) []string {
	var out []string
	for i := range refs {
		r := &refs[i]
		label := r.Sid
		if label == "" {
			label = fmt.Sprintf("#%d", r.Index)
		}
		out = append(out, r.Kind.String()+":"+label)
	}
	return out
}

func unresolvedLabels(us []Unresolved) []string {
	var out []string
	for _, u := range us {
		out = append(out, u.Element)
		if u.Key != "" {
			out = append(out, u.Element+":"+u.Key)
		}
	}
	return out
}

func componentLabels(cs []Component) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.String())
	}
	return out
}
