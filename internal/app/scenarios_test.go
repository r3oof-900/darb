package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/rules"
)

// analyzeVariant copies a fixture variant, lets edit change the copy, and
// analyzes it (the fixture itself is never modified).
func analyzeVariant(t *testing.T, fixture string, edit func(dir string)) *Analysis {
	t.Helper()
	dir := copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(fixture)))
	if edit != nil {
		edit(dir)
	}
	in := scansFor(t, dir)["normalized.golden.json"]
	l, err := Load(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Analyze(l, in.Config, DefaultFailOn)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func replaceIn(t *testing.T, file, old, repl string) {
	t.Helper()
	data, err := os.ReadFile(file) //nolint:gosec // G304: inside the test's temp copy.
	if err != nil || !strings.Contains(string(data), old) {
		t.Fatalf("%s: %q not found (%v)", file, old, err)
	}
	if err := os.WriteFile(file, []byte(strings.Replace(string(data), old, repl, 1)), 0o600); err != nil { //nolint:gosec // G703: temp copy.
		t.Fatal(err)
	}
}

func findingFor(a *Analysis, rule, jewel string) *rules.Finding {
	for i := range a.Findings {
		if a.Findings[i].Rule == rule && a.Findings[i].Jewel == jewel {
			return &a.Findings[i]
		}
	}
	return nil
}

// Scenario 7 (DESIGN.md §13.2): iam:PassRole + lambda:CreateFunction without
// an execution primitive is still an escalation, with lower confidence.
func TestPassRoleWithoutInvokeIsLowerConfidence(t *testing.T) {
	a := analyzeVariant(t, "07_passrole_lambda/vulnerable", func(dir string) {
		replaceIn(t, filepath.Join(dir, "terraform", "role.tf"), `["lambda:CreateFunction", "lambda:InvokeFunction"]`, `["lambda:CreateFunction"]`)
	})
	f := findingFor(a, "CLAPA-PATH-002", "arn:aws:s3:::acme-customer-pii")
	if f == nil || f.Confidence != "medium" || f.Factors.Confidence != 700 {
		t.Fatalf("PassRole + CreateFunction alone: %+v", f)
	}
}

// Scenario 10 (DESIGN.md §13.2): with the organization ID configured, a
// matching one gives the path, a non-matching one gives none.
func TestOrganizationIDDecidesScenario10(t *testing.T) {
	withOrg := func(org string) *Analysis {
		return analyzeVariant(t, "10_kms_principal_org_id/vulnerable", func(dir string) {
			f, err := os.OpenFile(filepath.Join(dir, "clapa.yaml"), os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // G304: temp copy.
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if _, err := f.WriteString("assume:\n  aws:PrincipalOrgID: [\"" + org + "\"]\n"); err != nil {
				t.Fatal(err)
			}
		})
	}
	if f := findingFor(withOrg("o-a1b2c3d4e5"), "CLAPA-PATH-001", "arn:aws:s3:::acme-customer-pii"); f == nil || !f.Confirmed {
		t.Errorf("matching organization: %+v", f)
	}
	if f := findingFor(withOrg("o-other"), "CLAPA-PATH-001", "arn:aws:s3:::acme-customer-pii"); f != nil {
		t.Errorf("non-matching organization: %+v", f)
	}
}

// Every rule names failing and passing cases: fixture variants (which must
// exist) or rule-level tests ("test:<name>").
func TestRuleCatalogMetadata(t *testing.T) {
	a := analyzeVariant(t, "01_classic/vulnerable", nil)
	for _, r := range a.Registry.Rules() {
		m := r.Meta()
		if m.Title == "" || m.Rationale == "" || len(m.References) == 0 || m.Major() != "1" {
			t.Errorf("%s: incomplete metadata", m.ID)
		}
		for _, ref := range m.References {
			if !strings.HasPrefix(ref.URL, "https://") {
				t.Errorf("%s: reference %s", m.ID, ref.URL)
			}
		}
		if len(m.Failing) == 0 || len(m.Passing) == 0 {
			t.Errorf("%s: needs at least one failing and one passing case", m.ID)
		}
		for _, f := range append(m.Failing, m.Passing...) {
			if strings.HasPrefix(f, "test:") {
				continue
			}
			if _, err := os.Stat(filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(f))); err != nil {
				t.Errorf("%s: fixture %s: %v", m.ID, f, err)
			}
		}
	}
}
