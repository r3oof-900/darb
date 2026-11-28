package app

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// limitRow is one row of DESIGN.md §12.3.
type limitRow struct {
	limit, kind, text, scenario string
}

// statedLimits reads the table of DESIGN.md §12.3.
func statedLimits(t *testing.T) []limitRow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "### 12.3 Limits every report states")
	if !ok {
		t.Fatal("DESIGN.md has no section 12.3")
	}
	section, _, _ = strings.Cut(section, "\n### ")
	row := regexp.MustCompile("^\\| ([^|]+) \\| `(note|gap): ([^`]+)` \\| [^|]+ \\| `([^`]+)` \\|$")
	var out []limitRow
	tableLines := 0
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "| Limit ") {
			tableLines++
		}
		if m := row.FindStringSubmatch(line); m != nil {
			out = append(out, limitRow{limit: m[1], kind: m[2], text: m[3], scenario: m[4]})
		}
	}
	if tableLines != len(out) {
		t.Fatalf("%d rows in DESIGN.md §12.3, %d of them in the form | limit | `note: …` or `gap: …` | … | `scenario` |", tableLines, len(out))
	}
	if len(out) < 7 {
		t.Fatalf("only %d rows read from DESIGN.md §12.3", len(out))
	}
	return out
}

// inlineScenarios are scenarios no fixture has, written by the test.
var inlineScenarios = map[string]map[string]string{
	// IAM users in Terraform are not analysed (item 4).
	"terraform-iam-user": {"terraform/main.tf": `resource "aws_iam_user" "ci" {
  name = "ci"
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}
`},
	// Terraform without tier takes the region's default tier: unknown, so
	// the parameter may be advanced and can be shared.
	"ssm-parameter-without-tier": {"terraform/main.tf": `resource "aws_ssm_parameter" "db" {
  name  = "/prod/db/password"
  type  = "SecureString"
  value = "not-a-real-value"
}
`},
}

// reportOf analyses one scenario and returns what its reports state: the
// note subjects and the gap details, of every scan of the variant.
func reportOf(t *testing.T, scenario string) (notes, gaps []string) {
	t.Helper()
	var loaded []*Loaded
	var configs []*Inputs
	if name, ok := strings.CutPrefix(scenario, "inline:"); ok {
		files, ok := inlineScenarios[name]
		if !ok {
			t.Fatalf("no inline scenario %q", name)
		}
		var in *Inputs
		l := loadTree(t, files, func(i *Inputs) { i.TerraformDirs = []string{"terraform"}; in = i })
		loaded, configs = append(loaded, l), append(configs, in)
	} else {
		dir := filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(scenario))
		for _, in := range scansFor(t, copyTree(t, dir)) {
			l, err := Load(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			loaded, configs = append(loaded, l), append(configs, in)
		}
	}
	for i, l := range loaded {
		a, err := Analyze(l, configs[i].Config, DefaultFailOn)
		if err != nil {
			t.Fatal(err)
		}
		r := Report(a, configs[i].Config, DefaultFailOn)
		for _, n := range r.Coverage.Notes {
			notes = append(notes, n.Subject)
		}
		for _, g := range r.Coverage.Gaps {
			gaps = append(gaps, g.Detail)
		}
	}
	return notes, gaps
}

// Every limit DESIGN.md §12.3 states is in the report of its scenario, and
// every note subject the code writes is stated there: a document cannot
// promise a note the code does not write, nor the code write one no
// document explains.
func TestStatedLimits(t *testing.T) {
	rows := statedLimits(t)
	var stated []string
	for _, r := range rows {
		notes, gaps := reportOf(t, r.scenario)
		found := false
		switch r.kind {
		case "note":
			stated = append(stated, r.text)
			found = slices.ContainsFunc(notes, func(s string) bool { return s == r.text || strings.HasSuffix(s, " "+r.text) })
		case "gap":
			found = slices.ContainsFunc(gaps, func(s string) bool { return strings.Contains(s, r.text) })
		}
		if !found {
			t.Errorf("%s: the report of %s has no %s %q (notes %q)", r.limit, r.scenario, r.kind, r.text, notes)
		}
	}
	for _, subject := range []string{NoteKMSGrants, NoteS3ACLs, NoteOrganizations, NoteRAMShares, NoteAdmission} {
		if !slices.Contains(stated, subject) {
			t.Errorf("the code writes the note %q; DESIGN.md §12.3 does not state it", subject)
		}
	}
}

// The KMS and S3 notes name what they concern and appear only when the
// input has it; the Organizations note only with AWS data.
func TestResourceNotes(t *testing.T) {
	notes, _ := reportOf(t, "21_k8s_secret/vulnerable") // Kubernetes only
	for _, s := range []string{NoteKMSGrants, NoteS3ACLs, NoteOrganizations} {
		if slices.Contains(notes, s) {
			t.Errorf("a Kubernetes-only scan carries %q", s)
		}
	}
	dir := filepath.Join(repoRoot(t), "tests", "fixtures", "01_classic", "vulnerable")
	for _, in := range scansFor(t, copyTree(t, dir)) {
		l, err := Load(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(l, in.Config, DefaultFailOn)
		if err != nil {
			t.Fatal(err)
		}
		r := Report(a, in.Config, DefaultFailOn)
		var kms, s3 string
		for _, n := range r.Coverage.Notes {
			switch n.Subject {
			case NoteKMSGrants:
				kms = n.Detail
			case NoteS3ACLs:
				s3 = n.Detail
			}
		}
		// Terraform keys: the runtime-grants note names the key. The bucket
		// states BucketOwnerEnforced (ACLs disabled): no S3 ACLs note.
		if !strings.Contains(kms, "key/tf-aws_kms_key.pii") || s3 != "" ||
			!strings.Contains(kms, "can be missed") || r.ExitCode != 1 {
			t.Errorf("notes kms=%q s3=%q exit %d", kms, s3, r.ExitCode)
		}
	}
}
