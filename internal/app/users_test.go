package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/access"
)

// CreateAccessKey towards a user holding AdministratorAccess (the real
// route of item 4's review): ci, which reads nothing, becomes the admin and
// reads the bucket: DARB-PATH-002 at 567 (entry 700 x path factor 900 = 630;
// x pii 900 = 567). The admin's many dominated routes (it can rewrite
// policies and escalate) stay in the cut; this test checks the path, not
// every cut edge (scenario 29's golden target holds an explicit read).
func TestCreateAccessKeyToAnAdministrator(t *testing.T) {
	a := analyzeVariant(t, "29_credential_leak/vulnerable", func(dir string) {
		file := filepath.Join(dir, "snapshot", "111122223333", "iam", "get-account-authorization-details.json")
		data, err := os.ReadFile(file) //nolint:gosec // G304: the test's temp copy.
		if err != nil {
			t.Fatal(err)
		}
		var auth struct {
			Users []map[string]any `json:"UserDetailList"`
			Rest  map[string]any   `json:"-"`
		}
		var all map[string]any
		if jerr := json.Unmarshal(data, &all); jerr != nil {
			t.Fatal(jerr)
		}
		if jerr := json.Unmarshal(data, &auth); jerr != nil {
			t.Fatal(jerr)
		}
		for _, user := range auth.Users {
			if user["UserName"] == "reports" {
				user["UserPolicyList"] = []any{}
				user["AttachedManagedPolicies"] = []any{map[string]any{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}}
			}
		}
		all["UserDetailList"] = auth.Users
		out, err := json.Marshal(all)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, out, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	f := findingFor(a, "DARB-PATH-002", piiBucket29)
	if f == nil || f.Entry != "arn:aws:iam::111122223333:user/ci" || f.Factors.Score != 567 || !f.Confirmed {
		t.Fatalf("ci -> admin -> PII: %+v", f)
	}
	if len(f.Path) == 0 || f.Path[0] != "CAN_ESCALATE arn:aws:iam::111122223333:user/reports" {
		t.Errorf("the path starts with the new key of the admin: %v", f.Path)
	}
}

// A Terraform input's IAM users are not analysed: one note names them.
func TestTerraformUsersNote(t *testing.T) {
	a := analyzeVariant(t, "01_classic/vulnerable", func(dir string) {
		tf := "resource \"aws_iam_user\" \"ci\" {\n  name = \"ci\"\n}\n\nresource \"aws_iam_access_key\" \"ci\" {\n  user = aws_iam_user.ci.name\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "terraform", "users.tf"), []byte(tf), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	i := slices.IndexFunc(a.Notes, func(n access.Note) bool { return n.Subject == NoteTerraformUsers })
	if i < 0 || a.Notes[i].Kind != "not-modelled" {
		t.Fatalf("notes: %+v", a.Notes)
	}
	for _, want := range []string{"aws_iam_user.ci", "aws_iam_access_key.ci"} {
		if !strings.Contains(a.Notes[i].Detail, want) {
			t.Errorf("the note names %s: %s", want, a.Notes[i].Detail)
		}
	}
}

const piiBucket29 = "arn:aws:s3:::acme-customer-pii"
