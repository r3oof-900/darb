package cli

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// copyFixture copies a fixture variant into a temp directory (no golden
// files) and returns it.
func copyFixture(t *testing.T, variant string) string {
	t.Helper()
	src := filepath.Join(fixtures, variant)
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		data, err := os.ReadFile(p) //nolint:gosec // G304: walking the fixture tree.
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o600) //nolint:gosec // G703: inside the test's temp dir.
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// pathFingerprint is the fingerprint of the first path finding of a scan.
func pathFingerprint(t *testing.T, args []string) string {
	t.Helper()
	_, out, _ := run(t, append(append([]string{"scan"}, args...), "--format", "json")...)
	var doc struct {
		Findings []struct {
			Rule        string `json:"rule"`
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range doc.Findings {
		if strings.HasPrefix(f.Rule, "DARB-PATH-") {
			return f.Fingerprint
		}
	}
	t.Fatal("no path finding")
	return ""
}

func inputArgs(dir string) []string {
	return []string{"--root", dir, "--terraform", "terraform", "--k8s", "k8s"}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.email=test@example.invalid", "-c", "user.name=test"}, args...)
	cmd := exec.Command("git", full...) //nolint:gosec // G204: fixed git subcommands of the test.
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

// remediate shows the verified patch and changes nothing; --write applies
// a narrow fix, refuses a revoke without --allow-revoke, and refuses a
// tree whose git state is not clean (or unknown) without --force.
func TestRemediateCommand(t *testing.T) {
	dir := copyFixture(t, "01_classic/vulnerable")
	role := filepath.Join(dir, "terraform", "role.tf")
	before, _ := os.ReadFile(role) //nolint:gosec // G304: the test's own copy.
	fp := pathFingerprint(t, inputArgs(dir))
	args := append(append([]string{"remediate"}, inputArgs(dir)...), fp[:12])

	code, out, errOut := run(t, args...)
	if code != ExitOK || !strings.Contains(out, "verified in memory: yes") || !strings.Contains(out, "verified on the patched files (rescanned from scratch): yes") ||
		!strings.Contains(out, `Effect = "Deny", Action = ["kms:Decrypt"]`) {
		t.Fatalf("show: %d %s %s", code, out, errOut)
	}
	if now, _ := os.ReadFile(role); !bytes.Equal(now, before) { //nolint:gosec // G304: the test's own copy.
		t.Fatal("remediate without --write changed a file")
	}

	write := append(append([]string{"remediate", "--write"}, inputArgs(dir)...), fp)
	if code, _, errOut := run(t, write...); code != ExitUsage || !strings.Contains(errOut, "cannot tell whether") {
		t.Fatalf("not a git tree: %d %s", code, errOut)
	}
	git(t, dir, "init", "-q")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "fixture")
	writeTestFile(t, filepath.Join(dir, "notes.txt"), "uncommitted")
	if code, _, errOut := run(t, write...); code != ExitUsage || !strings.Contains(errOut, "is not clean") {
		t.Fatalf("dirty tree: %d %s", code, errOut)
	}
	if err := os.Remove(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	if code, wrote, errOut := run(t, write...); code != ExitOK || !strings.Contains(wrote, "wrote terraform/role.tf") {
		t.Fatalf("clean tree: %d %s %s", code, wrote, errOut)
	}
	// The written fix holds: the finding is gone.
	_, out, _ = run(t, append(append([]string{"scan"}, inputArgs(dir)...), "--format", "json")...)
	if strings.Contains(out, fp) {
		t.Fatal("the finding is still reported after --write")
	}
}

func writeTestFile(t *testing.T, file, content string) {
	t.Helper()
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil { //nolint:gosec // G703: inside the test's temp dir.
		t.Fatal(err)
	}
}

func TestRemediateRevokeNeedsAllowRevoke(t *testing.T) {
	dir := copyFixture(t, "01_classic/vulnerable")
	// SSE-S3: the read is the whole path, and it is an explicit grant.
	bucket := filepath.Join(dir, "terraform", "pii_kms_bucket.tf")
	data, _ := os.ReadFile(bucket) //nolint:gosec // G304: the test's own copy.
	text := strings.Replace(string(data), `sse_algorithm     = "aws:kms"`, `sse_algorithm = "AES256"`, 1)
	text = strings.Replace(text, "      kms_master_key_id = aws_kms_key.pii.arn", "", 1)
	writeTestFile(t, bucket, text)
	fp := pathFingerprint(t, inputArgs(dir))
	write := append(append([]string{"remediate", "--write", "--force"}, inputArgs(dir)...), fp)
	code, out, errOut := run(t, write...)
	if code != ExitUsage || !strings.Contains(errOut, "is a revoke") || !strings.Contains(out, "this removes an explicit grant; confirm it is not needed") {
		t.Fatalf("revoke without --allow-revoke: %d %s %s", code, out, errOut)
	}
	allow := append(append([]string{"remediate", "--write", "--force", "--allow-revoke"}, inputArgs(dir)...), fp)
	if code, out, errOut := run(t, allow...); code != ExitOK || !strings.Contains(out, "wrote terraform/role.tf") {
		t.Fatalf("revoke with --allow-revoke: %d %s %s", code, out, errOut)
	}
}

// An UNKNOWN path is not patched: exit 1 and what would decide it.
func TestRemediateUnknown(t *testing.T) {
	dir := copyFixture(t, "10_kms_principal_org_id/vulnerable")
	fp := pathFingerprint(t, inputArgs(dir))
	code, out, _ := run(t, append(append([]string{"remediate"}, inputArgs(dir)...), fp)...)
	if code != ExitFindings || !strings.Contains(out, "UNKNOWN: no patch") || !strings.Contains(out, `assume: {"aws:PrincipalOrgID"`) {
		t.Fatalf("%d %s", code, out)
	}
	for _, args := range [][]string{{"remediate"}, {"remediate", "a", "b"}, append(append([]string{"remediate"}, inputArgs(dir)...), "ffffffff")} {
		if code, _, _ := run(t, args...); code != ExitUsage {
			t.Errorf("%v: %d, want usage", args, code)
		}
	}
}

// With intended access declared, --write applies the verified root-cause
// fix (first in the output): the Allow itself is narrowed.
func TestRemediateWritesRootCause(t *testing.T) {
	dir := copyFixture(t, "01b_classic_intended/vulnerable")
	fp := pathFingerprint(t, inputArgs(dir))
	code, out, errOut := run(t, append(append([]string{"remediate", "--write", "--force"}, inputArgs(dir)...), fp)...)
	if code != ExitOK || !strings.HasPrefix(strings.SplitN(out, "== ", 2)[1], "root-cause fix") || !strings.Contains(out, "wrote terraform/role.tf") {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "terraform", "role.tf")) //nolint:gosec // G304: the test's own copy.
	if !strings.Contains(string(data), `Action = ["kms:Decrypt"], Resource = [aws_kms_key.receipts.arn]`) {
		t.Fatalf("the Allow is not narrowed: %s", data)
	}
	if code, out, _ := run(t, append(append([]string{"scan"}, inputArgs(dir)...), "--format", "json")...); code != ExitOK || strings.Contains(out, `"rule": "DARB-POST-008"`) {
		t.Fatalf("after the root-cause fix: %d %s", code, out)
	}
}
