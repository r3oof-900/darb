package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/pkg/schema"
)

func scanJSON(t *testing.T, root string, extra ...string) (ExitCode, *schema.Report, string) {
	t.Helper()
	args := append([]string{"scan", "--root", root, "--terraform", "terraform", "--k8s", "k8s", "--format", "json"}, extra...)
	code, out, errOut := run(t, args...)
	var r schema.Report
	if code != ExitUsage && json.Unmarshal([]byte(out), &r) != nil {
		t.Fatalf("not JSON (exit %d): %s %s", code, out, errOut)
	}
	return code, &r, errOut
}

func writeFile(t *testing.T, root, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pathFinding(t *testing.T, r *schema.Report) *schema.Finding {
	t.Helper()
	for i := range r.Findings {
		if r.Findings[i].Rule == "CLAPA-PATH-001" {
			return &r.Findings[i]
		}
	}
	t.Fatalf("no CLAPA-PATH-001 in %+v", r.Findings)
	return nil
}

func TestSuppressionsThroughTheCLI(t *testing.T) {
	root := copyFixture(t, "01_classic/vulnerable")
	code, r, _ := scanJSON(t, root)
	fp := pathFinding(t, r).Fingerprint
	if code != ExitFindings {
		t.Fatalf("without suppressions: exit %d", code)
	}
	suppression := func(expires string) string {
		return "suppressions:\n  - {fingerprint: " + fp + ", reason: accepted until the migration, owner: payments-team, expires: \"" + expires + "\"}\n"
	}

	// In force: the critical path is silenced; the high CLAPA-POST-008 and
	// the low CLAPA-POST-007 remain, so the exit code is still 1.
	writeFile(t, root, ".clapa-ignore.yaml", suppression("2099-12-31"))
	code, r, _ = scanJSON(t, root)
	if code != ExitFindings || len(r.Suppressed) != 1 || r.Suppressed[0].Fingerprint != fp || r.Suppressed[0].Owner != "payments-team" || len(r.Findings) != 2 {
		t.Fatalf("suppressed: exit %d %+v findings %d", code, r.Suppressed, len(r.Findings))
	}
	for _, f := range r.Findings {
		if f.Fingerprint == fp {
			t.Fatal("the suppressed finding is still listed")
		}
	}
	broad := ""
	for _, f := range r.Findings {
		if f.Rule == "CLAPA-POST-008" {
			broad = f.Fingerprint
		}
	}
	// Both high findings suppressed: only the low one is left, exit 0.
	writeFile(t, root, ".clapa-ignore.yaml", suppression("2099-12-31")+"  - {fingerprint: "+broad+", reason: legacy key, owner: platform, expires: \"2099-12-31\"}"+"\n")
	if code, r, _ = scanJSON(t, root); code != ExitOK || len(r.Suppressed) != 2 || len(r.Findings) != 1 {
		t.Fatalf("both suppressed: exit %d findings %d", code, len(r.Findings))
	}
	if _, out, _ := run(t, "scan", "--root", root, "--terraform", "terraform", "--k8s", "k8s"); !strings.Contains(out, "suppressed 2 finding(s)") {
		t.Fatalf("console:\n%s", out)
	}

	// Expired: the finding fires again, and the console says so.
	writeFile(t, root, ".clapa-ignore.yaml", suppression("2000-01-01"))
	code, r, _ = scanJSON(t, root)
	if code != ExitFindings || len(r.Suppressed) != 0 || len(r.ExpiredSuppressions) != 1 || !r.ExpiredSuppressions[0].Fires || pathFinding(t, r).Fingerprint != fp {
		t.Fatalf("expired: exit %d %+v", code, r.ExpiredSuppressions)
	}
	if _, out, _ := run(t, "scan", "--root", root, "--terraform", "terraform", "--k8s", "k8s"); !strings.Contains(out, "WARNING: the suppression of "+fp+" (owner payments-team) expired on 2000-01-01: its finding fires again") {
		t.Fatalf("console:\n%s", out)
	}

	// A suppression without its owner (or reason, or expiry) is exit 2.
	writeFile(t, root, ".clapa-ignore.yaml", "suppressions:\n  - {fingerprint: "+fp+", reason: r, expires: \"2099-12-31\"}\n")
	if code, _, errOut := scanJSON(t, root); code != ExitUsage || !strings.Contains(errOut, "reason, owner and expires are required") {
		t.Fatalf("missing owner: exit %d %q", code, errOut)
	}
	// An explicit file that does not exist is exit 2; the default may be absent.
	if code, _, _ := scanJSON(t, root, "--ignore", "no-such.yaml"); code != ExitUsage {
		t.Fatalf("missing --ignore file: exit %d", code)
	}
}

func TestBaselineThroughTheCLI(t *testing.T) {
	fixed := copyFixture(t, "01_classic/fixed")
	_, before, _ := scanJSON(t, fixed)
	data, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	root := copyFixture(t, "01_classic/vulnerable")
	writeFile(t, root, "previous.json", string(data))
	code, r, _ := scanJSON(t, root, "--baseline", "previous.json")
	if code != ExitFindings || r.Baseline == nil || r.Baseline.File != "previous.json" {
		t.Fatalf("exit %d baseline %+v", code, r.Baseline)
	}
	// Only the new findings are listed: the path is new; the namespace
	// finding of both scans is unchanged; the fixed scan's rotation finding
	// on the receipts key is resolved.
	if len(r.Findings) != r.Baseline.New || pathFinding(t, r) == nil || r.Baseline.Unchanged != 1 || len(r.Baseline.Resolved) != 1 ||
		r.Baseline.Resolved[0].Rule != "CLAPA-POST-006" {
		t.Fatalf("findings %d baseline %+v", len(r.Findings), r.Baseline)
	}
	// The same scan as its own baseline: nothing new, exit 0.
	_, full, _ := scanJSON(t, root)
	data, _ = json.Marshal(full)
	writeFile(t, root, "same.json", string(data))
	if code, r, _ := scanJSON(t, root, "--baseline", "same.json"); code != ExitOK || len(r.Findings) != 0 || r.Baseline.New != 0 || len(r.Baseline.Resolved) != 0 {
		t.Fatalf("same baseline: exit %d %+v", code, r.Baseline)
	}
	writeFile(t, root, "bad.json", `{"schema": "other/v1"}`)
	if code, _, errOut := scanJSON(t, root, "--baseline", "bad.json"); code != ExitUsage || !strings.Contains(errOut, "not a clapa-report/v1 JSON report") {
		t.Fatalf("bad baseline: exit %d %q", code, errOut)
	}
}
