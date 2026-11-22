package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExitCodeValuesAreStable(t *testing.T) {
	// Documented in docs/DESIGN.md section 11; CI scripts depend on these numbers.
	for code, want := range map[ExitCode]int{
		ExitOK: 0, ExitFindings: 1, ExitUsage: 2, ExitIncomplete: 3, ExitInternal: 4,
	} {
		if int(code) != want {
			t.Errorf("exit code %d, want %d", code, want)
		}
	}
}

func run(t *testing.T, args ...string) (code ExitCode, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

const fixtures = "../../tests/fixtures/"

func TestCommands(t *testing.T) {
	if code, _, errOut := run(t); code != ExitUsage || !strings.Contains(errOut, "usage") {
		t.Errorf("no arguments: %d %q", code, errOut)
	}
	if code, _, _ := run(t, "frobnicate"); code != ExitUsage {
		t.Error("unknown command")
	}
	if code, out, _ := run(t, "version"); code != ExitOK || !strings.Contains(out, "rule catalog 2.1.0") {
		t.Errorf("version: %q", out)
	}
	if code, out, _ := run(t, "rules", "list"); code != ExitOK || strings.Count(out, "DARB-") != 11 {
		t.Errorf("rules list: %q", out)
	}
	if code, out, _ := run(t, "rules", "show", "DARB-PATH-001"); code != ExitOK || !strings.Contains(out, "T1530") || !strings.Contains(out, "https://") {
		t.Errorf("rules show: %q", out)
	}
	for _, args := range [][]string{{"rules", "show", "NOPE"}, {"rules"}, {"scan", "--format", "xml"}, {"scan", "--fail-on", "urgent"}, {"scan", "--bogus"}, {"scan", "extra"}} {
		if code, _, _ := run(t, args...); code != ExitUsage {
			t.Errorf("%v: %d, want usage error", args, code)
		}
	}
}

// Nothing scanned is exit 3 and says so: never a clean result.
func TestEmptyScanIsIncomplete(t *testing.T) {
	code, out, _ := run(t, "scan", "--root", fixtures+"15_empty_input/vulnerable")
	if code != ExitIncomplete || !strings.Contains(out, "NOTHING WAS SCANNED") {
		t.Fatalf("%d %q", code, out)
	}
}

func TestScanFormats(t *testing.T) {
	args := []string{"scan", "--root", fixtures + "01_classic/vulnerable", "--terraform", "terraform", "--k8s", "k8s"}
	code, out, _ := run(t, args...)
	if code != ExitFindings || !strings.Contains(out, "[CRITICAL 729] DARB-PATH-001") {
		t.Fatalf("console: %d %q", code, out)
	}
	_, out, _ = run(t, append(args, "--format", "json")...)
	var doc struct {
		Schema   string `json:"schema"`
		ExitCode int    `json:"exit_code"`
		Findings []struct {
			Rule  string `json:"rule"`
			Score int    `json:"score"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Schema != "darb-report/v1" || doc.ExitCode != 1 || doc.Findings[0].Score != 729 {
		t.Fatalf("json: %v %+v", err, doc)
	}
	_, out, _ = run(t, append(args, "--format", "sarif")...)
	if !strings.Contains(out, `"version": "2.1.0"`) || !strings.Contains(out, "darbFingerprint/v1") {
		t.Fatalf("sarif: %q", out)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	if code, _, _ := run(t, append(args, "--format", "json", "--output", report)...); code != ExitFindings {
		t.Fatalf("--output: %d", code)
	}
	if data, err := os.ReadFile(report); err != nil || !strings.Contains(string(data), "DARB-PATH-001") { //nolint:gosec // G304: the test's own temp file.
		t.Fatalf("report file: %v", err)
	}
	if code, _, _ := run(t, append(args, "--output", t.TempDir())...); code != ExitUsage {
		t.Error("an output path that is a directory must be refused")
	}
	if code, _, _ := run(t, "scan", "--root", fixtures+"01_classic/vulnerable", "--config", "missing.yaml"); code != ExitUsage {
		t.Error("an explicit missing config is a usage error")
	}
}
