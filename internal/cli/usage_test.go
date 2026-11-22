package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every usage error says what is wrong: exit 2 with a non-empty message on
// standard error, for each command.
func TestEveryUsageErrorSaysSomething(t *testing.T) {
	fx := fixtures + "01_classic/vulnerable"
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"--log-format", "xml", "version"},
		{"scan", "nowhere"},
		{"scan", fx + "/darb.yaml"},
		{"scan", "../../internal/redact"},
		{"scan", fx, "../../internal/redact"},
		{"scan", "--format", "xml", fx},
		{"scan", "--fail-on", "severe", fx},
		{"scan", "--no-such-flag"},
		{"scan", "--llm-model", "m", fx},
		{"scan", "--root", fx, "--config", "missing.yaml"},
		{"graph", "nowhere"},
		{"graph", "--format", "sarif", fx},
		{"graph", "--ignore", "x.yaml", fx},
		{"explain"},
		{"explain", "--root", fx, "--terraform", "terraform", "a", "b"},
		{"explain", "--format", "html", "abc"},
		{"remediate"},
		{"remediate", "--root", fx, "--output", "x.json", "abc"},
		{"doctor", "extra"},
		{"doctor", "--aws-assume-role", "arn:aws:iam::111122223333:role/r"},
		{"collect-snapshot"},
		{"rules", "bogus"},
		{"rules", "show", "DARB-NOPE"},
	} {
		code, _, errOut := run(t, args...)
		if code != ExitUsage || strings.TrimSpace(errOut) == "" {
			t.Errorf("darb %s: exit %d, message %q", strings.Join(args, " "), code, errOut)
		}
	}
}

// A command that exits 2 without writing anything still gets a hint.
func TestUsageHint(t *testing.T) {
	var b bytes.Buffer
	usageHint(&counting{w: &b}, ExitUsage, []string{"scan", "x"})
	if b.String() != "darb: usage error (run darb scan -h for the usage)\n" {
		t.Fatalf("%q", b.String())
	}
	b.Reset()
	usageHint(&counting{w: &b, n: 1}, ExitUsage, nil)
	usageHint(&counting{w: &b}, ExitFindings, nil)
	if b.Len() != 0 {
		t.Errorf("a hint after a message, or on another exit code: %q", b.String())
	}
}

// `darb scan DIR` finds the inputs under DIR and reads its darb.yaml: the
// report is the one of the explicit flags, byte for byte; flags may follow
// the path.
func TestScanPathsEqualExplicitFlags(t *testing.T) {
	fx := fixtures + "01_classic/vulnerable"
	_, explicit, _ := run(t, "scan", "--root", fx, "--terraform", "terraform", "--k8s", "k8s", "--format", "json")
	code, positional, errOut := run(t, "scan", fx, "--format", "json")
	if code != ExitFindings || positional != explicit {
		t.Fatalf("exit %d %s; the positional report differs from the explicit one", code, errOut)
	}
	// With --root, the paths are relative to it, and the root keeps its darb.yaml.
	code, rooted, _ := run(t, "scan", "--root", fx, "terraform", "k8s", "--format", "json")
	if code != ExitFindings || rooted != explicit {
		t.Fatalf("exit %d; paths under --root differ from the explicit flags", code)
	}
	// The same for graph.
	_, g1, _ := run(t, "graph", "--root", fx, "--terraform", "terraform", "--k8s", "k8s", "--format", "json")
	_, g2, _ := run(t, "graph", fx, "--format", "json")
	if g1 != g2 || g1 == "" {
		t.Error("graph DIR differs from the explicit flags")
	}
}

// A snapshot directory is recognised by its manifest; hidden directories
// are skipped; a JSON file without apiVersion and kind is not a manifest.
func TestScanPathsSnapshotAndHidden(t *testing.T) {
	fx := fixtures + "14_same_names_two_accounts/vulnerable"
	_, explicit, _ := run(t, "scan", "--root", fx, "--aws-snapshot", "snapshot", "--k8s", "k8s", "--format", "json")
	_, positional, errOut := run(t, "scan", fx, "--format", "json")
	if positional != explicit {
		t.Fatalf("snapshot and manifests not detected: %s", errOut)
	}
	dir := t.TempDir()
	for name, text := range map[string]string{
		".terraform/modules/x/main.tf": `resource "aws_s3_bucket" "hidden" {}`,
		"notes.json":                   `{"kind": "only a kind"}`,
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, _, errOut := run(t, "scan", dir); code != ExitUsage || !strings.Contains(errOut, "no Terraform files (.tf), Kubernetes manifests or darb snapshot found") {
		t.Fatalf("exit %d %q", code, errOut)
	}
}
