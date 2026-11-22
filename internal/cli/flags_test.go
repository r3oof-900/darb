package cli

import (
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/config"
)

// A shared flag a command parses but does not use is a usage error, not
// silently ignored.
func TestUnusedFlagsAreRefused(t *testing.T) {
	for _, args := range [][]string{
		append(append([]string{"remediate"}, scan01...), "--output", "x.json", "abc"),
		append(append([]string{"explain"}, scan01...), "--baseline", "old.json", "abc"),
		append(append([]string{"graph"}, scan01...), "--ignore", "x.yaml"),
		{"doctor", "--aws-assume-role", "arn:aws:iam::111122223333:role/r"},
	} {
		code, _, errOut := run(t, args...)
		if code != ExitUsage || !strings.Contains(errOut, "does not use --") {
			t.Errorf("%s: %d %q", args[0], code, errOut)
		}
	}
}

// --terraform-bin reaches the plan reader (DESIGN.md §4.1).
func TestTerraformBinFlag(t *testing.T) {
	f, ok := parseScan([]string{"--plan", "p.tfplan", "--terraform-bin", "/opt/terraform/bin/terraform"}, &strings.Builder{})
	if !ok {
		t.Fatal("not parsed")
	}
	if in := inputs(f, config.Default()); in.TerraformBin != "/opt/terraform/bin/terraform" || len(in.TerraformPlans) != 1 {
		t.Fatalf("inputs %+v", in)
	}
}
