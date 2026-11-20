package cli

import (
	"bytes"
	"context"
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

func TestSkeletonDoesNotClaimSuccess(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"scan", "."}, &out, &errOut)
	if code == ExitOK {
		t.Fatal("skeleton must not exit 0: it has not scanned anything")
	}
	if out.Len() != 0 {
		t.Errorf("unexpected stdout: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "not implemented") {
		t.Errorf("stderr should say commands are not implemented, got %q", errOut.String())
	}
}
