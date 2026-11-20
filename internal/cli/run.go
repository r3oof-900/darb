package cli

import (
	"context"
	"fmt"
	"io"
)

// Run executes the command line and returns the exit code.
//
// Phase 1 skeleton: no command is implemented yet, so every invocation is
// reported as a usage error rather than pretending to scan.
func Run(_ context.Context, _ []string, _, stderr io.Writer) ExitCode {
	_, _ = fmt.Fprintln(stderr, "clapa: not implemented yet: this is the phase 1 skeleton and no command exists; see docs/DESIGN.md")
	return ExitUsage
}
