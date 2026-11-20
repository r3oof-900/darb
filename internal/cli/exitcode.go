package cli

// ExitCode is the process exit status. See docs/DESIGN.md section 11.
type ExitCode int

// Exit codes. When several apply, precedence is
// ExitInternal > ExitUsage > ExitFindings > ExitIncomplete > ExitOK.
const (
	// ExitOK: no findings at or above the threshold and coverage complete.
	ExitOK ExitCode = 0
	// ExitFindings: findings at or above the --fail-on threshold.
	ExitFindings ExitCode = 1
	// ExitUsage: usage or configuration error.
	ExitUsage ExitCode = 2
	// ExitIncomplete: coverage gaps above tolerance, or nothing collected.
	ExitIncomplete ExitCode = 3
	// ExitInternal: internal error, including a recovered panic.
	ExitInternal ExitCode = 4
)
