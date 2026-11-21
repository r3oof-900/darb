package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/app"
	"github.com/r3oof-900/clapa/internal/config"
)

// remediate: `clapa remediate [scan flags] [--write [--allow-revoke]
// [--force]] FINGERPRINT` (DESIGN.md §9, §11). Without --write it shows the
// plan, both verifications and the patch, and changes nothing. --write
// applies a fix only when it is verified on both levels; it applies narrow
// fixes only, a revoke (which removes a grant written on purpose) needs
// --allow-revoke; and it refuses to write into a git tree that is not
// clean (or whose state it cannot tell) unless --force.
//
// Exit codes: 0 a verified fix (shown, or written with --write); 1 no
// verified fix (UNKNOWN, no fix within the constraints, a TODO, or
// rejected by a verification); 2 usage, or --write refused; 4 internal.
func remediateCmd(ctx context.Context, args []string, stdout, stderr io.Writer) ExitCode {
	var write, allowRevoke, force bool
	f, fp, ok := parseRemediate(args, stderr, func(fs *flag.FlagSet) {
		fs.BoolVar(&write, "write", false, "apply the verified patch to the input files")
		fs.BoolVar(&allowRevoke, "allow-revoke", false, "with --write: also apply revoke fixes (they remove an explicit grant)")
		fs.BoolVar(&force, "force", false, "with --write: write even into a git tree that is not clean")
	})
	if !ok {
		return ExitUsage
	}
	cfg, err := app.LoadConfig(f.root, f.cfg, f.cfg != "")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		return ExitUsage
	}
	if f.aws.live {
		_, _ = fmt.Fprintln(stderr, "clapa: remediate verifies a fix by rescanning patched files; with live data there are none: run collect-snapshot and remediate the snapshot (--aws-snapshot)")
		return ExitUsage
	}
	in := inputs(f, cfg)
	l, err := app.Load(ctx, in)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		if errors.Is(err, config.ErrInvalid) {
			return ExitUsage
		}
		return ExitIncomplete
	}
	a, err := app.Analyze(l, cfg, f.failOn)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		return ExitInternal
	}
	r, err := app.Remediate(ctx, in, l, a, fp)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		if strings.Contains(err.Error(), "fingerprint") {
			return ExitUsage
		}
		return ExitInternal
	}
	app.WriteRemediation(stdout, r)
	if !r.Accepted() {
		return ExitFindings
	}
	if !write {
		return ExitOK
	}
	if reason := refuseWrite(r, f.root, allowRevoke, force); reason != "" {
		_, _ = fmt.Fprintln(stderr, "clapa: --write refused:", reason)
		return ExitUsage
	}
	written, err := app.WritePatch(f.root, r.Patch)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		return ExitInternal
	}
	for _, p := range written {
		_, _ = fmt.Fprintln(stdout, "wrote", p)
	}
	return ExitOK
}

// refuseWrite says why --write must not write ("" when it may).
func refuseWrite(r *app.Remediation, root string, allowRevoke, force bool) string {
	for i := range r.Plan.Changes {
		if c := &r.Plan.Changes[i]; c.Kind != "narrow" && !allowRevoke {
			return fmt.Sprintf("the fix of %s is a revoke (it removes an explicit grant); confirm it is not needed and pass --allow-revoke", c.Edge)
		}
	}
	if len(r.Patch.Files) == 0 {
		return "the fix has no file to write (a snapshot or live policy: apply the policy document shown)"
	}
	if force {
		return ""
	}
	out, err := exec.Command("git", "-C", root, "status", "--porcelain").Output() //nolint:gosec // G204: fixed command; root is the user's scan root.
	switch {
	case err != nil:
		return fmt.Sprintf("cannot tell whether %s is a clean git tree (%v); pass --force to write anyway", root, err)
	case strings.TrimSpace(string(out)) != "":
		return fmt.Sprintf("the git tree of %s is not clean; commit or stash first, or pass --force", root)
	}
	return ""
}

// parseRemediate parses the scan flags, the remediate flags and exactly one
// fingerprint (after the flags).
func parseRemediate(args []string, stderr io.Writer, extra func(*flag.FlagSet)) (*scanFlags, string, bool) {
	f := &scanFlags{}
	fs := flag.NewFlagSet("remediate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scanFlagsOn(fs, f)
	extra(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		if err == nil {
			_, _ = fmt.Fprintln(stderr, "clapa: remediate needs exactly one finding fingerprint (or a unique prefix of one)")
		}
		return nil, "", false
	}
	if !slices.Contains([]string{"critical", "high", "medium", "low", "info"}, f.failOn) {
		_, _ = fmt.Fprintf(stderr, "clapa: invalid --fail-on %q\n", f.failOn)
		return nil, "", false
	}
	return f, fs.Arg(0), true
}
