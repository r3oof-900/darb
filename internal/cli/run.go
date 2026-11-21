package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/r3oof-900/clapa/internal/app"
	"github.com/r3oof-900/clapa/internal/config"
	"github.com/r3oof-900/clapa/internal/rules/catalog"
	"github.com/r3oof-900/clapa/internal/version"
	"github.com/r3oof-900/clapa/pkg/schema"
)

const usage = `usage:
  clapa scan [--root DIR] [--config FILE] [--plan FILE[=TFDIR]]... [--terraform DIR]...
             [--k8s DIR[=CLUSTER]]... [--aws-snapshot DIR]... [--live-aws [AWS flags]]
             [--format console|json|sarif] [--output FILE] [--fail-on critical|high|medium|low|info]
  clapa collect-snapshot --out DIR [AWS flags]
             AWS flags: [--aws-profile P] [--aws-region R]... [--aws-assume-role ARN]...
             [--aws-external-id ID] [--aws-concurrency N] [--aws-call-timeout D]
  clapa remediate [scan input flags] [--write [--allow-revoke] [--force]] FINGERPRINT
  clapa rules list
  clapa rules show RULE-ID
  clapa version
Paths are relative to --root (default "."). Exit codes: 0 clean, 1 findings at or
above --fail-on, 2 usage or configuration error, 3 incomplete scan, 4 internal error.`

// Run executes the command line and returns the exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) ExitCode {
	return RunWith(ctx, args, stdout, stderr, DefaultEnv())
}

// RunWith is Run with the connections of env.
func RunWith(ctx context.Context, args []string, stdout, stderr io.Writer, env *Env) ExitCode {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	switch args[0] {
	case "scan":
		return scan(ctx, args[1:], stdout, stderr, env)
	case "collect-snapshot":
		return collectSnapshot(ctx, args[1:], stdout, stderr, env)
	case "remediate":
		return remediateCmd(ctx, args[1:], stdout, stderr)
	case "rules":
		return rulesCmd(args[1:], stdout, stderr)
	case "version":
		v := version.Get()
		_, _ = fmt.Fprintf(stdout, "clapa %s (commit %s, rule catalog %s)\n", v.Version, v.Commit, catalog.Version)
		return ExitOK
	}
	_, _ = fmt.Fprintf(stderr, "clapa: unknown command %q\n%s\n", args[0], usage)
	return ExitUsage
}

// list is a repeatable string flag.
type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

type scanFlags struct {
	root, cfg, format, output, failOn string
	plans, tfDirs, k8sDirs, snapshots list
	aws                               awsFlags
}

func parseScan(args []string, stderr io.Writer) (*scanFlags, bool) {
	f := &scanFlags{}
	fset := flag.NewFlagSet("scan", flag.ContinueOnError)
	fset.SetOutput(stderr)
	scanFlagsOn(fset, f)
	if err := fset.Parse(args); err != nil || fset.NArg() > 0 {
		return nil, false
	}
	if !slices.Contains([]string{"critical", "high", "medium", "low", "info"}, f.failOn) || !slices.Contains(app.Formats(), f.format) {
		_, _ = fmt.Fprintf(stderr, "clapa: invalid --fail-on %q or --format %q\n", f.failOn, f.format)
		return nil, false
	}
	return f, true
}

// scanFlagsOn defines the input flags shared by scan and remediate.
func scanFlagsOn(fset *flag.FlagSet, f *scanFlags) {
	fset.StringVar(&f.root, "root", ".", "scan root; every input path is relative to it")
	fset.StringVar(&f.cfg, "config", "", "clapa.yaml (default: clapa.yaml in the root, if present)")
	fset.StringVar(&f.format, "format", "console", "output format: "+strings.Join(app.Formats(), ", "))
	fset.StringVar(&f.output, "output", "", "write the report to this file instead of standard output")
	fset.StringVar(&f.failOn, "fail-on", app.DefaultFailOn, "lowest severity that makes the exit code 1")
	fset.Var(&f.plans, "plan", "Terraform plan (JSON or binary), optionally =its configuration directory")
	fset.Var(&f.tfDirs, "terraform", "Terraform directory scanned statically")
	fset.Var(&f.k8sDirs, "k8s", "Kubernetes manifests directory, optionally =cluster name")
	fset.Var(&f.snapshots, "aws-snapshot", "offline AWS snapshot directory (clapa-snapshot/v1, written by collect-snapshot)")
	f.aws.on(fset, true)
}

func scan(ctx context.Context, args []string, stdout, stderr io.Writer, env *Env) ExitCode {
	f, ok := parseScan(args, stderr)
	if !ok {
		return ExitUsage
	}
	cfg, err := app.LoadConfig(f.root, f.cfg, f.cfg != "")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		return ExitUsage
	}
	in := inputs(f, cfg)
	if f.aws.live {
		if in.AWSLive, err = f.aws.options(ctx, env); err != nil {
			_, _ = fmt.Fprintln(stderr, "clapa:", err)
			return ExitUsage
		}
	}
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
	return write(app.Report(a, cfg, f.failOn), f.format, f.output, stdout, stderr)
}

func inputs(f *scanFlags, cfg *config.Config) *app.Inputs {
	in := &app.Inputs{Root: f.root, Config: cfg, Limits: app.DefaultLimits(), TerraformDirs: f.tfDirs, AWSSnapshots: f.snapshots}
	for _, p := range f.plans {
		path, dir, _ := strings.Cut(p, "=")
		in.TerraformPlans = append(in.TerraformPlans, app.PlanInput{Path: path, ConfigDir: dir})
	}
	for _, k := range f.k8sDirs {
		dir, cluster, _ := strings.Cut(k, "=") // "": resolved by app.Load
		in.K8sDirs = append(in.K8sDirs, app.K8sDir{Path: dir, Cluster: cluster})
	}
	return in
}

func write(r *schema.Report, format, output string, stdout, stderr io.Writer) ExitCode {
	w := stdout
	if output != "" {
		f, err := app.CreateOutput(output)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "clapa:", err)
			return ExitUsage
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if err := app.Write(w, format, r); err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		return ExitInternal
	}
	return ExitCode(r.ExitCode)
}

func rulesCmd(args []string, stdout, stderr io.Writer) ExitCode {
	reg, err := catalog.New()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		return ExitInternal
	}
	switch {
	case len(args) == 1 && args[0] == "list":
		for _, r := range reg.Rules() {
			m := r.Meta()
			_, _ = fmt.Fprintf(stdout, "%-16s %-8s %-8s %s\n", m.ID, m.Version, m.Kind, m.Title)
		}
		return ExitOK
	case len(args) == 2 && args[0] == "show":
		r, ok := reg.Get(args[1])
		if !ok {
			_, _ = fmt.Fprintf(stderr, "clapa: no rule %q\n", args[1])
			return ExitUsage
		}
		m := r.Meta()
		_, _ = fmt.Fprintf(stdout, "%s %s (%s)\n%s\n\n%s\n\nATT&CK: %s\n", m.ID, m.Version, m.Kind, m.Title, m.Rationale, strings.Join(m.Techniques, ", "))
		for _, ref := range m.References {
			_, _ = fmt.Fprintf(stdout, "  %s: %s\n", ref.Title, ref.URL)
		}
		return ExitOK
	}
	_, _ = fmt.Fprintln(stderr, usage)
	return ExitUsage
}
