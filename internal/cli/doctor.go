package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/app"
	"github.com/r3oof-900/darb/internal/config"
)

// doctorCmd: `darb doctor [--probe-aws [--aws-profile P] [--aws-region R]]
// [--probe-k8s CONTEXT [--kubeconfig F]]` (DESIGN.md §11). Without a probe
// flag it calls nothing and reads no file: it says what is installed and
// which configuration files exist. Exit codes: 0 every requested check ran
// (warnings included); 3 a probe failed; 2 usage.
func doctorCmd(ctx context.Context, args []string, stdout, stderr io.Writer, env *Env) ExitCode {
	var probeAWS bool
	var probeK8s, kubeconfig string
	var aws awsFlags
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&probeAWS, "probe-aws", false, "call sts:GetCallerIdentity with the configured AWS credentials")
	fs.StringVar(&probeK8s, "probe-k8s", "", "ask this kubeconfig context's API server for its version")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig file (default: KUBECONFIG, then ~/.kube/config)")
	aws.on(fs, false)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "darb: doctor takes no arguments, got %q (darb doctor -h)\n", fs.Args())
		return ExitUsage
	}
	if unused(fs, "doctor", stderr, "aws-assume-role", "aws-external-id", "aws-concurrency", "aws-call-timeout") {
		return ExitUsage
	}
	home, _ := os.UserHomeDir()
	checks := app.Doctor(ctx, &app.DoctorOptions{
		Getenv: env.getenv, Exists: env.exists, Home: home,
		ProbeAWS: probeAWS, AWSProfile: aws.profile, AWSRegions: aws.regions, AWS: env.AWS,
		ProbeK8s: probeK8s, Kubeconfig: kubeconfig, K8s: env.K8s.Kubeconfig,
	})
	code := ExitOK
	for _, c := range checks {
		_, _ = fmt.Fprintf(stdout, "[%-7s] %s: %s\n", c.Status, c.Name, c.Detail)
		if c.Status == app.DoctorFail {
			code = ExitIncomplete
		}
	}
	return code
}

// graphCmd: `darb graph [scan input flags] [--format dot|json] [--output F]`
// writes the access graph of the inputs (every node and edge, not only
// those on paths). Exit codes: 0 written; 2 usage; 3 incomplete input; 4
// internal.
func graphCmd(ctx context.Context, args []string, stdout, stderr io.Writer, env *Env) ExitCode {
	f := &scanFlags{}
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scanFlagsOn(fs, f)
	paths, err := parseInterspersed(fs, args)
	if err != nil || unused(fs, "graph", stderr, "ignore", "baseline", "fail-on") || !addPaths(f, paths, rootGiven(fs), stderr) {
		return ExitUsage
	}
	if f.format == "console" { // scanFlagsOn's default
		f.format = "dot"
	}
	if !slices.Contains(app.GraphFormats(), f.format) {
		_, _ = fmt.Fprintf(stderr, "darb: graph writes %s, not %q\n", strings.Join(app.GraphFormats(), " or "), f.format)
		return ExitUsage
	}
	a, _, code := analyzeInputs(ctx, f, env, stderr, true)
	if a == nil {
		return code
	}
	w := stdout
	if f.output != "" {
		out, err := app.CreateOutput(f.output)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "darb:", err)
			return ExitUsage
		}
		defer func() { _ = out.Close() }()
		w = out
	}
	if err := app.WriteGraph(w, f.format, a); err != nil {
		_, _ = fmt.Fprintln(stderr, "darb:", err)
		return ExitInternal
	}
	return ExitOK
}

// analyzeInputs loads darb.yaml and the inputs (live ones when allowed)
// and analyzes them; on failure it reports the error and returns nil with
// the exit code.
func analyzeInputs(ctx context.Context, f *scanFlags, env *Env, stderr io.Writer, live bool) (*app.Analysis, *config.Config, ExitCode) {
	fail := func(err error, code ExitCode) (*app.Analysis, *config.Config, ExitCode) {
		_, _ = fmt.Fprintln(stderr, "darb:", err)
		return nil, nil, code
	}
	cfg, err := app.LoadConfig(f.root, f.cfg, f.cfg != "")
	if err != nil {
		return fail(err, ExitUsage)
	}
	in := inputs(f, cfg)
	if live && f.aws.live {
		if in.AWSLive, err = f.aws.options(ctx, env); err != nil {
			return fail(err, ExitUsage)
		}
	}
	if live {
		if in.K8sLive, err = f.k8s.clusters(ctx, env, &f.aws, stderr); err != nil {
			return fail(err, ExitUsage)
		}
	}
	l, err := app.Load(ctx, in)
	if err != nil {
		if errors.Is(err, config.ErrInvalid) {
			return fail(err, ExitUsage)
		}
		return fail(err, ExitIncomplete)
	}
	logLoaded(env.logger(), f, l)
	a, err := app.Analyze(l, cfg, f.failOn)
	if err != nil {
		return fail(err, ExitInternal)
	}
	return a, cfg, ExitOK
}
