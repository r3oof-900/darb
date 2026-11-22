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
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
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
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return ExitUsage
	}
	if f.format == "console" { // scanFlagsOn's default
		f.format = "dot"
	}
	if !slices.Contains(app.GraphFormats(), f.format) {
		_, _ = fmt.Fprintf(stderr, "darb: graph writes %s, not %q\n", strings.Join(app.GraphFormats(), " or "), f.format)
		return ExitUsage
	}
	cfg, err := app.LoadConfig(f.root, f.cfg, f.cfg != "")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "darb:", err)
		return ExitUsage
	}
	in := inputs(f, cfg)
	if f.aws.live {
		if in.AWSLive, err = f.aws.options(ctx, env); err != nil {
			_, _ = fmt.Fprintln(stderr, "darb:", err)
			return ExitUsage
		}
	}
	if in.K8sLive, err = f.k8s.clusters(ctx, env, &f.aws, stderr); err != nil {
		_, _ = fmt.Fprintln(stderr, "darb:", err)
		return ExitUsage
	}
	l, err := app.Load(ctx, in)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "darb:", err)
		if errors.Is(err, config.ErrInvalid) {
			return ExitUsage
		}
		return ExitIncomplete
	}
	a, err := app.Analyze(l, cfg, f.failOn)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "darb:", err)
		return ExitInternal
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
