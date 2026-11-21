package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/r3oof-900/clapa/internal/app"
)

// Env holds what the commands connect to. Run uses the real AWS SDK; tests
// pass fakes, so no test reaches a cloud API.
type Env struct {
	AWS app.AWSConnector
	K8s app.K8sConnector
}

// DefaultEnv connects to AWS with the SDK's default configuration chain,
// and to clusters through kubeconfig contexts or EKS tokens.
func DefaultEnv() *Env {
	return &Env{AWS: app.ConnectAWS, K8s: app.K8sConnector{Kubeconfig: app.ConnectKubeconfig, EKS: app.ConnectEKS}}
}

// awsFlags are the live AWS flags of scan and collect-snapshot.
type awsFlags struct {
	live        bool
	profile     string
	regions     list
	roles       list
	externalID  string
	concurrency int
	timeout     time.Duration
}

func (a *awsFlags) on(fs *flag.FlagSet, withLive bool) {
	if withLive {
		fs.BoolVar(&a.live, "live-aws", false, "collect AWS live, read-only (docs/PERMISSIONS.md)")
	}
	fs.StringVar(&a.profile, "aws-profile", "", "AWS shared configuration profile (the SDK reads its credentials)")
	fs.Var(&a.regions, "aws-region", "region of the regional services (repeatable; default: the profile's region)")
	fs.Var(&a.roles, "aws-assume-role", "collect the account of this role, assumed with sts:AssumeRole (repeatable)")
	fs.StringVar(&a.externalID, "aws-external-id", "", "external ID for --aws-assume-role")
	fs.IntVar(&a.concurrency, "aws-concurrency", 4, "calls in flight per service and region")
	fs.DurationVar(&a.timeout, "aws-call-timeout", 30*time.Second, "timeout of each AWS API call")
}

// options connects and returns the collection options.
func (a *awsFlags) options(ctx context.Context, env *Env) (*app.AWSLive, error) {
	if a.concurrency < 1 || a.timeout <= 0 {
		return nil, fmt.Errorf("%w: --aws-concurrency must be at least 1 and --aws-call-timeout positive", errUsage)
	}
	factory, regions, err := env.AWS(ctx, a.profile, a.regions)
	if err != nil {
		return nil, err
	}
	o := &app.AWSLive{Factory: factory, Regions: regions, Concurrency: a.concurrency, CallTimeout: a.timeout}
	for _, r := range a.roles {
		o.Targets = append(o.Targets, app.AWSTarget{RoleARN: r, ExternalID: a.externalID})
	}
	return o, nil
}

var errUsage = errors.New("usage")

// collectSnapshot: `clapa collect-snapshot --out DIR [AWS flags]` collects
// live, read-only, and writes a clapa-snapshot/v1 bundle to DIR (a new
// directory), which `scan --aws-snapshot DIR` reads offline.
//
// Exit codes: 0 every call succeeded; 3 the bundle was written but some
// calls failed (recorded in its manifest), or nothing was collected (no
// bundle); 2 usage or configuration error.
func collectSnapshot(ctx context.Context, args []string, stdout, stderr io.Writer, env *Env) ExitCode {
	var out string
	a := &awsFlags{}
	fs := flag.NewFlagSet("collect-snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&out, "out", "", "directory to create for the bundle (must not exist)")
	a.on(fs, false)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || out == "" {
		_, _ = fmt.Fprintln(stderr, "usage: clapa collect-snapshot --out DIR [--aws-profile P] [--aws-region R]... [--aws-assume-role ARN]...")
		return ExitUsage
	}
	if _, err := os.Lstat(out); err == nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", out, "exists; collect-snapshot writes a new directory")
		return ExitUsage
	}
	opts, err := a.options(ctx, env)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		return ExitUsage
	}
	res, err := app.CollectSnapshot(ctx, opts, out)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "clapa:", err)
		printFailed(stderr, res)
		return ExitIncomplete
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s: %d account(s) (%s), %d API calls, %d failed\n",
		out, len(res.Accounts), strings.Join(res.Accounts, ", "), res.Calls, len(res.Failed))
	printFailed(stdout, res)
	if len(res.Failed) > 0 {
		return ExitIncomplete
	}
	return ExitOK
}

func printFailed(w io.Writer, res *app.SnapshotResult) {
	if res == nil {
		return
	}
	for i := range res.Failed {
		g := &res.Failed[i]
		_, _ = fmt.Fprintf(w, "  %s %s %s:%s %s: %s\n", g.Kind, g.Account, g.Service, g.API, g.Address, g.Detail)
	}
}
