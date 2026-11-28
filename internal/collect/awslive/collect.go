package awslive

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"golang.org/x/sync/errgroup"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
	"github.com/r3oof-900/darb/internal/coverage"
)

// Name identifies this collector in coverage gaps.
const Name = "aws-live"

// Options configure a live collection.
type Options struct {
	Factory Factory
	// Targets are the accounts to collect; empty means the caller's own.
	Targets []Target
	// Regions are the regional services' regions (KMS, EKS, Secrets
	// Manager, SSM). At least one is required; S3 and IAM are global.
	Regions []string
	// Concurrency bounds the calls in flight per service and region
	// (errgroup.SetLimit); default 4.
	Concurrency int
	// CallTimeout bounds every API call (each page of a list); default 30s.
	CallTimeout time.Duration
	// ReportWait bounds the wait for IAM to prepare the credential report
	// (GenerateCredentialReport is asynchronous); default 60s. Sleep waits
	// between polls (nil: a timer); tests replace it.
	ReportWait time.Duration
	Sleep      func(ctx context.Context, d time.Duration) error
}

// ErrNoRegion is returned when no region is given.
var ErrNoRegion = errors.New(Name + ": at least one region is required")

// ErrNothingCollected is returned when not one account could be identified:
// nothing was scanned, which is exit code 3, never a clean result.
var ErrNothingCollected = errors.New(Name + ": no account could be collected")

// Collect reads every target account, read-only. A call that fails (access
// denied, throttled after retries, timed out) is recorded with its outcome
// and is a coverage gap; it never stops the collection. Only the caller
// cancelling ctx does.
func Collect(ctx context.Context, opts *Options, rec *coverage.Recorder) (*awsraw.Snapshot, error) {
	if len(opts.Regions) == 0 {
		return nil, ErrNoRegion
	}
	o := *opts
	o.Concurrency = cmp.Or(o.Concurrency, 4)
	o.CallTimeout = cmp.Or(o.CallTimeout, 30*time.Second)
	o.ReportWait = cmp.Or(o.ReportWait, 60*time.Second)
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	targets := o.Targets
	if len(targets) == 0 {
		targets = []Target{{}}
	}
	snap := &awsraw.Snapshot{}
	for _, t := range targets {
		a, err := collectAccount(ctx, &o, t)
		if err != nil {
			return nil, err
		}
		for i := range a.acct.Calls {
			if g := a.acct.Calls[i].Gap(Name, a.acct.ID); g != nil {
				rec.Add(g)
			}
		}
		if a.acct.ID == "" {
			continue // the account was never identified; its calls are gaps
		}
		snap.Accounts = append(snap.Accounts, a.acct)
	}
	if len(snap.Accounts) == 0 {
		return nil, ErrNothingCollected
	}
	return snap, nil
}

// account is one account being collected; mu guards acct.
type account struct {
	o      *Options
	target Target
	mu     sync.Mutex
	acct   *awsraw.Account
}

func collectAccount(ctx context.Context, o *Options, t Target) (*account, error) {
	a := &account{o: o, target: t, acct: &awsraw.Account{}}
	home := o.Regions[0]
	c := o.Factory.Clients(t, home)
	var id *sts.GetCallerIdentityOutput
	err := a.call(ctx, "sts", "", "GetCallerIdentity", roleTarget(t), func(ctx context.Context) error {
		var err error
		id, err = c.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		return err
	})
	if done(err) {
		return nil, err
	}
	if id == nil || id.Account == nil {
		return a, nil // not identified: its one call is recorded, as a gap
	}
	a.acct.ID = *id.Account
	a.acct.Partition = partitionOf(deref(id.Arn))
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return a.iam(gctx, c) })
	g.Go(func() error { return a.s3(gctx, c) })
	for _, r := range o.Regions {
		rc := o.Factory.Clients(t, r)
		g.Go(func() error { return a.kms(gctx, rc, r) })
		g.Go(func() error { return a.eks(gctx, rc, r) })
		g.Go(func() error { return a.secrets(gctx, rc, r) })
		g.Go(func() error { return a.ssm(gctx, rc, r) })
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	a.sort()
	return a, nil
}

func roleTarget(t Target) string { return t.RoleARN }

// partitionOf reads the partition from the caller's ARN ("arn:aws-cn:...").
func partitionOf(callerARN string) string {
	parts := strings.SplitN(callerARN, ":", 3)
	if len(parts) < 2 || parts[1] == "" {
		return "aws"
	}
	return parts[1]
}

// call runs one API call (or one whole paginated listing) with the call
// timeout and records its outcome. It returns an error only when the
// caller's ctx is done: a failed call is a recorded outcome, not an error.
func (a *account) call(ctx context.Context, service, region, api, target string, fn func(context.Context) error) error {
	cctx, cancel := context.WithTimeout(ctx, a.o.CallTimeout)
	err := fn(cctx)
	cancel()
	if ctx.Err() != nil {
		return fmt.Errorf("%s: %w", Name, ctx.Err())
	}
	status, detail := classify(err)
	a.mu.Lock()
	a.acct.Calls = append(a.acct.Calls, awsraw.Call{Service: service, Region: region, API: api, Target: target, Status: status, Error: detail})
	a.mu.Unlock()
	if status != awsraw.StatusOK {
		return errFailed
	}
	return nil
}

// errFailed marks a call that failed and was recorded; callers skip the
// data it would have returned and go on.
var errFailed = errors.New("call failed (recorded)")

// done reports whether err must stop the caller: only cancellation does.
func done(err error) bool { return err != nil && !errors.Is(err, errFailed) }

// classify maps an SDK error to a call outcome. The SDK has already
// retried throttling and transient errors (adaptive mode).
func classify(err error) (status, detail string) {
	if err == nil {
		return awsraw.StatusOK, ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return awsraw.StatusTimeout, "the call did not complete within the call timeout"
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		detail = ae.ErrorCode() + ": " + ae.ErrorMessage()
		switch code := ae.ErrorCode(); {
		case slices.Contains(accessDeniedCodes(), code):
			return awsraw.StatusAccessDenied, detail
		case slices.Contains(throttlingCodes(), code):
			return awsraw.StatusThrottling, detail
		}
		return awsraw.StatusError, detail
	}
	return awsraw.StatusError, err.Error()
}

func accessDeniedCodes() []string {
	return []string{"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError", "UnauthorizedException", "AllAccessDisabled"}
}

func throttlingCodes() []string {
	return []string{
		"Throttling", "ThrottlingException", "ThrottledException", "RequestThrottled", "RequestThrottledException",
		"TooManyRequestsException", "RequestLimitExceeded", "SlowDown", "ProvisionedThroughputExceededException",
	}
}

// isCode reports whether err is an API error with one of codes (e.g. "no
// bucket policy", which is an answer, not a failure).
func isCode(err error, codes ...string) bool {
	var ae smithy.APIError
	return errors.As(err, &ae) && slices.Contains(codes, ae.ErrorCode())
}

// group runs fn for every item with the configured concurrency.
func group[T any](ctx context.Context, a *account, items []T, fn func(context.Context, T) error) error {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(a.o.Concurrency)
	for _, it := range items {
		g.Go(func() error {
			if err := fn(gctx, it); done(err) {
				return err
			}
			return nil
		})
	}
	return g.Wait()
}

func (a *account) sort() {
	acct := a.acct
	slices.SortFunc(acct.Calls, func(x, y awsraw.Call) int {
		return cmp.Or(strings.Compare(x.Service, y.Service), strings.Compare(x.Region, y.Region),
			strings.Compare(x.API, y.API), strings.Compare(x.Target, y.Target))
	})
	slices.SortFunc(acct.Keys, func(x, y *awsraw.Key) int {
		return cmp.Or(strings.Compare(x.Region, y.Region), strings.Compare(x.Metadata.KeyID, y.Metadata.KeyID))
	})
	slices.SortFunc(acct.Aliases, func(x, y awsraw.Alias) int {
		return cmp.Or(strings.Compare(x.Region, y.Region), strings.Compare(x.AliasName, y.AliasName))
	})
	slices.SortFunc(acct.Buckets, func(x, y *awsraw.Bucket) int { return strings.Compare(x.Name, y.Name) })
	slices.SortFunc(acct.Clusters, func(x, y *awsraw.Cluster) int {
		return cmp.Or(strings.Compare(x.Region, y.Region), strings.Compare(x.Name, y.Name))
	})
	for _, c := range acct.Clusters {
		slices.SortFunc(c.PodIdentity, func(x, y awsraw.PodIdentityAssociation) int {
			return strings.Compare(x.AssociationArn, y.AssociationArn)
		})
	}
	slices.SortFunc(acct.Secrets, func(x, y *awsraw.Secret) int { return strings.Compare(x.ARN, y.ARN) })
	slices.SortFunc(acct.Params, func(x, y *awsraw.Parameter) int { return strings.Compare(x.ARN, y.ARN) })
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
