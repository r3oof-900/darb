package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/collect/awslive"
	"github.com/r3oof-900/darb/internal/collect/awsraw"
	"github.com/r3oof-900/darb/internal/collect/awssnapshot"
	"github.com/r3oof-900/darb/internal/coverage"
	"github.com/r3oof-900/darb/internal/managedpolicies"
	"github.com/r3oof-900/darb/pkg/schema"
)

// AWSLive configures a live AWS collection (scan --live-aws, collect-snapshot).
type AWSLive = awslive.Options

// AWSTarget is one account to collect (the caller's own, or one reached
// with sts:AssumeRole).
type AWSTarget = awslive.Target

// AWSConnector makes the clients of a live collection and returns the
// regions to collect: the given ones, or the configuration's region. The
// CLI uses ConnectAWS; tests pass a fake, so no test reaches AWS.
type AWSConnector func(ctx context.Context, profile string, regions []string) (awslive.Factory, []string, error)

// ErrNoRegion is returned when neither --aws-region nor the AWS
// configuration names a region.
var ErrNoRegion = errors.New("no AWS region: pass --aws-region or set a region in the AWS configuration")

// ConnectAWS loads the shared AWS configuration (the SDK reads the
// credentials; darb never does) and makes SDK clients.
func ConnectAWS(ctx context.Context, profile string, regions []string) (awslive.Factory, []string, error) {
	first := ""
	if len(regions) > 0 {
		first = regions[0]
	}
	cfg, err := awslive.LoadConfig(ctx, profile, first)
	if err != nil {
		return nil, nil, err
	}
	if len(regions) == 0 && cfg.Region != "" {
		regions = []string{cfg.Region}
	}
	if len(regions) == 0 {
		return nil, nil, ErrNoRegion
	}
	return awslive.NewFactory(&cfg), regions, nil
}

// SnapshotResult summarises a collect-snapshot run.
type SnapshotResult struct {
	Accounts []string
	Calls    int
	Failed   []coverage.Gap
}

// CollectSnapshot collects live (read-only) and writes the bundle to dir,
// a new directory. Failed calls are recorded in its manifest and returned.
func CollectSnapshot(ctx context.Context, opts *AWSLive, dir string) (*SnapshotResult, error) {
	rec := &coverage.Recorder{}
	snap, err := awslive.Collect(ctx, opts, rec)
	if err != nil {
		return &SnapshotResult{Failed: rec.Gaps()}, err
	}
	if err := awssnapshot.Write(dir, snap); err != nil {
		return nil, err
	}
	res := &SnapshotResult{Failed: rec.Gaps()}
	for _, a := range snap.Accounts {
		res.Accounts = append(res.Accounts, a.ID)
		res.Calls += len(a.Calls)
	}
	return res, nil
}

// Note kinds the console prints as warnings (pkg/schema).
const (
	NoteManagedPolicies = schema.NoteManagedPolicies
	NoteServiceCoverage = schema.NoteServiceCoverage
)

// awsNotes: what a live or snapshot scan of AWS could not decide, as notes
// with counts, so that no UNKNOWN is left without a visible reason.
func awsNotes(snap *awsraw.Snapshot, mp *managedpolicies.Snapshot) []access.Note {
	var notes []access.Note
	if missing := missingManagedPolicies(snap, mp); len(missing) > 0 {
		notes = append(notes, access.Note{
			Kind: NoteManagedPolicies, Subject: fmt.Sprintf("%d AWS managed policies", len(missing)),
			Detail: fmt.Sprintf("managed policy snapshot is incomplete: run tools/refresh-managed-policies. "+
				"%d AWS managed policies attached in the scanned accounts are not in the snapshot (%s, %d policies), "+
				"so what they grant is unknown: %s", len(missing), mp.SnapshotDate, len(mp.Policies), strings.Join(missing, ", ")),
		})
	}
	for _, a := range snap.Accounts {
		for _, c := range awsraw.ServiceCoverage(a.Calls) {
			if c.Full() {
				continue
			}
			notes = append(notes, access.Note{Kind: NoteServiceCoverage, Subject: strings.TrimSpace(a.ID + " " + c.Service + " " + c.Region), Detail: c.String()})
		}
	}
	for _, a := range snap.Accounts {
		// Collected since Phase 7; a snapshot written before has no file
		// for it and no failed call.
		if a.PublicAccessBlock == nil && !a.PublicAccessBlockFailed {
			notes = append(notes, access.Note{
				Kind: "not-modelled", Subject: a.ID + " S3 account-level Block Public Access",
				Detail: "not in the input (s3:GetAccountPublicAccessBlock; a snapshot from before Phase 7): a bucket without its own setting is treated as not blocked, which can report a path the account setting blocks, never hide one",
			})
		}
	}
	return notes
}

// missingManagedPolicies lists the AWS managed policies attached to a role
// or set as a permissions boundary that the vendored snapshot lacks.
func missingManagedPolicies(snap *awsraw.Snapshot, mp *managedpolicies.Snapshot) []string {
	var out []string
	add := func(arn string) {
		if _, ok := mp.Lookup(arn); !ok && managedpolicies.IsAWSManaged(arn) && !slices.Contains(out, arn) {
			out = append(out, arn)
		}
	}
	for _, a := range snap.Accounts {
		if a.Auth == nil {
			continue
		}
		for i := range a.Auth.RoleDetailList {
			r := &a.Auth.RoleDetailList[i]
			for _, p := range r.AttachedManagedPolicies {
				add(p.PolicyArn)
			}
			if r.PermissionsBoundary != nil {
				add(r.PermissionsBoundary.PermissionsBoundaryArn)
			}
		}
	}
	slices.Sort(out)
	for i, arn := range out {
		out[i] = arn[strings.LastIndex(arn, "/")+1:]
	}
	return out
}
