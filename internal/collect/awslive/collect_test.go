package awslive_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/r3oof-900/clapa/internal/collect/awslive"
	"github.com/r3oof-900/clapa/internal/collect/awslive/awsfake"
	"github.com/r3oof-900/clapa/internal/collect/awsraw"
	"github.com/r3oof-900/clapa/internal/coverage"
)

func run(t *testing.T, ff *awsfake.Factory, regions ...string) (*awsraw.Account, *coverage.Recorder) {
	t.Helper()
	rec := &coverage.Recorder{}
	snap, err := awslive.Collect(context.Background(), &awslive.Options{Factory: ff, Regions: regions, CallTimeout: 50 * time.Millisecond}, rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Accounts) != 1 {
		t.Fatalf("%d accounts", len(snap.Accounts))
	}
	return snap.Accounts[0], rec
}

func TestCollectEverything(t *testing.T) {
	ff := &awsfake.Factory{}
	a, rec := run(t, ff, "eu-west-1")
	if rec.Len() != 0 {
		t.Fatalf("gaps: %+v", rec.Gaps())
	}
	if a.ID != "111122223333" || a.Partition != "aws" {
		t.Fatalf("account %q partition %q", a.ID, a.Partition)
	}
	// IAM: both pages.
	if len(a.Auth.RoleDetailList) != 1 || len(a.Auth.Policies) != 1 || a.Auth.RoleDetailList[0].AttachedManagedPolicies[0].PolicyArn != "arn:aws:iam::aws:policy/ReadOnlyAccess" {
		t.Fatalf("auth %+v", a.Auth)
	}
	if string(a.Auth.RoleDetailList[0].AssumeRolePolicyDocument) != `"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D"` {
		t.Fatalf("trust kept URL-encoded for the normalizer: %s", a.Auth.RoleDetailList[0].AssumeRolePolicyDocument)
	}
	// S3: the bucket without a policy has none (an answer, not a failure);
	// no bucket-level Block Public Access is "all off".
	logs, pii := a.Buckets[0], a.Buckets[1]
	if logs.Name != "logs" || logs.Region != "us-east-1" || logs.Policy != "" || logs.PolicyFailed || *logs.PublicAccessBlock != (awsraw.PublicAccessBlock{}) || logs.Tags == nil {
		t.Fatalf("logs %+v", logs)
	}
	if pii.Region != "eu-west-1" || pii.Policy == "" || !pii.PublicAccessBlock.RestrictPublicBuckets || pii.Encryption.KMSMasterKeyID != "k1" || !*pii.Encryption.BucketKeyEnabled {
		t.Fatalf("pii %+v", pii)
	}
	// KMS: both pages; no rotation or tag calls for the AWS managed key.
	if len(a.Keys) != 2 || a.Keys[0].Metadata.KeyID != "aws1" || a.Keys[0].RotationEnabled != nil || a.Keys[0].Tags != nil {
		t.Fatalf("keys %+v", a.Keys[0])
	}
	if k1 := a.Keys[1]; k1.Metadata.KeyManager != "CUSTOMER" || !*k1.RotationEnabled || len(k1.Tags) != 1 || k1.Policy == "" {
		t.Fatalf("k1 %+v", k1)
	}
	if len(a.Aliases) != 2 || a.Aliases[1].TargetKeyID != "aws1" {
		t.Fatalf("aliases %+v", a.Aliases)
	}
	if c := a.Clusters[0]; c.Arn == "" || c.OIDCIssuer == "" || len(c.PodIdentity) != 1 || c.PodIdentity[0].ServiceAccount != "api" {
		t.Fatalf("cluster %+v", c)
	}
	if len(a.Secrets) != 2 || a.Secrets[0].Name != "db/password" || a.Secrets[0].KMSKeyID != "k1" || a.Secrets[0].Policy == "" || a.Secrets[1].Policy != "" {
		t.Fatalf("secrets %+v", a.Secrets)
	}
	// SSM: only the advanced parameter has its resource policies read.
	if len(a.Params) != 2 || a.Params[0].Type != "SecureString" || len(a.Params[0].Policies) != 1 || a.Params[1].Policies != nil {
		t.Fatalf("params %+v %+v", a.Params[0], a.Params[1])
	}
	calls := strings.Join(ff.Calls(), "\n")
	if strings.Contains(calls, "GetResourcePolicies arn:aws:ssm:eu-west-1:111122223333:parameter/app/url") || strings.Contains(calls, "GetKeyRotationStatus aws1") {
		t.Fatalf("unnecessary calls:\n%s", calls)
	}
	for _, c := range a.Calls {
		if c.Status != awsraw.StatusOK {
			t.Fatalf("call %+v", c)
		}
	}
}

// A denied detail call is recorded and is a gap; the item stays, with
// that part unknown. A denied list call leaves the service's items unknown.
func TestCollectRecordsFailures(t *testing.T) {
	ff := &awsfake.Factory{Fail: map[string]error{
		"GetKeyPolicy k1":     awsfake.Denied("AccessDeniedException"),
		"GetBucketPolicy pii": awsfake.Denied("AccessDenied"),
		"ListClusters":        awsfake.Denied("ThrottlingException"),
		"ListSecrets":         errors.New("connection reset"),
		"GetResourcePolicies arn:aws:ssm:eu-west-1:111122223333:parameter/app/db": awsfake.Denied("AccessDeniedException"),
	}}
	a, rec := run(t, ff, "eu-west-1")
	gaps := rec.Gaps()
	kinds := map[string]coverage.Kind{}
	for _, g := range gaps {
		if g.Source != awslive.Name || g.Account != "111122223333" {
			t.Fatalf("gap %+v", g)
		}
		kinds[g.API+" "+g.Address] = g.Kind
	}
	want := map[string]coverage.Kind{
		"GetKeyPolicy k1": coverage.KindAccessDenied, "GetBucketPolicy pii": coverage.KindAccessDenied,
		"ListClusters ": coverage.KindThrottled, "ListSecrets ": coverage.KindAPIError,
		"GetResourcePolicies arn:aws:ssm:eu-west-1:111122223333:parameter/app/db": coverage.KindAccessDenied,
	}
	if len(kinds) != len(want) {
		t.Fatalf("gaps %v", kinds)
	}
	for k, v := range want {
		if kinds[k] != v {
			t.Fatalf("%s: %q, want %q (all: %v)", k, kinds[k], v, kinds)
		}
	}
	if k1 := a.Keys[1]; k1.Policy != "" || k1.RotationEnabled == nil {
		t.Fatalf("k1: the policy is unknown, the rest is read: %+v", k1)
	}
	if !a.Buckets[1].PolicyFailed || a.Buckets[0].PolicyFailed {
		t.Fatal("PolicyFailed marks only the bucket whose policy could not be read")
	}
	if !a.Params[0].PolicyFailed || a.Clusters != nil || a.Secrets != nil {
		t.Fatalf("params %+v clusters %v secrets %v", a.Params[0], a.Clusters, a.Secrets)
	}
}

func TestCollectTimeout(t *testing.T) {
	ff := &awsfake.Factory{Hang: map[string]bool{"DescribeCluster": true}}
	a, rec := run(t, ff, "eu-west-1")
	if g := rec.Gaps(); len(g) != 1 || g[0].Kind != coverage.KindTimeout || g[0].API != "DescribeCluster" {
		t.Fatalf("gaps %+v", g)
	}
	if len(a.Clusters) != 1 || a.Clusters[0].PodIdentity == nil {
		t.Fatalf("the associations are still read: %+v", a.Clusters)
	}
}

func TestCollectSeveralRegions(t *testing.T) {
	ff := &awsfake.Factory{}
	a, _ := run(t, ff, "eu-west-1", "us-east-1")
	if len(a.Keys) != 4 || len(a.Clusters) != 2 || len(a.Secrets) != 4 || len(a.Buckets) != 2 {
		t.Fatalf("keys %d clusters %d secrets %d buckets %d", len(a.Keys), len(a.Clusters), len(a.Secrets), len(a.Buckets))
	}
	if !slices.IsSortedFunc(a.Calls, func(x, y awsraw.Call) int {
		return strings.Compare(x.Service+x.Region+x.API+x.Target, y.Service+y.Region+y.API+y.Target)
	}) {
		t.Fatal("calls are not sorted")
	}
	// Global services are called once, not per region.
	n := 0
	for _, c := range ff.Calls() {
		if strings.Contains(c, "ListBuckets") || strings.Contains(c, "GetAccountAuthorizationDetails ") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("global calls: %d", n)
	}
}

func TestCollectNothing(t *testing.T) {
	rec := &coverage.Recorder{}
	ff := &awsfake.Factory{Fail: map[string]error{"GetCallerIdentity": awsfake.Denied("AccessDenied")}}
	_, err := awslive.Collect(context.Background(), &awslive.Options{Factory: ff, Regions: []string{"eu-west-1"}}, rec)
	if !errors.Is(err, awslive.ErrNothingCollected) || rec.Count(coverage.KindAccessDenied) != 1 {
		t.Fatalf("err %v, gaps %+v", err, rec.Gaps())
	}
	if _, err := awslive.Collect(context.Background(), &awslive.Options{Factory: ff}, rec); !errors.Is(err, awslive.ErrNoRegion) {
		t.Fatalf("no region: %v", err)
	}
}

func TestCollectCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := awslive.Collect(ctx, &awslive.Options{Factory: &awsfake.Factory{}, Regions: []string{"eu-west-1"}}, &coverage.Recorder{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}
