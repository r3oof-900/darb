package aws

import (
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect/awsraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/managedpolicies"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
)

func build(t *testing.T, a *awsraw.Account) (*model.Inventory, *coverage.Recorder) {
	t.Helper()
	mp, err := managedpolicies.Load()
	if err != nil {
		t.Fatal(err)
	}
	rec := &coverage.Recorder{}
	b := normalize.NewBuilder()
	Normalize(&awsraw.Snapshot{Accounts: []*awsraw.Account{a}}, mp, b, rec)
	inv, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return inv, rec
}

// An AWS managed key rotates (documented default, no gap); a customer
// managed key whose rotation was not read is unknown and a gap.
func TestKeyRotationOfAWSManagedKeys(t *testing.T) {
	inv, rec := build(t, &awsraw.Account{ID: "111122223333", Partition: "aws", Auth: &awsraw.AuthorizationDetails{}, Keys: []*awsraw.Key{
		{Region: "eu-west-1", Metadata: awsraw.KeyMetadata{KeyID: "aws1", Arn: "arn:aws:kms:eu-west-1:111122223333:key/aws1", KeyManager: "AWS"}, Policy: "{\"Version\":\"2012-10-17\",\"Statement\":[]}"},
		{Region: "eu-west-1", Metadata: awsraw.KeyMetadata{KeyID: "k1", Arn: "arn:aws:kms:eu-west-1:111122223333:key/k1", KeyManager: "CUSTOMER"}, Policy: "{\"Version\":\"2012-10-17\",\"Statement\":[]}"},
	}})
	got := map[string]*model.Resource{}
	for _, r := range inv.Resources {
		got[r.ARN()] = r
	}
	aws1, k1 := got["arn:aws:kms:eu-west-1:111122223333:key/aws1"], got["arn:aws:kms:eu-west-1:111122223333:key/k1"]
	if aws1.KeyRotation() != model.True || !slices.Equal(aws1.Defaulted(), []string{model.DefaultAWSManagedKeyRot}) {
		t.Fatalf("aws1 rotation %v defaulted %v", aws1.KeyRotation(), aws1.Defaulted())
	}
	if k1.KeyRotation() != model.Unknown || rec.Count(coverage.KindUnresolved) != 1 {
		t.Fatalf("k1 rotation %v, gaps %+v", k1.KeyRotation(), rec.Gaps())
	}
}

// A bucket policy that could not be read is an unknown policy, never none.
func TestFailedBucketPolicyIsUnknown(t *testing.T) {
	inv, _ := build(t, &awsraw.Account{ID: "111122223333", Partition: "aws", Auth: &awsraw.AuthorizationDetails{}, Buckets: []*awsraw.Bucket{
		{Name: "denied", Region: "eu-west-1", PolicyFailed: true},
		{Name: "none", Region: "eu-west-1"},
	}})
	policies := map[string]string{}
	for _, p := range inv.Policies {
		policies[p.Doc.ID()] = summary(p.Doc)
	}
	// unknownDoc: an Allow and a Deny of an unresolved placeholder.
	if s, ok := policies["arn:aws:s3:::denied#bucket-policy"]; !ok || !strings.HasPrefix(s, "Allow ") || !strings.Contains(s, ";Deny ") {
		t.Fatalf("denied bucket: %v", policies)
	}
	if _, ok := policies["arn:aws:s3:::none#bucket-policy"]; ok {
		t.Fatalf("a bucket without a policy has none: %v", policies)
	}
}

// Two clusters with one name (two regions): the first is analysed, the
// second is a visible gap, never a failed scan or a silent merge.
func TestClustersWithTheSameName(t *testing.T) {
	inv, rec := build(t, &awsraw.Account{ID: "111122223333", Partition: "aws", Auth: &awsraw.AuthorizationDetails{}, Clusters: []*awsraw.Cluster{
		{Region: "eu-west-1", Name: "prod", Arn: "arn:aws:eks:eu-west-1:111122223333:cluster/prod"},
		{Region: "us-east-1", Name: "prod", Arn: "arn:aws:eks:us-east-1:111122223333:cluster/prod", PodIdentity: []awsraw.PodIdentityAssociation{{ClusterName: "prod"}}},
	}})
	if len(inv.Clusters) != 1 || inv.Clusters[0].ARN != "arn:aws:eks:eu-west-1:111122223333:cluster/prod" || len(inv.PodIdentity) != 0 {
		t.Fatalf("clusters %+v pod identity %d", inv.Clusters, len(inv.PodIdentity))
	}
	g := rec.Gaps()
	if len(g) != 1 || g[0].Kind != coverage.KindUnsupported || g[0].Address != "arn:aws:eks:us-east-1:111122223333:cluster/prod" || !strings.Contains(g[0].Detail, "1 Pod Identity associations are not analysed") {
		t.Fatalf("gaps %+v", g)
	}
}
