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

// Two clusters with one name in two regions are two clusters: two keys
// (their ARNs), each association on its own cluster, and no gap.
func TestClustersWithTheSameName(t *testing.T) {
	const euw1, use1 = "arn:aws:eks:eu-west-1:111122223333:cluster/prod", "arn:aws:eks:us-east-1:111122223333:cluster/prod"
	inv, rec := build(t, &awsraw.Account{ID: "111122223333", Partition: "aws", Auth: &awsraw.AuthorizationDetails{}, Clusters: []*awsraw.Cluster{
		{Region: "eu-west-1", Name: "prod", Arn: euw1},
		{Region: "us-east-1", Name: "prod", Arn: use1, PodIdentity: []awsraw.PodIdentityAssociation{{ClusterName: "prod", Namespace: "a", ServiceAccount: "s"}}},
	}})
	if len(inv.Clusters) != 2 || inv.Clusters[0].Key() != euw1 || inv.Clusters[1].Key() != use1 {
		t.Fatalf("clusters %+v", inv.Clusters)
	}
	if len(inv.PodIdentity) != 1 || inv.PodIdentity[0].Cluster != use1 {
		t.Fatalf("pod identity %+v", inv.PodIdentity)
	}
	if rec.Len() != 0 {
		t.Fatalf("gaps %+v", rec.Gaps())
	}
}

// A secret's or parameter's KMS key reference resolves to the key's ARN;
// the service's AWS managed key is ""; an alias the snapshot does not
// resolve is unresolved (UNKNOWN), never the managed key.
func TestKeyReferences(t *testing.T) {
	n := &norm{acct: &awsraw.Account{ID: "111122223333", Partition: "aws", Aliases: []awsraw.Alias{
		{Region: "us-east-1", AliasName: "alias/app", TargetKeyID: "k-app"},
	}}, b: normalize.NewBuilder()}
	const p = "arn:aws:kms:us-east-1:111122223333:"
	for ref, want := range map[string]string{
		"": "", "alias/aws/ssm": "", p + "alias/aws/ssm": "",
		p + "key/k1": p + "key/k1", "k1": p + "key/k1", "alias/app": p + "key/k-app", p + "alias/app": p + "key/k-app",
	} {
		if got := n.keyARN("us-east-1", ref, "alias/aws/ssm"); got != want {
			t.Errorf("%q: %q", ref, got)
		}
	}
	if got := n.keyARN("us-east-1", "alias/missing", "alias/aws/ssm"); !model.ContainsUnresolved(got) {
		t.Errorf("an unknown alias: %q", got)
	}
}

// The account's Block Public Access becomes a record: its value when
// collected, unknown when the call failed, none when not collected.
func TestAccountBlock(t *testing.T) {
	for name, c := range map[string]struct {
		a    awsraw.Account
		want []model.Tri
	}{
		"on":            {awsraw.Account{PublicAccessBlock: &awsraw.PublicAccessBlock{RestrictPublicBuckets: true}}, []model.Tri{model.True}},
		"none":          {awsraw.Account{PublicAccessBlock: &awsraw.PublicAccessBlock{}}, []model.Tri{model.False}},
		"failed":        {awsraw.Account{PublicAccessBlockFailed: true}, []model.Tri{model.Unknown}},
		"not collected": {awsraw.Account{}, nil},
	} {
		c.a.ID, c.a.Partition, c.a.Auth = "111122223333", "aws", &awsraw.AuthorizationDetails{}
		inv, _ := build(t, &c.a)
		var got []model.Tri
		for _, b := range inv.AccountBlocks {
			got = append(got, b.RestrictPublicBuckets)
			if b.Account != "111122223333" {
				t.Errorf("%s: account %q", name, b.Account)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}
