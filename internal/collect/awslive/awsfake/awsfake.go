// Package awsfake is an in-memory AWS account for tests of the live
// collector and of the commands that use it. It never opens a connection.
package awsfake

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3ctypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/r3oof-900/darb/internal/collect/awslive"
)

// fake is the account in one region.
type fake struct {
	region string
	fail   map[string]error
	hang   map[string]bool
	mu     *sync.Mutex
	calls  *[]string
}

// Denied is an API error with code, as the SDK returns it.
func Denied(code string) error { return &smithy.GenericAPIError{Code: code, Message: "not authorized"} }

func (f *fake) do(ctx context.Context, api, target string) error {
	f.mu.Lock()
	*f.calls = append(*f.calls, strings.TrimSpace(f.region+" "+api+" "+target))
	f.mu.Unlock()
	if f.hang[api] || f.hang[api+" "+target] {
		<-ctx.Done()
		return ctx.Err()
	}
	if err, ok := f.fail[api+" "+target]; ok {
		return err
	}
	return f.fail[api]
}

// Factory is one account (111122223333) in every region. Fail maps "API"
// or "API target" to the error that call returns; Hang makes a call wait
// for its context (a timeout). Every call is recorded.
type Factory struct {
	Fail  map[string]error
	Hang  map[string]bool
	mu    sync.Mutex
	calls []string
}

// Clients implements awslive.Factory.
func (ff *Factory) Clients(_ awslive.Target, region string) *awslive.Clients {
	f := &fake{region: region, fail: ff.Fail, hang: ff.Hang, mu: &ff.mu, calls: &ff.calls}
	return &awslive.Clients{STS: f, IAM: f, S3: f, Control: control{f}, KMS: f, EKS: f, Secrets: f, SSM: f}
}

// Calls returns every call made, sorted ("region API target").
func (ff *Factory) Calls() []string {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	out := append([]string(nil), ff.calls...)
	sort.Strings(out)
	return out
}

func (f *fake) GetCallerIdentity(ctx context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if err := f.do(ctx, "GetCallerIdentity", ""); err != nil {
		return nil, err
	}
	return &sts.GetCallerIdentityOutput{Account: aws.String("111122223333"), Arn: aws.String("arn:aws:sts::111122223333:assumed-role/audit/darb")}, nil
}

// Two pages: the first has the role, the second the managed policy.
func (f *fake) GetAccountAuthorizationDetails(ctx context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	if err := f.do(ctx, "GetAccountAuthorizationDetails", aws.ToString(in.Marker)); err != nil {
		return nil, err
	}
	if in.Marker == nil {
		return &iam.GetAccountAuthorizationDetailsOutput{IsTruncated: true, Marker: aws.String("p2"), RoleDetailList: []iamtypes.RoleDetail{{
			RoleName: aws.String("app"), Arn: aws.String("arn:aws:iam::111122223333:role/app"),
			AssumeRolePolicyDocument: aws.String("%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D"),
			AttachedManagedPolicies:  []iamtypes.AttachedPolicy{{PolicyName: aws.String("ReadOnlyAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")}},
		}}}, nil
	}
	return &iam.GetAccountAuthorizationDetailsOutput{Policies: []iamtypes.ManagedPolicyDetail{{
		PolicyName: aws.String("custom"), Arn: aws.String("arn:aws:iam::111122223333:policy/custom"), DefaultVersionId: aws.String("v1"),
	}}}, nil
}

func (f *fake) ListBuckets(ctx context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if err := f.do(ctx, "ListBuckets", ""); err != nil {
		return nil, err
	}
	return &s3.ListBucketsOutput{Buckets: []s3types.Bucket{
		{Name: aws.String("pii"), BucketRegion: aws.String("eu-west-1")},
		{Name: aws.String("logs")}, // no BucketRegion: GetBucketLocation
	}}, nil
}

func (f *fake) GetBucketLocation(ctx context.Context, in *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	if err := f.do(ctx, "GetBucketLocation", *in.Bucket); err != nil {
		return nil, err
	}
	return &s3.GetBucketLocationOutput{}, nil // us-east-1
}

func (f *fake) GetBucketPolicy(ctx context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if err := f.do(ctx, "GetBucketPolicy", *in.Bucket); err != nil {
		return nil, err
	}
	if *in.Bucket == "logs" {
		return nil, &smithy.GenericAPIError{Code: "NoSuchBucketPolicy", Message: "The bucket policy does not exist"}
	}
	return &s3.GetBucketPolicyOutput{Policy: aws.String(`{"Version":"2012-10-17","Statement":[]}`)}, nil
}

func (f *fake) GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if err := f.do(ctx, "GetBucketEncryption", *in.Bucket); err != nil {
		return nil, err
	}
	return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{
		ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms, KMSMasterKeyID: aws.String("k1")},
		BucketKeyEnabled:                   aws.Bool(true),
	}}}}, nil
}

func (f *fake) GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if err := f.do(ctx, "GetPublicAccessBlock", *in.Bucket); err != nil {
		return nil, err
	}
	if *in.Bucket == "logs" {
		return nil, &smithy.GenericAPIError{Code: "NoSuchPublicAccessBlockConfiguration"}
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{RestrictPublicBuckets: aws.Bool(true), BlockPublicPolicy: aws.Bool(true)}}, nil
}

func (f *fake) GetBucketTagging(ctx context.Context, in *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	if err := f.do(ctx, "GetBucketTagging", *in.Bucket); err != nil {
		return nil, err
	}
	if *in.Bucket == "logs" {
		return nil, &smithy.GenericAPIError{Code: "NoSuchTagSet"}
	}
	return &s3.GetBucketTaggingOutput{TagSet: []s3types.Tag{{Key: aws.String("data-classification"), Value: aws.String("pii")}}}, nil
}

// Keys: k1 (customer managed) on page 1, aws1 (AWS managed) on page 2.
func (f *fake) ListKeys(ctx context.Context, in *kms.ListKeysInput, _ ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if err := f.do(ctx, "ListKeys", aws.ToString(in.Marker)); err != nil {
		return nil, err
	}
	if in.Marker == nil {
		return &kms.ListKeysOutput{Truncated: true, NextMarker: aws.String("m2"), Keys: []kmstypes.KeyListEntry{{KeyId: aws.String("k1")}}}, nil
	}
	return &kms.ListKeysOutput{Keys: []kmstypes.KeyListEntry{{KeyId: aws.String("aws1")}}}, nil
}

func (f *fake) arn(service, res string) string {
	return "arn:aws:" + service + ":" + f.region + ":111122223333:" + res
}

func (f *fake) ListAliases(ctx context.Context, _ *kms.ListAliasesInput, _ ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	if err := f.do(ctx, "ListAliases", ""); err != nil {
		return nil, err
	}
	return &kms.ListAliasesOutput{Aliases: []kmstypes.AliasListEntry{
		{AliasName: aws.String("alias/aws/ssm"), AliasArn: aws.String(f.arn("kms", "alias/aws/ssm")), TargetKeyId: aws.String("aws1")},
		{AliasName: aws.String("alias/aws/secretsmanager")}, // not created yet: no target
	}}, nil
}

func (f *fake) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if err := f.do(ctx, "DescribeKey", *in.KeyId); err != nil {
		return nil, err
	}
	mgr := kmstypes.KeyManagerTypeCustomer
	if strings.HasPrefix(*in.KeyId, "aws") {
		mgr = kmstypes.KeyManagerTypeAws
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
		KeyId: in.KeyId, Arn: aws.String(f.arn("kms", "key/"+*in.KeyId)), KeyManager: mgr, KeyState: kmstypes.KeyStateEnabled,
	}}, nil
}

func (f *fake) GetKeyPolicy(ctx context.Context, in *kms.GetKeyPolicyInput, _ ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	if err := f.do(ctx, "GetKeyPolicy", *in.KeyId); err != nil {
		return nil, err
	}
	return &kms.GetKeyPolicyOutput{Policy: aws.String(`{"Version":"2012-10-17","Statement":[]}`)}, nil
}

func (f *fake) GetKeyRotationStatus(ctx context.Context, in *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	if err := f.do(ctx, "GetKeyRotationStatus", *in.KeyId); err != nil {
		return nil, err
	}
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: true}, nil
}

func (f *fake) ListResourceTags(ctx context.Context, in *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	if err := f.do(ctx, "ListResourceTags", *in.KeyId); err != nil {
		return nil, err
	}
	return &kms.ListResourceTagsOutput{Tags: []kmstypes.Tag{{TagKey: aws.String("team"), TagValue: aws.String("payments")}}}, nil
}

func (f *fake) ListClusters(ctx context.Context, _ *eks.ListClustersInput, _ ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	if err := f.do(ctx, "ListClusters", ""); err != nil {
		return nil, err
	}
	return &eks.ListClustersOutput{Clusters: []string{"prod"}}, nil
}

func (f *fake) DescribeCluster(ctx context.Context, in *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	if err := f.do(ctx, "DescribeCluster", *in.Name); err != nil {
		return nil, err
	}
	return &eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{
		Name: in.Name, Arn: aws.String(f.arn("eks", "cluster/"+*in.Name)),
		Identity: &ekstypes.Identity{Oidc: &ekstypes.OIDC{Issuer: aws.String("https://oidc.eks." + f.region + ".amazonaws.com/id/ABC")}},
	}}, nil
}

func (f *fake) ListPodIdentityAssociations(ctx context.Context, in *eks.ListPodIdentityAssociationsInput, _ ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	if err := f.do(ctx, "ListPodIdentityAssociations", *in.ClusterName); err != nil {
		return nil, err
	}
	return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{{AssociationId: aws.String("a-1")}}}, nil
}

func (f *fake) DescribePodIdentityAssociation(ctx context.Context, in *eks.DescribePodIdentityAssociationInput, _ ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	if err := f.do(ctx, "DescribePodIdentityAssociation", *in.ClusterName+"/"+*in.AssociationId); err != nil {
		return nil, err
	}
	return &eks.DescribePodIdentityAssociationOutput{Association: &ekstypes.PodIdentityAssociation{
		ClusterName: in.ClusterName, Namespace: aws.String("payments"), ServiceAccount: aws.String("api"),
		RoleArn: aws.String("arn:aws:iam::111122223333:role/app"), AssociationArn: aws.String(f.arn("eks", "podidentityassociation/prod/"+*in.AssociationId)),
	}}, nil
}

func (f *fake) ListSecrets(ctx context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if err := f.do(ctx, "ListSecrets", ""); err != nil {
		return nil, err
	}
	return &secretsmanager.ListSecretsOutput{SecretList: []smtypes.SecretListEntry{
		{
			ARN: aws.String(f.arn("secretsmanager", "secret:db/password-a1b2c3")), Name: aws.String("db/password"), KmsKeyId: aws.String("k1"),
			Tags: []smtypes.Tag{{Key: aws.String("data-classification"), Value: aws.String("credentials")}},
		},
		{ARN: aws.String(f.arn("secretsmanager", "secret:plain-fake")), Name: aws.String("plain")}, // aws/secretsmanager
	}}, nil
}

func (f *fake) GetResourcePolicy(ctx context.Context, in *secretsmanager.GetResourcePolicyInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	if err := f.do(ctx, "GetResourcePolicy", *in.SecretId); err != nil {
		return nil, err
	}
	if strings.Contains(*in.SecretId, "plain") {
		return &secretsmanager.GetResourcePolicyOutput{}, nil // no policy
	}
	return &secretsmanager.GetResourcePolicyOutput{ResourcePolicy: aws.String(`{"Version":"2012-10-17","Statement":[]}`)}, nil
}

func (f *fake) DescribeParameters(ctx context.Context, _ *ssm.DescribeParametersInput, _ ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	if err := f.do(ctx, "DescribeParameters", ""); err != nil {
		return nil, err
	}
	return &ssm.DescribeParametersOutput{Parameters: []ssmtypes.ParameterMetadata{
		{Name: aws.String("/app/db"), ARN: aws.String(f.arn("ssm", "parameter/app/db")), Type: ssmtypes.ParameterTypeSecureString, KeyId: aws.String("alias/aws/ssm"), Tier: ssmtypes.ParameterTierAdvanced},
		{Name: aws.String("/app/url"), ARN: aws.String(f.arn("ssm", "parameter/app/url")), Type: ssmtypes.ParameterTypeString, Tier: ssmtypes.ParameterTierStandard},
	}}, nil
}

func (f *fake) ListTagsForResource(ctx context.Context, in *ssm.ListTagsForResourceInput, _ ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error) {
	if err := f.do(ctx, "ListTagsForResource", *in.ResourceId); err != nil {
		return nil, err
	}
	return &ssm.ListTagsForResourceOutput{}, nil
}

func (f *fake) GetResourcePolicies(ctx context.Context, in *ssm.GetResourcePoliciesInput, _ ...func(*ssm.Options)) (*ssm.GetResourcePoliciesOutput, error) {
	if err := f.do(ctx, "GetResourcePolicies", *in.ResourceArn); err != nil {
		return nil, err
	}
	return &ssm.GetResourcePoliciesOutput{Policies: []ssmtypes.GetResourcePoliciesResponseEntry{{Policy: aws.String(`{"Version":"2012-10-17","Statement":[]}`)}}}, nil
}

// control is the account's s3control endpoint: RestrictPublicBuckets off,
// BlockPublicPolicy on (so the buckets' own settings decide).
type control struct{ f *fake }

func (c control) GetPublicAccessBlock(ctx context.Context, in *s3control.GetPublicAccessBlockInput, _ ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	if err := c.f.do(ctx, "GetAccountPublicAccessBlock", aws.ToString(in.AccountId)); err != nil {
		return nil, err
	}
	return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3ctypes.PublicAccessBlockConfiguration{
		RestrictPublicBuckets: aws.Bool(false), BlockPublicPolicy: aws.Bool(true),
	}}, nil
}
