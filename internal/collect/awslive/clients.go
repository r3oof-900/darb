package awslive

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// The API subsets CLAPA calls. They are read-only by construction: no
// interface here has a method that changes anything, and none reads a
// secret or parameter value (no GetSecretValue, no GetParameter*; see
// read_only_test.go). docs/PERMISSIONS.md lists the same actions.

// STSAPI identifies the caller.
type STSAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// IAMAPI reads the account authorization details.
type IAMAPI interface {
	iam.GetAccountAuthorizationDetailsAPIClient
}

// S3API reads bucket configuration (never objects).
type S3API interface {
	s3.ListBucketsAPIClient
	GetBucketLocation(ctx context.Context, in *s3.GetBucketLocationInput, opts ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetBucketPolicy(ctx context.Context, in *s3.GetBucketPolicyInput, opts ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, opts ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketTagging(ctx context.Context, in *s3.GetBucketTaggingInput, opts ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
}

// KMSAPI reads keys, their policies, rotation, tags and aliases.
type KMSAPI interface {
	kms.ListKeysAPIClient
	kms.ListAliasesAPIClient
	kms.ListResourceTagsAPIClient
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyPolicy(ctx context.Context, in *kms.GetKeyPolicyInput, opts ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error)
	GetKeyRotationStatus(ctx context.Context, in *kms.GetKeyRotationStatusInput, opts ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// EKSAPI reads clusters and Pod Identity associations.
type EKSAPI interface {
	eks.ListClustersAPIClient
	eks.ListPodIdentityAssociationsAPIClient
	DescribeCluster(ctx context.Context, in *eks.DescribeClusterInput, opts ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	DescribePodIdentityAssociation(ctx context.Context, in *eks.DescribePodIdentityAssociationInput, opts ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error)
}

// SecretsAPI lists secrets' metadata and resource policies, never values.
type SecretsAPI interface {
	secretsmanager.ListSecretsAPIClient
	GetResourcePolicy(ctx context.Context, in *secretsmanager.GetResourcePolicyInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
}

// SSMAPI describes parameters (metadata only, never values), their tags
// and resource policies.
type SSMAPI interface {
	ssm.DescribeParametersAPIClient
	ssm.GetResourcePoliciesAPIClient
	ListTagsForResource(ctx context.Context, in *ssm.ListTagsForResourceInput, opts ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error)
}

// Clients are the clients of one account in one region.
type Clients struct {
	STS     STSAPI
	IAM     IAMAPI
	S3      S3API
	KMS     KMSAPI
	EKS     EKSAPI
	Secrets SecretsAPI
	SSM     SSMAPI
}

// Factory makes the clients of an account (Target) in a region. The SDK
// factory (NewFactory) assumes the target's role; tests use fakes.
type Factory interface {
	Clients(t Target, region string) *Clients
}

// Target is one account to collect: the caller's own (RoleARN "") or one
// reached with sts:AssumeRole.
type Target struct {
	RoleARN    string
	ExternalID string
}
