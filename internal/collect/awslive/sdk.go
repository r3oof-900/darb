package awslive

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// LoadConfig loads the shared AWS configuration: the SDK's default chain
// (environment, shared config and credentials files, SSO, IMDS), with
// profile selecting a profile when set. Credentials are read by the SDK
// and never by darb, and are never logged. Retries use the SDK's
// adaptive mode, which also rate-limits the client after throttling.
func LoadConfig(ctx context.Context, profile, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRetryer(func() aws.Retryer { return retry.NewAdaptiveMode() }),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("%s: loading the AWS configuration: %w", Name, err)
	}
	return cfg, nil
}

// NewFactory makes SDK clients from cfg; a target with a role is reached
// with sts:AssumeRole (credentials cached and refreshed by the SDK).
// s3opts apply to every S3 client (the LocalStack test uses path-style
// addressing).
func NewFactory(cfg *aws.Config, s3opts ...func(*s3.Options)) Factory {
	return &sdkFactory{base: cfg.Copy(), s3opts: s3opts, creds: map[Target]aws.CredentialsProvider{}}
}

type sdkFactory struct {
	base   aws.Config
	s3opts []func(*s3.Options)
	mu     sync.Mutex
	creds  map[Target]aws.CredentialsProvider
}

func (f *sdkFactory) Clients(t Target, region string) *Clients {
	cfg := f.base.Copy()
	if region != "" {
		cfg.Region = region
	}
	if t.RoleARN != "" {
		cfg.Credentials = f.assumed(t)
	}
	return &Clients{
		STS: sts.NewFromConfig(cfg), IAM: iam.NewFromConfig(cfg), S3: s3.NewFromConfig(cfg, f.s3opts...), Control: s3control.NewFromConfig(cfg),
		KMS: kms.NewFromConfig(cfg), EKS: eks.NewFromConfig(cfg),
		Secrets: secretsmanager.NewFromConfig(cfg), SSM: ssm.NewFromConfig(cfg),
	}
}

func (f *sdkFactory) assumed(t Target) aws.CredentialsProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.creds[t]; ok {
		return p
	}
	p := aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(f.base), t.RoleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "darb-read-only"
		if t.ExternalID != "" {
			o.ExternalID = aws.String(t.ExternalID)
		}
	}))
	f.creds[t] = p
	return p
}
