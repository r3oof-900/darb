//go:build integration

package awslive

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
	"github.com/r3oof-900/darb/internal/coverage"
)

// The live collector against LocalStack (.github/workflows/integration.yml).
// The test refuses any endpoint that is not on this machine, so it cannot
// reach a real AWS account. The setup below writes to LocalStack; the
// collector itself only reads.
func TestIntegrationLocalStack(t *testing.T) {
	endpoint := os.Getenv("DARB_LOCALSTACK_ENDPOINT")
	if endpoint == "" {
		t.Skip("DARB_LOCALSTACK_ENDPOINT is not set")
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") {
		t.Fatalf("refusing endpoint %q: the integration test runs against a local LocalStack only", endpoint)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cfg := aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
	}
	pathStyle := func(o *s3.Options) { o.UsePathStyle = true }
	keyID := setUp(ctx, t, &cfg, pathStyle)

	rec := &coverage.Recorder{}
	snap, err := Collect(ctx, &Options{Factory: NewFactory(&cfg, pathStyle), Regions: []string{"us-east-1"}}, rec)
	if err != nil {
		t.Fatal(err)
	}
	a := snap.Accounts[0]
	for _, c := range a.Calls {
		t.Logf("%s %s %s %s: %s %s", c.Service, c.Region, c.API, c.Target, c.Status, c.Error)
	}
	if a.ID != "000000000000" {
		t.Errorf("account %q", a.ID)
	}
	role := false
	for _, r := range a.Auth.RoleDetailList {
		role = role || (r.RoleName == "darb-it-app" && len(r.RolePolicyList) == 1)
	}
	if !role {
		t.Errorf("role darb-it-app with its inline policy not collected: %+v", a.Auth.RoleDetailList)
	}
	var bucket *awsraw.Bucket
	for _, b := range a.Buckets {
		if b.Name == "darb-it-pii" {
			bucket = b
		}
	}
	if bucket == nil || bucket.Policy == "" || bucket.PolicyFailed || len(bucket.Tags) != 1 {
		t.Errorf("bucket %+v", bucket)
	}
	var key *awsraw.Key
	for _, k := range a.Keys {
		if k.Metadata.KeyID == keyID {
			key = k
		}
	}
	if key == nil || key.Policy == "" || key.RotationEnabled == nil || !*key.RotationEnabled || len(key.Tags) != 1 {
		t.Errorf("key %+v", key)
	}
	var secret *awsraw.Secret
	for _, s := range a.Secrets {
		if s.Name == "darb-it/db" {
			secret = s
		}
	}
	if secret == nil || secret.KMSKeyID == "" || secret.Policy == "" {
		t.Errorf("secret %+v", secret)
	}
	var param *awsraw.Parameter
	for _, p := range a.Params {
		if p.Name == "/darb-it/db" {
			param = p
		}
	}
	if param == nil || param.Type != "SecureString" || param.KeyID == "" {
		t.Errorf("parameter %+v", param)
	}
	// EKS is not in LocalStack's free services: whatever it answers, the
	// outcome is recorded, and a failure is a gap.
	for _, c := range a.Calls {
		if c.Service == "eks" && c.API == "ListClusters" && c.Status != awsraw.StatusOK && rec.Len() == 0 {
			t.Error("a failed ListClusters is not a gap")
		}
	}
}

// setUp creates, in LocalStack, a role, a bucket with a policy and a tag,
// a key with rotation and a tag, a secret with a resource policy and a
// SecureString parameter (with a dummy value LocalStack stores; the
// collector never reads it).
func setUp(ctx context.Context, t *testing.T, cfg *aws.Config, pathStyle func(*s3.Options)) string {
	t.Helper()
	must := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	read := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::darb-it-pii/*"}]}`
	ic := iam.NewFromConfig(*cfg)
	must(ic.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("darb-it-app"), AssumeRolePolicyDocument: aws.String(trust)}))
	must(ic.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: aws.String("darb-it-app"), PolicyName: aws.String("read"), PolicyDocument: aws.String(read)}))

	sc := s3.NewFromConfig(*cfg, pathStyle)
	must(sc.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("darb-it-pii")}))
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::darb-it-pii/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`
	must(sc.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String("darb-it-pii"), Policy: aws.String(policy)}))
	must(sc.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String("darb-it-pii"), Tagging: &s3types.Tagging{
		TagSet: []s3types.Tag{{Key: aws.String("data-classification"), Value: aws.String("pii")}},
	}}))

	kc := kms.NewFromConfig(*cfg)
	key, err := kc.CreateKey(ctx, &kms.CreateKeyInput{Tags: []kmstypes.Tag{{TagKey: aws.String("team"), TagValue: aws.String("it")}}})
	if err != nil {
		t.Fatal(err)
	}
	keyID := aws.ToString(key.KeyMetadata.KeyId)
	must(kc.EnableKeyRotation(ctx, &kms.EnableKeyRotationInput{KeyId: aws.String(keyID)}))

	smc := secretsmanager.NewFromConfig(*cfg)
	sec, err := smc.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name: aws.String("darb-it/db"), KmsKeyId: aws.String(keyID), SecretString: aws.String("dummy"),
		Tags: []smtypes.Tag{{Key: aws.String("data-classification"), Value: aws.String("credentials")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/darb-it-app"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`
	must(smc.PutResourcePolicy(ctx, &secretsmanager.PutResourcePolicyInput{SecretId: sec.ARN, ResourcePolicy: aws.String(resPolicy)}))

	pc := ssm.NewFromConfig(*cfg)
	must(pc.PutParameter(ctx, &ssm.PutParameterInput{
		Name: aws.String("/darb-it/db"), Type: ssmtypes.ParameterTypeSecureString, Value: aws.String("dummy"), KeyId: aws.String(keyID),
	}))
	return keyID
}
