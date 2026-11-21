package awssnapshot

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/r3oof-900/clapa/internal/collect"
	"github.com/r3oof-900/clapa/internal/collect/awsraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/safeio"
)

func ptr[T any](v T) *T { return &v }

// sample has every field the layout stores, names that need escaping, and
// failed calls whose resources must read back as unknown.
func sample() *awsraw.Snapshot {
	const acct = "111122223333"
	return &awsraw.Snapshot{Accounts: []*awsraw.Account{{
		ID: acct, Partition: "aws",
		Auth: &awsraw.AuthorizationDetails{
			RoleDetailList: []awsraw.RoleDetail{{
				RoleName: "app", Arn: "arn:aws:iam::" + acct + ":role/app",
				AssumeRolePolicyDocument: json.RawMessage(`"%7B%7D"`),
				RolePolicyList:           []awsraw.InlinePolicy{{PolicyName: "p", PolicyDocument: json.RawMessage(`"%7B%7D"`)}},
				AttachedManagedPolicies:  []awsraw.AttachedPolicy{{PolicyName: "ReadOnlyAccess", PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess"}},
				PermissionsBoundary:      &awsraw.Boundary{PermissionsBoundaryType: "Policy", PermissionsBoundaryArn: "arn:aws:iam::" + acct + ":policy/b"},
				Tags:                     []awsraw.Tag{{Key: "team", Value: "x"}},
			}},
			UserDetailList:  []awsraw.UserDetail{},
			GroupDetailList: []awsraw.GroupDetail{},
			Policies:        []awsraw.ManagedPolicy{},
		},
		Keys: []*awsraw.Key{
			{Region: "eu-west-1", Metadata: awsraw.KeyMetadata{KeyID: "aws1", Arn: "arn:aws:kms:eu-west-1:" + acct + ":key/aws1", KeyManager: "AWS", KeyState: "Enabled"}, Policy: "{}"},
			{
				Region: "eu-west-1", Metadata: awsraw.KeyMetadata{KeyID: "k1", Arn: "arn:aws:kms:eu-west-1:" + acct + ":key/k1", KeyManager: "CUSTOMER", KeyState: "Enabled"},
				RotationEnabled: ptr(false), Tags: []awsraw.Tag{{Key: "data-classification", Value: "pii"}},
			},
		},
		Aliases: []awsraw.Alias{{Region: "eu-west-1", AliasName: "alias/aws/ssm", AliasArn: "arn:aws:kms:eu-west-1:" + acct + ":alias/aws/ssm", TargetKeyID: "aws1"}},
		Buckets: []*awsraw.Bucket{
			{Name: "logs", Region: "us-east-1", PolicyFailed: true, PublicAccessBlock: &awsraw.PublicAccessBlock{}, Tags: []awsraw.Tag{}},
			{
				Name: "pii.data", Region: "eu-west-1", Policy: `{"Version":"2012-10-17"}`,
				Encryption:        &awsraw.Encryption{SSEAlgorithm: "aws:kms", KMSMasterKeyID: "k1", BucketKeyEnabled: ptr(true)},
				PublicAccessBlock: &awsraw.PublicAccessBlock{RestrictPublicBuckets: true, BlockPublicPolicy: true},
				Tags:              []awsraw.Tag{{Key: "a", Value: "b"}},
			},
		},
		Clusters: []*awsraw.Cluster{{
			Region: "eu-west-1", Name: "Prod", Arn: "arn:aws:eks:eu-west-1:" + acct + ":cluster/Prod", OIDCIssuer: "https://oidc.example/id/X",
			PodIdentity: []awsraw.PodIdentityAssociation{{
				ClusterName: "Prod", Namespace: "payments", ServiceAccount: "api", RoleArn: "arn:aws:iam::" + acct + ":role/app",
				AssociationArn: "arn:aws:eks:eu-west-1:" + acct + ":podidentityassociation/Prod/a-1", DisableSessionTags: ptr(false),
			}},
		}},
		Secrets: []*awsraw.Secret{
			{Region: "eu-west-1", ARN: "arn:aws:secretsmanager:eu-west-1:" + acct + ":secret:db/Password-a1", Name: "db/Password", KMSKeyID: "k1", Policy: `{"Version":"2012-10-17"}`, Tags: []awsraw.Tag{}},
			{Region: "eu-west-1", ARN: "arn:aws:secretsmanager:eu-west-1:" + acct + ":secret:db/password-b2", Name: "db/password", PolicyFailed: true, Tags: []awsraw.Tag{{Key: "k", Value: "v"}}},
		},
		Params: []*awsraw.Parameter{
			{Region: "eu-west-1", Name: "/app/db", ARN: "arn:aws:ssm:eu-west-1:" + acct + ":parameter/app/db", Type: "SecureString", KeyID: "alias/aws/ssm", Tier: "Advanced", Policies: []string{`{"Version":"2012-10-17"}`}, Tags: []awsraw.Tag{}},
			{Region: "eu-west-1", Name: "/app/url", ARN: "arn:aws:ssm:eu-west-1:" + acct + ":parameter/app/url", Type: "String", Tier: "Standard"},
		},
		Calls: []awsraw.Call{
			{Service: "s3", Region: "us-east-1", API: "GetBucketPolicy", Target: "logs", Status: awsraw.StatusAccessDenied, Error: "AccessDenied: no"},
			{Service: "secretsmanager", Region: "eu-west-1", API: "GetResourcePolicy", Target: "arn:aws:secretsmanager:eu-west-1:" + acct + ":secret:db/password-b2", Status: awsraw.StatusThrottling},
			{Service: "sts", API: "GetCallerIdentity", Status: awsraw.StatusOK},
		},
	}}}
}

func TestWriteThenCollectRoundTrips(t *testing.T) {
	root := t.TempDir()
	in := sample()
	if err := Write(filepath.Join(root, "bundle"), in); err != nil {
		t.Fatal(err)
	}
	rec := &coverage.Recorder{}
	out, err := Collect(context.Background(), &collect.Input{Root: root, Path: "bundle", Limits: safeio.DefaultLimits()}, rec)
	if err != nil {
		t.Fatal(err)
	}
	// The two failed calls are the only gaps: every written file is read.
	if rec.Len() != 2 || rec.Count(coverage.KindAccessDenied) != 1 || rec.Count(coverage.KindThrottled) != 1 {
		t.Fatalf("gaps %+v", rec.Gaps())
	}
	if !reflect.DeepEqual(in, out) {
		a, b := in.Accounts[0], out.Accounts[0]
		for name, pair := range map[string][2]any{
			"auth": {a.Auth, b.Auth}, "keys": {a.Keys, b.Keys}, "aliases": {a.Aliases, b.Aliases}, "buckets": {a.Buckets, b.Buckets},
			"clusters": {a.Clusters, b.Clusters}, "secrets": {a.Secrets, b.Secrets}, "params": {a.Params, b.Params}, "calls": {a.Calls, b.Calls},
		} {
			if !reflect.DeepEqual(pair[0], pair[1]) {
				x, _ := json.Marshal(pair[0])
				y, _ := json.Marshal(pair[1])
				t.Errorf("%s:\n wrote %s\n read  %s", name, x, y)
			}
		}
		t.FailNow()
	}
}

func TestWriteIsDeterministic(t *testing.T) {
	root := t.TempDir()
	read := func(dir string) map[string]string {
		files := map[string]string{}
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, rerr := os.ReadFile(p) //nolint:gosec // G304: the test's own temporary directory.
			rel, _ := filepath.Rel(dir, p)
			files[filepath.ToSlash(rel)] = string(data)
			return rerr
		})
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	for _, d := range []string{"a", "b"} {
		if err := Write(filepath.Join(root, d), sample()); err != nil {
			t.Fatal(err)
		}
	}
	a, b := read(filepath.Join(root, "a")), read(filepath.Join(root, "b"))
	if !reflect.DeepEqual(a, b) || len(a) < 15 {
		t.Fatalf("%d and %d files differ", len(a), len(b))
	}
	if _, ok := a["111122223333/eu-west-1/secretsmanager/db%2F!password/describe-secret.json"]; !ok {
		t.Fatalf("escaped secret path missing: %v", keys(a))
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestWriteRefusesAnExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, sample()); !errors.Is(err, ErrWrite) {
		t.Fatalf("err %v", err)
	}
}
