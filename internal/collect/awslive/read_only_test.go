package awslive

import (
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// valueReads are the calls that return a secret or parameter value.
// darb reads metadata and policies only, never values.
func valueReads() []string {
	return []string{
		"GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath",
		"GetParameterHistory", "GetObject", "Decrypt", "GenerateDataKey",
	}
}

// AllowedAPIs is every AWS API the collector may call; docs/PERMISSIONS.md
// grants exactly these (TestPermissionsDocument).
func allowedAPIs() []string {
	return []string{
		"sts:GetCallerIdentity", "iam:GetAccountAuthorizationDetails",
		"iam:GenerateCredentialReport", "iam:GetCredentialReport", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
		"s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketPolicy", "s3:GetEncryptionConfiguration",
		"s3:GetBucketPublicAccessBlock", "s3:GetBucketTagging", "s3:GetAccountPublicAccessBlock",
		"s3:GetBucketOwnershipControls", "s3:GetBucketAcl",
		"kms:ListKeys", "kms:ListAliases", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags",
		"kms:ListGrants",
		"eks:ListClusters", "eks:DescribeCluster", "eks:ListPodIdentityAssociations", "eks:DescribePodIdentityAssociation",
		"secretsmanager:ListSecrets", "secretsmanager:GetResourcePolicy",
		"ssm:DescribeParameters", "ssm:ListTagsForResource", "ssm:GetResourcePolicies",
	}
}

// preparesOnly: the one method outside List*, Get*, Describe*:
// GenerateCredentialReport asks IAM to prepare the account's credential
// report (read with GetCredentialReport). It changes no configuration and
// no permission, and SecurityAudit grants it (item 4).
func preparesOnly() []string { return []string{"GenerateCredentialReport"} }

// Every method of every client interface reads: List*, Get*, Describe*
// (or only prepares a report to read), and none reads a value.
func TestClientInterfacesAreReadOnly(t *testing.T) {
	n := 0
	for _, typ := range []reflect.Type{
		reflect.TypeFor[STSAPI](), reflect.TypeFor[IAMAPI](), reflect.TypeFor[S3API](), reflect.TypeFor[S3ControlAPI](), reflect.TypeFor[KMSAPI](),
		reflect.TypeFor[EKSAPI](), reflect.TypeFor[SecretsAPI](), reflect.TypeFor[SSMAPI](),
	} {
		for i := range typ.NumMethod() {
			m := typ.Method(i).Name
			n++
			read := regexp.MustCompile(`^(List|Get|Describe)[A-Z]`).MatchString(m) || slices.Contains(preparesOnly(), m)
			if !read || slices.Contains(valueReads(), m) {
				t.Errorf("%s.%s is not a metadata read", typ.Name(), m)
			}
		}
	}
	if n != 31 {
		t.Fatalf("%d methods; update allowedAPIs and docs/PERMISSIONS.md with the interfaces", n)
	}
}

// No source file of the package names a value read, even in a comment
// that could become code.
func TestSourceNamesNoValueRead(t *testing.T) {
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		name := f.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name) //nolint:gosec // G304: the package's own source.
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range valueReads() {
			if regexp.MustCompile(`\.` + call + `\(`).Match(data) {
				t.Errorf("%s calls %s", name, call)
			}
		}
	}
}
