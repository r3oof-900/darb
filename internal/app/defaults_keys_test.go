package app

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/model"
)

// managedKeyCases: the documented defaults of AWS managed KMS keys.
func managedKeyCases() []defaultCase {
	return []defaultCase{
		{model.DefaultAWSManagedKeyRot, func(t *testing.T) {
			key := func(id, manager string) string {
				return `{"KeyMetadata": {"KeyId": "` + id + `", "Arn": "arn:aws:kms:eu-west-1:111122223333:key/` + id + `", "KeyManager": "` + manager + `"}}`
			}
			l := loadTree(t, map[string]string{
				"snap/manifest.json": `{"format": "clapa-snapshot/v1", "accounts": [{"id": "111122223333", "partition": "aws"}], "calls": []}`,
				"snap/111122223333/iam/get-account-authorization-details.json": `{}`,
				"snap/111122223333/eu-west-1/kms/aws1/describe-key.json":       key("aws1", "AWS"),
				"snap/111122223333/eu-west-1/kms/aws1/get-key-policy.json":     `{"Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"}`,
				"snap/111122223333/eu-west-1/kms/k1/describe-key.json":         key("k1", "CUSTOMER"),
				"snap/111122223333/eu-west-1/kms/k1/get-key-policy.json":       `{"Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"}`,
			}, func(in *Inputs) { in.AWSSnapshots = []string{"snap"} })
			for _, r := range l.Inventory.Resources {
				aws := strings.HasSuffix(r.ARN(), "/aws1")
				if aws != (r.KeyRotation() == model.True) || aws != slices.Contains(r.Defaulted(), model.DefaultAWSManagedKeyRot) {
					t.Errorf("%s: rotation %s, defaulted %v", r.ARN(), r.KeyRotation(), r.Defaulted())
				}
			}
		}},
		{model.DefaultSecretsManagedKey, func(t *testing.T) {
			const secret = "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-aaaaaa" //nolint:gosec // G101: a secret's ARN, not a credential.
			key := `"KmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"`
			describe := func(dir string) string {
				return filepath.Join(dir, "snapshot", "111122223333", "us-east-1", "secretsmanager", "prod%2Fdb", "describe-secret.json")
			}
			// The AWS managed key: principals of the secret's account decrypt.
			a := analyzeVariant(t, "19_secrets_manager/vulnerable", func(dir string) { replaceIn(t, describe(dir), key, `"KmsKeyId": ""`) })
			f := findingFor(a, "CLAPA-PATH-001", secret)
			if f == nil || !slices.Contains(f.DefaultsUsed, model.DefaultSecretsManagedKey) || !f.Confirmed {
				t.Fatalf("aws/secretsmanager, same account: %+v", f)
			}
			a = analyzeVariant(t, "19_secrets_manager/vulnerable", func(dir string) {
				replaceIn(t, describe(dir), key, `"KmsKeyId": "alias/aws/secretsmanager"`)
			})
			if f := findingFor(a, "CLAPA-PATH-001", secret); f == nil || !slices.Contains(f.DefaultsUsed, model.DefaultSecretsManagedKey) {
				t.Fatalf("alias/aws/secretsmanager: %+v", f)
			}
		}},
		{model.DefaultSSMManagedKey, func(t *testing.T) {
			const param = "arn:aws:ssm:us-east-1:111122223333:parameter/prod/db/password"
			a := analyzeVariant(t, "20_ssm_securestring/vulnerable", func(dir string) {
				replaceIn(t, filepath.Join(dir, "snapshot", "111122223333", "us-east-1", "ssm", "%2Fprod%2Fdb%2Fpassword", "describe-parameters.json"),
					`"KeyId": "arn:aws:kms:us-east-1:111122223333:key/66666666-7777-8888-9999-000000000000"`, `"KeyId": "alias/aws/ssm"`)
			})
			f := findingFor(a, "CLAPA-PATH-001", param)
			if f == nil || !slices.Contains(f.DefaultsUsed, model.DefaultSSMManagedKey) || !f.Confirmed {
				t.Fatalf("aws/ssm: %+v", f)
			}
		}},
	}
}
