package access

import "github.com/r3oof-900/darb/internal/model"

// bucketRegion: an S3 request goes to the bucket's region
// (aws:RequestedRegion), when the input states it; nil leaves the region to
// the caller (eval.DocumentedKeys).
func bucketRegion(j *model.Resource) map[string][]string {
	if j.Region() == "" {
		return nil
	}
	return map[string][]string{"aws:RequestedRegion": {j.Region()}}
}

// s3Decrypt: the context of the kms:Decrypt S3 makes for principal on
// bucket j under encryption context c (S3 User Guide › Encryption context;
// KMS Developer Guide › kms:ViaService, kms:CallerAccount): a forward access
// session of S3 (DESIGN.md §6.2). A bucket whose region is not in the input
// leaves that part of kms:ViaService unresolved.
func s3Decrypt(principal *model.Principal, j *model.Resource, c string) map[string][]string {
	region := j.Region()
	if region == "" {
		region = model.UnresolvedPlaceholder("bucket-region")
	}
	return map[string][]string{
		"kms:EncryptionContext:aws:s3:arn": {c},
		"kms:EncryptionContextKeys":        {"aws:s3:arn"},
		"kms:ViaService":                   {"s3." + region + ".amazonaws.com"},
		"kms:CallerAccount":                {principal.Account()},
	}
}
