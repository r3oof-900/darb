package awslive_test

import (
	"slices"
	"testing"

	"github.com/r3oof-900/darb/internal/collect/awslive"
	"github.com/r3oof-900/darb/internal/collect/awslive/awsfake"
)

// Every recorded call of a full collection is one of the allowed APIs.
func TestCallsAreAllowed(t *testing.T) {
	ff := &awsfake.Factory{}
	a, _ := run(t, ff, "eu-west-1")
	// Without the credential report, the keys' last use comes from
	// GetAccessKeyLastUsed.
	denied, _ := run(t, &awsfake.Factory{Fail: map[string]error{"GenerateCredentialReport": awsfake.Denied("AccessDenied")}}, "eu-west-1")
	a.Calls = append(a.Calls, denied.Calls...)
	iamName := map[string]string{
		"s3:ListBuckets": "s3:ListAllMyBuckets", "s3:GetBucketEncryption": "s3:GetEncryptionConfiguration",
		"s3:GetPublicAccessBlock": "s3:GetBucketPublicAccessBlock", "s3control:GetPublicAccessBlock": "s3:GetAccountPublicAccessBlock",
	}
	used := map[string]bool{}
	for _, c := range a.Calls {
		action := c.Service + ":" + c.API
		if n, ok := iamName[action]; ok {
			action = n
		}
		used[action] = true
		if !slices.Contains(awslive.AllowedAPIs(), action) {
			t.Errorf("call %s is not in allowedAPIs", action)
		}
	}
	// The fakes' account has no bucket without a region, so GetBucketLocation
	// is the one allowed API a full fake collection may not call.
	for _, api := range awslive.AllowedAPIs() {
		if !used[api] && api != "s3:GetBucketLocation" {
			t.Errorf("%s is allowed but never called", api)
		}
	}
}
