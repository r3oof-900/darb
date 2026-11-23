package normalize

import (
	"strings"

	"github.com/r3oof-900/darb/internal/model"
)

// S3 ACL grantee groups (S3 User Guide › Access control list (ACL)
// overview, "Amazon S3 predefined groups").
const (
	GroupAllUsers           = "http://acs.amazonaws.com/groups/global/AllUsers"
	GroupAuthenticatedUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// Object Ownership values (S3 API Reference › OwnershipControlsRule).
const (
	OwnerEnforced  = "BucketOwnerEnforced"
	OwnerPreferred = "BucketOwnerPreferred"
	ObjectWriter   = "ObjectWriter"
)

// ACLsOf says whether ACLs affect access with this Object Ownership:
// BucketOwnerEnforced disables them; BucketOwnerPreferred and ObjectWriter
// keep them ("a bucket with the Bucket owner preferred setting continues to
// accept and honor bucket and object ACLs"); anything else is unknown.
func ACLsOf(ownership string) model.Tri {
	switch ownership {
	case OwnerEnforced:
		return model.False
	case OwnerPreferred, ObjectWriter:
		return model.True
	}
	return model.Unknown
}

// PublicGrant names a grant to a public group ("AllUsers READ"); ok is
// false for any other grantee. A bucket or object ACL is public "if it
// grants any permissions to members of the predefined AllUsers or
// AuthenticatedUsers groups" (S3 User Guide › Blocking public access).
func PublicGrant(uri, permission string) (string, bool) {
	switch uri {
	case GroupAllUsers:
		return "AllUsers " + permission, true
	case GroupAuthenticatedUsers:
		return "AuthenticatedUsers " + permission, true
	}
	return "", false
}

// CannedPublicGrants returns the public grants of a canned ACL (S3 User Guide ›
// Access control list (ACL) overview, "Canned ACL").
func CannedPublicGrants(acl string) []string {
	switch acl {
	case "public-read":
		return []string{"AllUsers READ"}
	case "public-read-write":
		return []string{"AllUsers READ", "AllUsers WRITE"}
	case "authenticated-read":
		return []string{"AuthenticatedUsers READ"}
	}
	return nil
}

// ACLGap returns the not-modelled gap of a bucket whose ACLs are enabled. Each
// object has its own ACL, read only object by object (GetObjectAcl), which
// darb does not do; an object ACL's READ allows "to read the object data",
// so a path to the data can be missed. A bucket ACL's READ only lists the
// objects; a public one is named as evidence.
func ACLGap(s *model.S3Settings) (string, bool) {
	if s.ACLs != model.True {
		return "", false
	}
	how := "no ownership controls on an existing bucket"
	if s.Ownership != "" {
		how = "Object Ownership " + s.Ownership
	}
	detail := "ACLs are enabled (" + how + "): object ACLs are not collected, and one can give anyone or another account read access to the data"
	if len(s.PublicACL) > 0 {
		detail += "; the bucket ACL grants " + strings.Join(s.PublicACL, ", ") + " (anyone can list the objects, not read them)"
	}
	return detail, true
}

// OwnershipUnknown is the gap detail of a bucket whose Object Ownership
// the input does not state.
const OwnershipUnknown = "Object Ownership of this bucket is not in the input (no aws_s3_bucket_ownership_controls); ACLs may be enabled, and object ACLs are not collected"
