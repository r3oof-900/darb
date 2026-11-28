package model

import "slices"

// Credentials is what an IAM user, or the account root, can authenticate
// with (DESIGN.md §5, entry points): from the credential report (the
// primary source) and ListAccessKeys (the key IDs). Known is False when
// neither was in the input: the user is then an entry at the worst case,
// unconfirmed.
type Credentials struct {
	Principal ID
	Known     Tri
	// Keys: every access key, active or not (AWS allows two per user).
	Keys []AccessKey
	// KeyCount: how many keys exist (active or inactive); -1 when not known.
	KeyCount int
	Password Tri
	MFA      Tri
	// Generated: when the credential report was generated (it may be hours
	// old); "" when the state comes from ListAccessKeys only.
	Generated string
	Source    SourceLocation
}

// AccessKey is one access key of a user.
type AccessKey struct {
	// ID: the AccessKeyId (ListAccessKeys); "" when only the report names
	// the key. Reports show its last four characters only.
	ID       string
	Active   bool
	Created  string
	LastUsed string
}

// ActiveKey reports whether the user has an active access key.
func (c *Credentials) ActiveKey() Tri {
	if c == nil || c.Known != True {
		return Unknown
	}
	return TriOf(slices.ContainsFunc(c.Keys, func(k AccessKey) bool { return k.Active }))
}

// MaskedID is an access key ID with every character but the last four
// replaced (reports never print a key ID in full).
func MaskedID(id string) string {
	if len(id) <= 4 {
		return id
	}
	return "****" + id[len(id)-4:]
}

// IAMGroup is an IAM group: its members and its own policies (inline and
// attached), which apply to every member.
type IAMGroup struct {
	ARN      string
	Account  string
	Members  []ID
	Policies []*PolicyDocument
	Source   SourceLocation
}

// ManagedPolicyVersions is a customer managed policy with its stored
// versions (iam:GetAccountAuthorizationDetails PolicyVersionList): the
// escalations CreatePolicyVersion and SetDefaultPolicyVersion read them.
type ManagedPolicyVersions struct {
	ARN     string
	Account string
	// Count: stored versions (IAM keeps at most five).
	Count int
	// Others: the non-default versions, each with its version ID as the
	// document's ID suffix ("<ARN>#v2").
	Others []*PolicyDocument
	// Attached: the principals the policy is attached to (users, roles;
	// groups as their members).
	Attached []ID
}
