package awsraw

import "encoding/json"

// Raw AWS data, shaped like AWS CLI / API JSON output so that snapshots
// ("aws ... --output json") and the live collector (Phase 6) produce the same
// types. Policy documents are kept raw: the API returns URL-encoded strings,
// the CLI returns decoded objects; the normalizer accepts both.

// Snapshot is a whole bundle.
type Snapshot struct {
	Accounts []*Account
}

// Account holds one account's data.
type Account struct {
	ID        string
	Partition string
	Auth      *AuthorizationDetails // iam get-account-authorization-details
	Keys      []*Key
	Buckets   []*Bucket
	Clusters  []*Cluster
	Calls     []Call // every collection call, with its outcome
}

// AuthorizationDetails is iam:GetAccountAuthorizationDetails.
type AuthorizationDetails struct {
	UserDetailList  []UserDetail    `json:"UserDetailList"`
	GroupDetailList []GroupDetail   `json:"GroupDetailList"`
	RoleDetailList  []RoleDetail    `json:"RoleDetailList"`
	Policies        []ManagedPolicy `json:"Policies"`
}

// RoleDetail is one role.
type RoleDetail struct {
	Path                     string           `json:"Path"`
	RoleName                 string           `json:"RoleName"`
	RoleID                   string           `json:"RoleId"`
	Arn                      string           `json:"Arn"`
	AssumeRolePolicyDocument json.RawMessage  `json:"AssumeRolePolicyDocument"`
	RolePolicyList           []InlinePolicy   `json:"RolePolicyList"`
	AttachedManagedPolicies  []AttachedPolicy `json:"AttachedManagedPolicies"`
	PermissionsBoundary      *Boundary        `json:"PermissionsBoundary"`
	Tags                     []Tag            `json:"Tags"`
}

// UserDetail is one user.
type UserDetail struct {
	Path                    string           `json:"Path"`
	UserName                string           `json:"UserName"`
	UserID                  string           `json:"UserId"`
	Arn                     string           `json:"Arn"`
	UserPolicyList          []InlinePolicy   `json:"UserPolicyList"`
	GroupList               []string         `json:"GroupList"`
	AttachedManagedPolicies []AttachedPolicy `json:"AttachedManagedPolicies"`
	PermissionsBoundary     *Boundary        `json:"PermissionsBoundary"`
	Tags                    []Tag            `json:"Tags"`
}

// GroupDetail is one group.
type GroupDetail struct {
	Path                    string           `json:"Path"`
	GroupName               string           `json:"GroupName"`
	GroupID                 string           `json:"GroupId"`
	Arn                     string           `json:"Arn"`
	GroupPolicyList         []InlinePolicy   `json:"GroupPolicyList"`
	AttachedManagedPolicies []AttachedPolicy `json:"AttachedManagedPolicies"`
}

// InlinePolicy is an inline policy.
type InlinePolicy struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument json.RawMessage `json:"PolicyDocument"`
}

// AttachedPolicy references a managed policy.
type AttachedPolicy struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

// Boundary references a permissions boundary policy.
type Boundary struct {
	PermissionsBoundaryType string `json:"PermissionsBoundaryType"`
	PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn"`
}

// ManagedPolicy is a customer managed policy with its versions.
type ManagedPolicy struct {
	PolicyName        string          `json:"PolicyName"`
	PolicyID          string          `json:"PolicyId"`
	Arn               string          `json:"Arn"`
	DefaultVersionID  string          `json:"DefaultVersionId"`
	PolicyVersionList []PolicyVersion `json:"PolicyVersionList"`
}

// PolicyVersion is one version of a managed policy.
type PolicyVersion struct {
	Document         json.RawMessage `json:"Document"`
	VersionID        string          `json:"VersionId"`
	IsDefaultVersion bool            `json:"IsDefaultVersion"`
}

// Tag is a resource tag.
type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// Key is a KMS key: kms describe-key + get-key-policy (+ rotation status).
type Key struct {
	Region          string
	Metadata        KeyMetadata
	Policy          string // the key policy JSON (get-key-policy "Policy")
	RotationEnabled *bool
	Tags            []Tag
}

// KeyMetadata is describe-key's KeyMetadata.
type KeyMetadata struct {
	KeyID      string `json:"KeyId"`
	Arn        string `json:"Arn"`
	KeyManager string `json:"KeyManager"`
	KeyState   string `json:"KeyState"`
}

// Bucket is an S3 bucket with its policy, encryption and public access block.
type Bucket struct {
	Name              string
	Region            string
	Policy            string // "" when the bucket has no policy
	Encryption        *Encryption
	PublicAccessBlock *PublicAccessBlock
	Tags              []Tag
}

// Encryption is the default encryption rule (get-bucket-encryption).
type Encryption struct {
	SSEAlgorithm     string // "AES256", "aws:kms", "aws:kms:dsse"
	KMSMasterKeyID   string // key ARN, key ID or alias; "" for the AWS managed key
	BucketKeyEnabled *bool  // the rule's BucketKeyEnabled; nil when not in the response
}

// PublicAccessBlock is get-public-access-block.
type PublicAccessBlock struct {
	BlockPublicAcls       bool `json:"BlockPublicAcls"`
	IgnorePublicAcls      bool `json:"IgnorePublicAcls"`
	BlockPublicPolicy     bool `json:"BlockPublicPolicy"`
	RestrictPublicBuckets bool `json:"RestrictPublicBuckets"`
}

// Cluster is an EKS cluster with its Pod Identity associations.
type Cluster struct {
	Region      string
	Name        string
	Arn         string
	OIDCIssuer  string
	PodIdentity []PodIdentityAssociation
}

// PodIdentityAssociation is eks describe-pod-identity-association.
type PodIdentityAssociation struct {
	ClusterName    string `json:"clusterName"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	RoleArn        string `json:"roleArn"`
	AssociationArn string `json:"associationArn"`
	TargetRoleArn  string `json:"targetRoleArn,omitempty"`
	// DisableSessionTags is nil when the snapshot does not record it.
	DisableSessionTags *bool `json:"disableSessionTags,omitempty"`
}

// Call is one collection API call and its outcome.
type Call struct {
	Service string `json:"service"`
	Region  string `json:"region"`
	API     string `json:"api"`
	Target  string `json:"target"`
	Status  string `json:"status"` // "ok", "AccessDenied", "Throttling", "Timeout", "Error"
	Error   string `json:"error"`
}
