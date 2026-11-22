package model

// Records of the canonical inventory. Nodes (Principal, Resource, Workload)
// are immutable types with constructors; the relation records below are
// plain value types that normalizers build once and nothing mutates after
// Inventory.Sort (docs/DESIGN.md section 5, "value types").

// Encryption is how a resource's data is encrypted at rest.
type Encryption struct {
	Type   string // "aws:kms", "aws:kms:dsse", "AES256", "none", or "" when unknown
	KeyARN string // KMS key ARN, when Type is aws:kms*; "" means the AWS managed key
	// BucketKey: S3 Bucket Key enabled. It decides the KMS encryption context
	// (the bucket ARN with it, the object ARN without — S3 User Guide ›
	// "Encryption context"); no default is documented, so unstated is Unknown.
	BucketKey Tri
}

// S3Settings are the S3 facts the evaluator needs.
type S3Settings struct {
	RestrictPublicBuckets Tri // bucket-level Block Public Access (Unknown when not stated)
}

// AccountPublicAccessBlock is an account's S3 Block Public Access
// (s3control GetPublicAccessBlock, aws_s3_account_public_access_block).
// The stricter of the account's and the bucket's setting applies (S3 User
// Guide › Blocking public access to your Amazon S3 storage: "If the block
// public access settings for the access point, bucket, or account differ,
// then Amazon S3 applies the most restrictive combination of the access
// point, bucket, and account settings.").
type AccountPublicAccessBlock struct {
	Account               string
	RestrictPublicBuckets Tri // Unknown when the call failed or the value is not known
	Source                SourceLocation
}

// AttachedPolicy binds a policy document to a principal or resource.
type AttachedPolicy struct {
	Target ID
	Doc    *PolicyDocument
	// Default is the DocumentedDefaults key when the policy is a documented
	// default (the KMS default key policy); "" when the input states it.
	Default string
}

// ServiceAccount is a Kubernetes service account and its AWS identity.
type ServiceAccount struct {
	ID        ID
	Cluster   string
	Namespace string
	Name      string
	// IRSA: the eks.amazonaws.com/role-arn annotation (may be an unresolved placeholder).
	RoleARN string
	// Audience is eks.amazonaws.com/audience, defaulting to sts.amazonaws.com.
	Audience       string
	AutomountToken Tri
	Defaulted      []string // settings that took a documented default
	Source         SourceLocation
}

// SubjectString is "system:serviceaccount:<ns>:<name>", the IRSA :sub value
// (EKS User Guide › IAM roles for service accounts).
func (s *ServiceAccount) SubjectString() string {
	return "system:serviceaccount:" + s.Namespace + ":" + s.Name
}

// Cluster is an EKS (or other) cluster.
type Cluster struct {
	Name       string
	ARN        string
	Account    string
	Region     string
	OIDCIssuer string // https://oidc.eks.<region>.amazonaws.com/id/<ID>; "" when unknown
	Source     SourceLocation
}

// PodIdentityAssociation maps a service account to a role (EKS Pod Identity;
// EKS API Reference › CreatePodIdentityAssociation).
type PodIdentityAssociation struct {
	Cluster        string
	Namespace      string
	ServiceAccount string
	RoleARN        string
	// TargetRoleARN is the role the association role chains into
	// (targetRoleArn); "" when none.
	TargetRoleARN string
	// SessionTagsDisabled is disableSessionTags: False (the default) means
	// EKS adds its six session tags, so the trust policy must also allow
	// sts:TagSession.
	SessionTagsDisabled Tri
	Defaulted           []string // settings that took a documented default
	Source              SourceLocation
}

// NetworkPolicy is the part of a Kubernetes NetworkPolicy the posture rules
// read: whether it is a default deny for ingress in its namespace.
type NetworkPolicy struct {
	Cluster   string
	Namespace string
	Name      string
	// SelectsAll: an empty podSelector (every pod of the namespace).
	SelectsAll bool
	// Ingress: the policy affects ingress (stated, or the documented default
	// when policyTypes is not specified).
	Ingress      bool
	IngressRules int
	Defaulted    []string
	Source       SourceLocation
}

// DefaultDenyIngress reports whether the policy denies all ingress to every
// pod of its namespace.
func (p *NetworkPolicy) DefaultDenyIngress() bool {
	return p.SelectsAll && p.Ingress && p.IngressRules == 0
}

// OIDCProvider is an IAM OIDC identity provider. STS accepts a web identity
// token only when its aud claim is one of ClientIDs (IAM User Guide ›
// "Create an OpenID Connect (OIDC) identity provider").
type OIDCProvider struct {
	ARN       string
	Account   string
	ClientIDs []string
	Source    SourceLocation
}

// ClusterAddon is an EKS add-on installed on a cluster (for example the
// eks-pod-identity-agent, without which Pod Identity issues no credentials).
type ClusterAddon struct {
	Cluster string
	Name    string
	Source  SourceLocation
}

// NodeGroup is a group of worker nodes with an instance role and IMDS settings.
type NodeGroup struct {
	Cluster      string
	Name         string
	RoleARN      string
	HTTPTokens   string // "required", "optional", or "" when unknown
	HopLimit     int    // 0 when unknown
	HTTPEndpoint string // "enabled", "disabled", or "" when unknown
	Source       SourceLocation
}

// RBACRule is one Kubernetes RBAC rule.
type RBACRule struct {
	APIGroups     []string
	Resources     []string
	Verbs         []string
	ResourceNames []string
}

// RBACGrant is a resolved (Cluster)RoleBinding: a subject gets rules in a
// namespace ("" = cluster-wide).
type RBACGrant struct {
	Cluster          string
	Namespace        string
	SubjectKind      string // ServiceAccount, User, Group
	SubjectNamespace string
	SubjectName      string
	Rules            []RBACRule
	// Unresolved explains why Rules are unknown (e.g. a referenced role that is
	// not in the input); "" when Rules are complete.
	Unresolved string
	Source     SourceLocation
}

// SubjectIAMPrincipal is the RBAC subject kind of an EKS access policy
// association: the IAM principal itself holds the Kubernetes permissions.
const SubjectIAMPrincipal = "IAMPrincipal"

// IdentityMapping maps an IAM principal to a Kubernetes user and groups
// (aws-auth ConfigMap or EKS access entries).
type IdentityMapping struct {
	Cluster      string
	PrincipalARN string
	Username     string
	Groups       []string
	Source       SourceLocation
}

// Inventory is the normalized output of all collectors.
type Inventory struct {
	Principals      []*Principal
	Resources       []*Resource
	Workloads       []*Workload
	ServiceAccounts []*ServiceAccount
	Clusters        []*Cluster
	Policies        []*AttachedPolicy // identity, boundary and resource-based policies
	Boundaries      []*AttachedPolicy
	Trusts          []*TrustRelationship
	Exposures       []*NetworkExposure
	PodIdentity     []*PodIdentityAssociation
	Addons          []*ClusterAddon
	NetworkPolicies []*NetworkPolicy
	OIDCProviders   []*OIDCProvider
	NodeGroups      []*NodeGroup
	RBAC            []*RBACGrant
	Mappings        []*IdentityMapping
	// AccountBlocks: account-level S3 Block Public Access of the accounts
	// whose setting is in the input (Phase 7).
	AccountBlocks []*AccountPublicAccessBlock
}

// RestrictPublic is a bucket's effective RestrictPublicBuckets: true when
// the bucket's or its account's setting is on; otherwise unknown when
// either is unknown; otherwise off. An account whose setting is not in the
// input does not change the bucket's (DESIGN.md 4.4: that can report a
// path the account setting blocks, never hide one).
func (inv *Inventory) RestrictPublic(r *Resource) Tri {
	v := r.S3().RestrictPublicBuckets
	if v == True {
		return True
	}
	for _, a := range inv.AccountBlocks {
		if a.Account != r.Account() {
			continue
		}
		if a.RestrictPublicBuckets == True {
			return True
		}
		if a.RestrictPublicBuckets == Unknown {
			v = Unknown
		}
	}
	return v
}
