package model

// Records of the canonical inventory. Nodes (Principal, Resource, Workload)
// are immutable types with constructors; the relation records below are
// plain value types that normalizers build once and nothing mutates after
// Inventory.Sort (docs/DESIGN.md section 5, "value types").

// Encryption is how a resource's data is encrypted at rest.
type Encryption struct {
	Type   string // "aws:kms", "aws:kms:dsse", "AES256", "none", or "" when unknown
	KeyARN string // KMS key ARN, when Type is aws:kms*; "" means the AWS managed key
}

// S3Settings are the S3 facts the evaluator needs.
type S3Settings struct {
	RestrictPublicBuckets Tri // bucket-level Block Public Access (Unknown when not stated)
}

// AttachedPolicy binds a policy document to a principal or resource.
type AttachedPolicy struct {
	Target ID
	Doc    *PolicyDocument
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

// PodIdentityAssociation maps a service account to a role (EKS Pod Identity).
type PodIdentityAssociation struct {
	Cluster        string
	Namespace      string
	ServiceAccount string
	RoleARN        string
	Source         SourceLocation
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
	NodeGroups      []*NodeGroup
	RBAC            []*RBACGrant
	Mappings        []*IdentityMapping
}
