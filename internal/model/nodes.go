package model

import (
	"cmp"
	"slices"
)

// Tag is a resource tag.
type Tag struct {
	Key   string
	Value string
}

// Principal is an identity that can act: an IAM role or user, an account
// root, an AWS service, the anonymous principal, or a Kubernetes subject.
type Principal struct {
	id       ID
	kind     NodeKind
	identity string
	account  string
	source   SourceLocation
}

// NewPrincipal builds a principal. identity is the canonical identity
// (ARN, service name, or K8sIdentity); account may be empty.
func NewPrincipal(kind NodeKind, identity, account string, src *SourceLocation) *Principal {
	return &Principal{id: NewID(kind, identity), kind: kind, identity: identity, account: account, source: *src}
}

// ID returns the stable node ID.
func (p *Principal) ID() ID { return p.id }

// Kind returns the node kind.
func (p *Principal) Kind() NodeKind { return p.kind }

// Identity returns the canonical identity.
func (p *Principal) Identity() string { return p.identity }

// Account returns the AWS account ID, if any.
func (p *Principal) Account() string { return p.account }

// Source returns where the principal was defined.
func (p *Principal) Source() *SourceLocation { s := p.source; return &s }

// ResourceInput is the mutable input to NewResource.
type ResourceInput struct {
	Kind           NodeKind
	ARN            string
	Account        string
	Region         string
	Tags           map[string]string
	Classification string // e.g. "pii"; empty when not a crown jewel
	ClassifiedBy   string // which rule marked it: "tag:DataClass", "config", "heuristic:..."
	Encryption     Encryption
	S3             S3Settings
	KeyRotation    Tri // KMS keys: automatic rotation (Unknown when not stated and no deterministic default)
	// Tier: SSM parameters: "Standard", "Advanced" or "Intelligent-Tiering";
	// "" when not known (Terraform without tier takes the region's default).
	Tier string
	// Grants: KMS keys: how far the key's grants are known (GrantsListed,
	// GrantsTerraform, or GrantsNotCollected).
	Grants string
	// Defaulted lists the settings that took a documented default
	// (DocumentedDefaults keys).
	Defaulted []string
	Source    SourceLocation
}

// How far a KMS key's grants are known.
const (
	// GrantsNotCollected: ListGrants failed, or the snapshot predates it.
	GrantsNotCollected = ""
	// GrantsListed: every grant is in the input (ListGrants).
	GrantsListed = "listed"
	// GrantsTerraform: the aws_kms_grant resources are; grants that AWS
	// services create at runtime are not visible in IaC.
	GrantsTerraform = "terraform"
)

// Resource is a protected AWS or Kubernetes resource.
type Resource struct {
	id             ID
	kind           NodeKind
	arn            string
	account        string
	region         string
	tags           []Tag
	classification string
	classifiedBy   string
	encryption     Encryption
	s3             S3Settings
	tier           string
	keyRotation    Tri
	grants         string
	defaulted      []string
	source         SourceLocation
}

// NewResource copies in; tags are sorted by key.
func NewResource(in *ResourceInput) *Resource {
	tags := make([]Tag, 0, len(in.Tags))
	for k, v := range in.Tags {
		tags = append(tags, Tag{Key: k, Value: v})
	}
	slices.SortFunc(tags, func(a, b Tag) int { return cmp.Compare(a.Key, b.Key) })
	return &Resource{
		id: NewID(in.Kind, in.ARN), kind: in.Kind, arn: in.ARN, account: in.Account, region: in.Region,
		tags: tags, classification: in.Classification, classifiedBy: in.ClassifiedBy,
		encryption: in.Encryption, s3: in.S3.clone(), keyRotation: in.KeyRotation, tier: in.Tier, grants: in.Grants, defaulted: sortedSet(in.Defaulted), source: in.Source,
	}
}

// sortedSet returns ss sorted, without duplicates, as a new slice.
func sortedSet(ss []string) []string {
	out := slices.Clone(ss)
	slices.Sort(out)
	return slices.Compact(out)
}

// Grants reports how far a KMS key's grants are known.
func (r *Resource) Grants() string { return r.grants }

// KeyRotation reports a KMS key's automatic rotation.
func (r *Resource) KeyRotation() Tri { return r.keyRotation }

// Tier returns an SSM parameter's tier ("" when not known).
func (r *Resource) Tier() string { return r.tier }

// Shareable reports whether an SSM parameter may be shared through AWS
// RAM: only advanced-tier parameters can be (Parameter Store › Working with
// shared parameters: "To share a parameter, it must be in the advanced
// parameter tier."). Intelligent-Tiering may make a parameter advanced, and
// an unknown tier may be advanced.
func (r *Resource) Shareable() bool { return r.kind == KindSSMParameter && r.tier != "Standard" }

// Defaulted returns the settings that took a documented default.
func (r *Resource) Defaulted() []string { return slices.Clone(r.defaulted) }

// ID returns the stable node ID.
func (r *Resource) ID() ID { return r.id }

// Kind returns the node kind.
func (r *Resource) Kind() NodeKind { return r.kind }

// ARN returns the resource's canonical identity (an ARN for AWS resources).
func (r *Resource) ARN() string { return r.arn }

// Account returns the owning account ID, if known.
func (r *Resource) Account() string { return r.account }

// Region returns the region, if any.
func (r *Resource) Region() string { return r.region }

// Tags returns a copy of the tags, sorted by key.
func (r *Resource) Tags() []Tag { return slices.Clone(r.tags) }

// Classification returns the data classification and which rule set it.
func (r *Resource) Classification() (class, by string) { return r.classification, r.classifiedBy }

// Encryption returns the encryption at rest.
func (r *Resource) Encryption() Encryption { return r.encryption }

// S3 returns S3-specific settings.
func (r *Resource) S3() S3Settings { return r.s3.clone() }

// clone copies the settings, so a caller cannot change a Resource's.
func (s S3Settings) clone() S3Settings {
	s.PublicACL = slices.Clone(s.PublicACL)
	return s
}

// WithClassification returns a copy of r marked as a crown jewel.
func (r *Resource) WithClassification(class, by string) *Resource {
	c := *r
	c.tags = slices.Clone(r.tags)
	c.classification, c.classifiedBy = class, by
	return &c
}

// Source returns where the resource was defined.
func (r *Resource) Source() *SourceLocation { s := r.source; return &s }

// WithS3 returns a copy of r with other S3 settings (remediation).
func (r *Resource) WithS3(s S3Settings) *Resource {
	c := *r
	c.tags, c.defaulted = slices.Clone(r.tags), slices.Clone(r.defaulted)
	c.s3 = s.clone()
	return &c
}

// WorkloadInput is the mutable input to NewWorkload.
type WorkloadInput struct {
	Cluster        string
	Namespace      string
	Kind           string // Deployment, Pod, ...
	Name           string
	ServiceAccount string
	HostNetwork    bool
	Privileged     bool // any container runs privileged
	AutomountToken Tri  // Unknown when not stated and not derivable
	// ProjectedAudiences are the audiences of serviceAccountToken volumes the
	// pod spec projects itself (no annotation needed).
	ProjectedAudiences []string
	// SecretRefs: the Secrets of its namespace the pod spec names (secret
	// and projected volumes, env secretKeyRef, envFrom secretRef); the
	// kubelet gives them to the pod without any RBAC check (DESIGN.md 7.2).
	SecretRefs []string
	Defaulted  []string
	Source     SourceLocation
}

// Workload is a Kubernetes workload.
type Workload struct {
	id             ID
	cluster        string
	namespace      string
	kind           string
	name           string
	serviceAccount string
	hostNetwork    bool
	privileged     bool
	projected      []string
	secretRefs     []string
	automountToken Tri
	defaulted      []string
	source         SourceLocation
}

// NewWorkload copies in. The ID derives from K8sIdentity.
func NewWorkload(in *WorkloadInput) *Workload {
	identity := K8sIdentity(in.Cluster, in.Namespace, in.Kind, in.Name)
	return &Workload{
		id: NewID(KindK8sWorkload, identity), cluster: in.Cluster, namespace: in.Namespace, kind: in.Kind,
		name: in.Name, serviceAccount: in.ServiceAccount, hostNetwork: in.HostNetwork, privileged: in.Privileged,
		projected: sortedSet(in.ProjectedAudiences), secretRefs: sortedSet(in.SecretRefs), automountToken: in.AutomountToken, defaulted: sortedSet(in.Defaulted), source: in.Source,
	}
}

// ProjectedAudiences returns the audiences of the service account tokens
// the pod spec projects.
func (w *Workload) ProjectedAudiences() []string { return slices.Clone(w.projected) }

// SecretRefs returns the Secrets of its namespace the pod spec names.
func (w *Workload) SecretRefs() []string { return slices.Clone(w.secretRefs) }

// Privileged reports whether any container runs privileged.
func (w *Workload) Privileged() bool { return w.privileged }

// Defaulted returns the settings that took a documented default.
func (w *Workload) Defaulted() []string { return slices.Clone(w.defaulted) }

// ID returns the stable node ID.
func (w *Workload) ID() ID { return w.id }

// Identity returns the canonical K8s identity.
func (w *Workload) Identity() string {
	return K8sIdentity(w.cluster, w.namespace, w.kind, w.name)
}

// Cluster returns the cluster name.
func (w *Workload) Cluster() string { return w.cluster }

// Namespace returns the namespace.
func (w *Workload) Namespace() string { return w.namespace }

// ServiceAccount returns the service account name the pods run as.
func (w *Workload) ServiceAccount() string { return w.serviceAccount }

// HostNetwork reports hostNetwork: true.
func (w *Workload) HostNetwork() bool { return w.hostNetwork }

// AutomountToken reports whether the SA token is mounted.
func (w *Workload) AutomountToken() Tri { return w.automountToken }

// Source returns where the workload was defined.
func (w *Workload) Source() *SourceLocation { s := w.source; return &s }

// WithoutHostNetwork returns a copy of w whose pods do not use the node's
// network namespace (remediation).
func (w *Workload) WithoutHostNetwork() *Workload {
	c := *w
	c.projected, c.defaulted = slices.Clone(w.projected), slices.Clone(w.defaulted)
	c.hostNetwork = false
	return &c
}

// WithoutTokenMount is w with automountServiceAccountToken: false.
func (w *Workload) WithoutTokenMount() *Workload {
	c := *w
	c.projected = slices.Clone(w.projected)
	c.defaulted = slices.DeleteFunc(slices.Clone(w.defaulted), func(d string) bool { return d == DefaultAutomountToken })
	c.automountToken = False
	return &c
}

// WithoutSecretRef is w whose pod spec no longer names Secret name.
func (w *Workload) WithoutSecretRef(name string) *Workload {
	c := *w
	c.projected = slices.Clone(w.projected)
	c.defaulted = slices.Clone(w.defaulted)
	c.secretRefs = slices.DeleteFunc(slices.Clone(w.secretRefs), func(s string) bool { return s == name })
	return &c
}

// TrustRelationship binds a role to its trust policy (a resource-based
// policy on the role).
type TrustRelationship struct {
	role   ID
	policy *PolicyDocument
}

// NewTrustRelationship links a role node to its trust policy.
func NewTrustRelationship(role ID, policy *PolicyDocument) *TrustRelationship {
	return &TrustRelationship{role: role, policy: policy}
}

// Role returns the role's node ID.
func (t *TrustRelationship) Role() ID { return t.role }

// Policy returns the trust policy.
func (t *TrustRelationship) Policy() *PolicyDocument { return t.policy }

// NetworkExposure records how a workload is reachable from outside.
type NetworkExposure struct {
	workload ID
	via      string // "Service/LoadBalancer", "Service/NodePort", "Ingress"
	public   Tri    // Unknown when e.g. an internal-LB annotation cannot be read
	source   SourceLocation
}

// NewNetworkExposure records an exposure of a workload.
func NewNetworkExposure(workload ID, via string, public Tri, src *SourceLocation) *NetworkExposure {
	return &NetworkExposure{workload: workload, via: via, public: public, source: *src}
}

// Workload returns the exposed workload's ID.
func (e *NetworkExposure) Workload() ID { return e.workload }

// Via names the exposing object kind.
func (e *NetworkExposure) Via() string { return e.via }

// Public reports whether the exposure is internet-facing.
func (e *NetworkExposure) Public() Tri { return e.public }

// Source returns where the exposure was defined.
func (e *NetworkExposure) Source() *SourceLocation { s := e.source; return &s }

// ClassUnclassified is the classification of a data store no rule
// classifies (classify.Unclassified, SCORING.md §1.2).
const ClassUnclassified = "unclassified"
