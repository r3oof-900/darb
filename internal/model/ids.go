package model

import (
	"crypto/sha256"
	"encoding/hex"
)

// NodeKind names the kind of a canonical node. The kind is part of the ID,
// so two nodes of different kinds never share an ID.
type NodeKind string

// Node kinds known to the MVP. Providers add kinds without changing the core.
const (
	KindIAMRole          NodeKind = "aws:iam:role"
	KindIAMUser          NodeKind = "aws:iam:user"
	KindAccountRoot      NodeKind = "aws:iam:account-root"
	KindAWSService       NodeKind = "aws:service"
	KindAnonymous        NodeKind = "aws:anonymous"
	KindS3Bucket         NodeKind = "aws:s3:bucket"
	KindKMSKey           NodeKind = "aws:kms:key"
	KindSecret           NodeKind = "aws:secretsmanager:secret"
	KindSSMParameter     NodeKind = "aws:ssm:parameter"
	KindEC2Instance      NodeKind = "aws:ec2:instance"
	KindK8sServiceAcct   NodeKind = "k8s:serviceaccount"
	KindK8sUser          NodeKind = "k8s:user"
	KindK8sGroup         NodeKind = "k8s:group"
	KindK8sWorkload      NodeKind = "k8s:workload"
	KindK8sSecret        NodeKind = "k8s:secret"
	KindInternet         NodeKind = "net:internet"
	KindTerraformPending NodeKind = "tf:pending" // resource whose ARN is unknown until apply
	KindK8sNamespace     NodeKind = "k8s:namespace"
	// KindIAMRoleAnyPermission: a role whose policies an attacker can rewrite
	// (identity allows everything; its permissions boundary still applies).
	KindIAMRoleAnyPermission NodeKind = "aws:iam:role:any-permission"
	// Synthetic principals of the IAM escalations of users (item 4, after
	// v0.1.0-rc.1); each keeps the principal's ARN as its identity:
	// KindIAMUserAnyPermission, a user whose policies it can rewrite;
	// KindRewritten, a principal with every resource policy it can rewrite
	// (in its account) granting it; KindNoBoundary, a principal whose
	// permissions boundary is removed; KindPolicyVersion, a principal with
	// one of its managed policies at another stored version; KindInGroups, a
	// user in every group it can join; KindConsoleSession, a user signed in
	// to the console with a password someone else set.
	KindIAMUserAnyPermission NodeKind = "aws:iam:user:any-permission"
	KindRewritten            NodeKind = "aws:iam:principal:rewritten-resource-policies"
	KindNoBoundary           NodeKind = "aws:iam:principal:no-boundary"
	KindPolicyVersion        NodeKind = "aws:iam:principal:policy-version"
	KindInGroups             NodeKind = "aws:iam:user:in-groups"
	KindConsoleSession       NodeKind = "aws:iam:user:console-session"
	KindEKSNodeGroup         NodeKind = "aws:eks:nodegroup"
)

// ID is a node's stable identifier: the lowercase hex SHA-256 of
// "darb/v1", the kind and the canonical identity, separated by NUL bytes.
// Canonical identities are full ARNs (with partition and account) or
// "k8s:{cluster}/{namespace}/{kind}/{name}", so IDs never collide across
// accounts or clusters. See docs/DESIGN.md section 5.
type ID string

const idDomain = "darb/v1"

// NewID derives the ID of a node from its kind and canonical identity.
func NewID(kind NodeKind, canonical string) ID {
	h := sha256.New()
	h.Write([]byte(idDomain))
	h.Write([]byte{0})
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(canonical))
	return ID(hex.EncodeToString(h.Sum(nil)))
}

// K8sIdentity builds the canonical identity of a Kubernetes object;
// cluster is the cluster's key (ClusterKey: its ARN when known).
// Cluster-scoped objects use an empty namespace.
func K8sIdentity(cluster, namespace, kind, name string) string {
	return "k8s:" + cluster + "/" + namespace + "/" + kind + "/" + name
}
