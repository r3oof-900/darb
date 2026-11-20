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
	KindEKSNodeGroup     NodeKind = "aws:eks:nodegroup"
)

// ID is a node's stable identifier: the lowercase hex SHA-256 of
// "clapa/v1", the kind and the canonical identity, separated by NUL bytes.
// Canonical identities are full ARNs (with partition and account) or
// "k8s:{cluster}/{namespace}/{kind}/{name}", so IDs never collide across
// accounts or clusters. See docs/DESIGN.md section 5.
type ID string

const idDomain = "clapa/v1"

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

// K8sIdentity builds the canonical identity of a Kubernetes object.
// Cluster-scoped objects use an empty namespace.
func K8sIdentity(cluster, namespace, kind, name string) string {
	return "k8s:" + cluster + "/" + namespace + "/" + kind + "/" + name
}
