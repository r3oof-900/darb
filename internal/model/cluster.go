package model

import "strings"

// DefaultClusterName names the cluster of Kubernetes input that names
// none and has no cluster in darb.yaml (docs/DESIGN.md 5).
const DefaultClusterName = "default"

// EKSClusterARN returns the ARN of an EKS cluster, or "" when the account,
// region or name is not known (empty or unresolved).
func EKSClusterARN(partition, region, account, name string) string {
	if partition == "" {
		partition = "aws"
	}
	if region == "" || account == "" || name == "" ||
		ContainsUnresolved(region) || ContainsUnresolved(account) || ContainsUnresolved(name) {
		return ""
	}
	return "arn:" + partition + ":eks:" + region + ":" + account + ":cluster/" + name
}

// IsClusterARN reports whether s is an EKS cluster ARN.
func IsClusterARN(s string) bool {
	parts := strings.SplitN(s, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[2] == "eks" && strings.HasPrefix(parts[5], "cluster/")
}

// ClusterKey is the identity of a cluster in every Kubernetes identity
// ("k8s:{key}/{namespace}/{kind}/{name}") and in every cluster reference:
// the cluster's ARN when it is known, otherwise its name. Two clusters with
// one name in two regions or accounts have two keys, so their objects
// never collide.
func ClusterKey(arn, name string) string {
	if arn != "" && !ContainsUnresolved(arn) {
		return arn
	}
	return name
}

// Key is the cluster's ClusterKey.
func (c *Cluster) Key() string { return ClusterKey(c.ARN, c.Name) }

// EncryptionContextKey is the KMS condition key that names the protected
// resource arn in the encryption context its service sends: SecretARN for
// Secrets Manager, PARAMETER_ARN for Parameter Store, aws:s3:arn for S3
// (their user guides' "encryption context" sections; DESIGN.md 7.3).
func EncryptionContextKey(arn string) string {
	switch {
	case strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":secretsmanager:"):
		return "kms:EncryptionContext:SecretARN"
	case strings.HasPrefix(arn, "arn:") && strings.Contains(arn, ":ssm:") && strings.Contains(arn, ":parameter/"):
		return "kms:EncryptionContext:PARAMETER_ARN"
	}
	return "kms:EncryptionContext:aws:s3:arn"
}
