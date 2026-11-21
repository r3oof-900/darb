package model

import "strings"

// DefaultClusterName names the cluster of Kubernetes input that names
// none and has no cluster in clapa.yaml (docs/DESIGN.md 5).
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
