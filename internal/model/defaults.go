package model

import (
	"slices"
	"strings"
)

// A setting the input does not state takes its documented default only when
// that default is deterministic; the node then lists the default's key in
// its Defaulted settings, and evidence says "value_source: default" with the
// reference below. Settings without a deterministic default (IMDS, S3 Block
// Public Access) stay unknown and are coverage gaps (docs/DESIGN.md §4.7).

// Keys of documented defaults.
const (
	DefaultAutomountToken    = "k8s.automountServiceAccountToken" //nolint:gosec // G101: a table key, not a credential
	DefaultHostNetwork       = "k8s.hostNetwork"
	DefaultPrivileged        = "k8s.securityContext.privileged"
	DefaultIRSAAudience      = "eks.irsa.audience"
	DefaultKeyRotationTF     = "terraform.aws_kms_key.enable_key_rotation"
	DefaultKeyPolicy         = "kms.default-key-policy"
	DefaultS3Encryption      = "s3.default-encryption"
	DefaultPodIdentitySTags  = "eks.pod-identity.disableSessionTags"
	DefaultUnsetRoleBindings = "terraform.aws_iam_role.managed_policy_arns"
)

// DocumentedDefault is one deterministic default and where it is documented.
type DocumentedDefault struct {
	Key       string
	Setting   string
	Value     string
	Reference string // documentation URL
	Quote     string // the sentence that states it (short)
}

// DocumentedDefaults returns the table, sorted by key. Each row was read on
// its page on 2026-11-20.
func DocumentedDefaults() []DocumentedDefault {
	t := []DocumentedDefault{
		{
			DefaultAutomountToken, "Pod and ServiceAccount automountServiceAccountToken (the Pod's value wins)", "true",
			"https://kubernetes.io/docs/concepts/security/service-accounts/",
			"By default, Kubernetes provides the Pod with the credentials for an assigned ServiceAccount",
		},
		{
			DefaultHostNetwork, "PodSpec hostNetwork", "false",
			"https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/",
			"Host networking requested for this pod. [...] Default to false.",
		},
		{
			DefaultPrivileged, "container securityContext.privileged", "false",
			"https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/",
			"Run container in privileged mode. [...] Defaults to false.",
		},
		{
			DefaultIRSAAudience, "ServiceAccount annotation eks.amazonaws.com/audience", "sts.amazonaws.com",
			"https://github.com/aws/amazon-eks-pod-identity-webhook",
			`optional: Defaults to "sts.amazonaws.com" if not set`,
		},
		{
			DefaultKeyRotationTF, "Terraform aws_kms_key enable_key_rotation", "false",
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key",
			"Whether key rotation is enabled. Defaults to `false`.",
		},
		{
			DefaultKeyPolicy, "KMS key created without a key policy", "the default key policy: account root, kms:*",
			"https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html",
			"AWS KMS applies a very simple default key policy.",
		},
		{
			DefaultS3Encryption, "S3 bucket without a default encryption configuration", "SSE-S3 (AES256)",
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
			"applies server-side encryption with Amazon S3 managed keys (SSE-S3) as the base level of encryption for every bucket",
		},
		{
			DefaultPodIdentitySTags, "Pod Identity association disableSessionTags", "false",
			"https://docs.aws.amazon.com/eks/latest/APIReference/API_CreatePodIdentityAssociation.html",
			"Disable the automatic sessions tags that are appended by EKS Pod Identity.",
		},
		{
			DefaultUnsetRoleBindings, "Terraform aws_iam_role managed_policy_arns and inline_policy, not configured", "no attachments added",
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role",
			"If this attribute is not configured, Terraform will ignore policy attachments to this resource.",
		},
	}
	slices.SortFunc(t, func(a, b DocumentedDefault) int { return strings.Compare(a.Key, b.Key) })
	return t
}

// LookupDefault returns the documented default for key.
func LookupDefault(key string) (DocumentedDefault, bool) {
	for _, d := range DocumentedDefaults() {
		if d.Key == key {
			return d, true
		}
	}
	return DocumentedDefault{}, false
}
