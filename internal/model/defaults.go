package model

import (
	"slices"
	"strings"
)

// A setting the input does not state takes its documented default only when
// that default is deterministic; the node then lists the default's key in
// its Defaulted settings, and evidence says "value_source: default" with the
// reference below. Settings without a deterministic default (IMDS; S3 Block
// Public Access of a bucket that already exists) stay unknown and are
// coverage gaps (docs/DESIGN.md §4.7).

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
	DefaultNetPolTypes       = "k8s.networkPolicy.policyTypes"
	DefaultOIDCAudience      = "eks.irsa.oidc-provider-audience"
	DefaultS3NewBucketBPA    = "s3.block-public-access.new-bucket"
	DefaultS3NewBucketACLs   = "s3.object-ownership.new-bucket"
	DefaultAWSManagedKeyRot  = "kms.aws-managed-key.rotation"
	DefaultSecretsManagedKey = "secretsmanager.aws-managed-key"
	DefaultSSMManagedKey     = "ssm.aws-managed-key"
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
	t := append(kubernetesDefaults(), awsDefaults()...)
	slices.SortFunc(t, func(a, b DocumentedDefault) int { return strings.Compare(a.Key, b.Key) })
	return t
}

// kubernetesDefaults: Kubernetes and EKS settings.
func kubernetesDefaults() []DocumentedDefault {
	return []DocumentedDefault{
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
			DefaultPodIdentitySTags, "Pod Identity association disableSessionTags", "false",
			"https://docs.aws.amazon.com/eks/latest/APIReference/API_CreatePodIdentityAssociation.html",
			"Disable the automatic sessions tags that are appended by EKS Pod Identity.",
		},
		{
			DefaultOIDCAudience, "client IDs (audiences) of a cluster's IAM OIDC provider that is not in the input", "sts.amazonaws.com",
			"https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html",
			"For Audience, enter sts.amazonaws.com.",
		},
		{
			DefaultNetPolTypes, "NetworkPolicy policyTypes", "includes Ingress",
			"https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/",
			"all policies (whether or not they contain an ingress section) are assumed to affect ingress",
		},
	}
}

// awsDefaults: AWS and Terraform settings.
func awsDefaults() []DocumentedDefault {
	return []DocumentedDefault{
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
			// Only for a bucket a plan creates: the setting of an existing
			// bucket may have been changed outside the input.
			DefaultS3NewBucketBPA, "S3 Block Public Access of a bucket a Terraform plan creates, with no aws_s3_bucket_public_access_block",
			"all four settings on (restrict_public_buckets = true)",
			"https://aws.amazon.com/blogs/aws/heads-up-amazon-s3-security-changes-are-coming-in-april-of-2023/",
			"newly created buckets [...] will by default have S3 Block Public Access enabled",
		},
		{
			// Only for a bucket a plan creates, as above. Read on 2026-11-22;
			// the What's New post of 2022-12-13 says the April 2023 defaults
			// "apply to all new buckets regardless of how they are created,
			// including AWS CLI, APIs, SDKs, and AWS CloudFormation".
			DefaultS3NewBucketACLs, "S3 Object Ownership of a bucket a Terraform plan creates, with no aws_s3_bucket_ownership_controls",
			"BucketOwnerEnforced (ACLs disabled)",
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html",
			"For newly created buckets, ACLs are disabled by default.",
		},
		{
			// Read on 2026-11-21. The account cannot change it, so it is
			// deterministic for every AWS managed key.
			DefaultAWSManagedKeyRot, "rotation of an AWS managed KMS key (KeyManager AWS)", "true (every year)",
			"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
			"AWS KMS automatically rotates AWS managed keys every year",
		},
		{
			// Read on 2026-11-21.
			DefaultSecretsManagedKey, "Secrets Manager secret encrypted with the AWS managed key aws/secretsmanager",
			"principals of the secret's account may decrypt through Secrets Manager; no other account",
			"https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html",
			"only when Secrets Manager makes the request on the user's behalf",
		},
		{
			// Read on 2026-11-21.
			DefaultSSMManagedKey, "SSM SecureString parameter encrypted with the AWS managed key aws/ssm",
			"every IAM principal of the parameter's account may decrypt; no other account",
			"https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-access.html",
			"has Decrypt permission for all IAM principals within the AWS account",
		},
		{
			DefaultUnsetRoleBindings, "Terraform aws_iam_role managed_policy_arns and inline_policy, not configured", "no attachments added",
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role",
			"If this attribute is not configured, Terraform will ignore policy attachments to this resource.",
		},
	}
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
