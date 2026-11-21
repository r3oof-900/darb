# Permissions for live collection

CLAPA only reads. `clapa scan --live-aws`, `clapa scan --live-k8s` and
`clapa collect-snapshot` call the APIs below and nothing else. The tests pin
the lists: `TestPermissionsDocument` (AWS) and `TestK8sPermissionsDocument`
(Kubernetes) fail when the code calls an API this page does not grant, and the
other way round.

**Values are never read.** CLAPA never calls `secretsmanager:GetSecretValue`,
`ssm:GetParameter*`, `s3:GetObject` or `kms:Decrypt`. A test fails if the
collector's source names any of them. Secret and parameter **metadata** is read:
names, ARNs, KMS keys, tags and resource policies.

## AWS

Use the minimal custom policy below. DESIGN.md §4.4 expects the AWS managed
policies `SecurityAudit` and `ViewOnlyAccess` together to be enough. That is
**not verified** against their current versions: the managed-policy snapshot
has not been refreshed yet (DESIGN.md §12.1). Until it is, the custom policy is
the one known to cover every call.

For several accounts, the caller assumes a role in each account that has the
same policy (`--aws-assume-role ARN`, repeatable), with `sts:AssumeRole` allowed
on those roles.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ClapaReadOnly",
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:DescribePodIdentityAssociation",
        "eks:ListClusters",
        "eks:ListPodIdentityAssociations",
        "iam:GetAccountAuthorizationDetails",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListKeys",
        "kms:ListResourceTags",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetEncryptionConfiguration",
        "s3:ListAllMyBuckets",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecrets",
        "ssm:DescribeParameters",
        "ssm:GetResourcePolicies",
        "ssm:ListTagsForResource",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

A KMS key policy that does not allow the caller `kms:GetKeyPolicy` or
`kms:DescribeKey` makes that key's policy unknown. This is recorded as an
`access-denied` coverage gap, never read as "no policy". The same holds for
every other call. A failed list call (for example `kms:ListKeys`) means CLAPA
does not know how many keys exist in that region, so coverage for that service
and region is unknown, never 100%.

Not collected yet, and stated in every report as `not-modelled`:

- account-level S3 Block Public Access (`s3:GetAccountPublicAccessBlock`). A
  bucket without its own setting is treated as not blocked, which can report a
  path the account setting would block. It never hides one.
- KMS grants (`kms:ListGrants`).
- AWS Organizations SCPs and RCPs.

## Kubernetes

A `ClusterRole` bound to the identity CLAPA uses. `get` on `configmaps` is
limited to `aws-auth`. Secrets are listed as metadata only: CLAPA requests
`PartialObjectMetadataList`, so the API server returns names, namespaces and
labels, never `data`. Kubernetes RBAC cannot grant "list metadata only", though:
`list` on secrets also allows a client that asks for full objects to read the
values. If that is not acceptable, leave out the `secrets` rule. CLAPA then
records an `access-denied` gap and does not treat Kubernetes Secrets as
targets.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: clapa-read-only
rules:
  - apiGroups: [""]
    resources: [namespaces, pods, serviceaccounts, services]
    verbs: [list]
  - apiGroups: [""]
    resources: [secrets]
    verbs: [list]
  - apiGroups: [""]
    resources: [configmaps]
    resourceNames: [aws-auth]
    verbs: [get]
  - apiGroups: [apps]
    resources: [daemonsets, deployments, replicasets, statefulsets]
    verbs: [list]
  - apiGroups: [batch]
    resources: [cronjobs, jobs]
    verbs: [list]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses, networkpolicies]
    verbs: [list]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [clusterrolebindings, clusterroles, rolebindings, roles]
    verbs: [list]
```

On EKS, CLAPA can authenticate with an in-memory token: a SigV4-presigned
`sts:GetCallerIdentity` URL carrying the `x-k8s-aws-id` header. This is the
token `aws eks get-token` prints. The identity must be mapped to a Kubernetes
group bound to the role above, either through an EKS access entry or through
`aws-auth`. The token is never written or logged.
