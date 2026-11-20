# Scenario 1 through EKS Pod Identity instead of IRSA: the trust policy the
# EKS User Guide documents ("Create the role"), pinned to payments/api by the
# session tags EKS adds, and the association of that service account.
data "aws_iam_policy_document" "pod_identity_trust" {
  statement {
    sid     = "AllowEksAuthToAssumeRoleForPodIdentity"
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-namespace"
      values   = ["payments"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes-service-account"
      values   = ["api"]
    }
  }
}

resource "aws_eks_pod_identity_association" "payments_api" {
  cluster_name    = "prod"
  namespace       = "payments"
  service_account = "api"
  role_arn        = aws_iam_role.payments_api.arn
}

resource "aws_eks_addon" "pod_identity_agent" {
  cluster_name = "prod"
  addon_name   = "eks-pod-identity-agent"
}
