# payments/api's own role: trust pinned to its service account.
resource "aws_iam_role" "payments_api" {
  name               = "payments-api"
  assume_role_policy = data.aws_iam_policy_document.payments_trust.json
}

data "aws_iam_policy_document" "payments_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["system:serviceaccount:payments:api"]
    }
  }
}

resource "aws_iam_role_policy" "payments_api" {
  name = "data-access"
  role = aws_iam_role.payments_api.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      { Sid = "ReadCustomerData", Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.customer_pii.arn}/*" },
      { Sid = "DecryptPII", Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.pii.arn },
    ]
  })
}
