# etl/etl-job's own role. Its data access is declared intended.
resource "aws_iam_role" "etl_reader" {
  name               = "etl-reader"
  assume_role_policy = data.aws_iam_policy_document.etl_trust.json
}

data "aws_iam_policy_document" "etl_trust" {
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
      values   = ["system:serviceaccount:etl:etl-runner"]
    }
  }
}

resource "aws_iam_role_policy" "etl_reader" {
  name = "data-access"
  role = aws_iam_role.etl_reader.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      { Sid = "ReadCustomerData", Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.customer_pii.arn}/*" },
      { Sid = "DecryptPII", Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.pii.arn },
    ]
  })
}
