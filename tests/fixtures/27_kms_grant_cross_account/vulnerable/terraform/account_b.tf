# Account B (444455556666): the cluster's IRSA role. It may read the PII
# objects and has no kms permission of its own.
provider "aws" {
  alias               = "b"
  region              = "us-east-1"
  allowed_account_ids = ["444455556666"]
}

locals {
  oidc_host = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
}

resource "aws_iam_role" "reader" {
  provider = aws.b
  name     = "reader"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::444455556666:oidc-provider/${local.oidc_host}" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_host}:sub" = "system:serviceaccount:payments:api"
          "${local.oidc_host}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "reader" {
  provider = aws.b
  name     = "read-pii"
  role     = aws_iam_role.reader.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      { Sid = "ReadCustomerData", Effect = "Allow", Action = ["s3:GetObject"], Resource = "arn:aws:s3:::acme-customer-pii/*" },
    ]
  })
}
