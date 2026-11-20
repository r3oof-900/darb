provider "aws" {
  region = "eu-west-1"
}

variable "extra_policy" {}

resource "aws_iam_role" "app" {
  name               = "app"
  path               = "/svc/"
  assume_role_policy = data.aws_iam_policy_document.trust.json
  inline_policy {
    name   = "inline-unknown"
    policy = var.extra_policy
  }
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/NotInTheSnapshot",
    aws_iam_policy.custom.arn,
    "arn:aws:iam::999999999999:policy/elsewhere",
  ]
  permissions_boundary = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_policy" "custom" {
  name   = "custom"
  policy = <<EOT
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "${aws_secretsmanager_secret.db.arn}"},
 {"Effect": "Allow", "Action": "ssm:GetParameter", "Resource": "${aws_ssm_parameter.token.arn}"},
 {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*", "Condition": {"StringEquals": {"kms:CallerAccount": "${aws_kms_key.k.key_id}"}}}]}
EOT
}

resource "aws_iam_policy" "broken" {
  name   = "broken"
  policy = "{\"Version\": \"2012-10-17\", \"Statement\": [ oops ]}"
}

resource "aws_iam_policy_attachment" "both" {
  name       = "both"
  roles      = [aws_iam_role.app.name, "not-defined-here"]
  policy_arn = aws_iam_policy.broken.arn
}

resource "aws_iam_role_policy_attachment" "custom" {
  role       = "app"
  policy_arn = aws_iam_policy.custom.arn
}

data "aws_iam_policy_document" "trust" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]
  statement {
    sid     = "Anyone"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
  statement {
    effect  = "Deny"
    actions = ["sts:AssumeRole"]
    not_principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111122223333:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

data "aws_iam_policy_document" "base" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "k" {
  description = "k"
  policy      = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "kms:*", Resource = "*" }] })
}

resource "aws_secretsmanager_secret" "db" {
  name = "db-password"
}

resource "aws_ssm_parameter" "token" {
  name  = "/app/token"
  type  = "SecureString"
  value = "not-a-real-secret"
}

resource "aws_s3_bucket_policy" "orphan" {
  bucket = "bucket-not-in-input"
  policy = "{}"
}

resource "aws_eks_cluster" "c" {
  name     = "c"
  role_arn = "arn:aws:iam::111122223333:role/cluster"
}

resource "aws_eks_pod_identity_association" "api" {
  cluster_name    = aws_eks_cluster.c.name
  namespace       = "payments"
  service_account = "api"
  role_arn        = aws_iam_role.app.arn
}

resource "aws_eks_node_group" "bare" {
  cluster_name    = "c"
  node_group_name = "bare"
  node_role_arn   = "arn:aws:iam::111122223333:role/node"
}

resource "aws_iam_openid_connect_provider" "eks" {
  url = "https://oidc.eks.eu-west-1.amazonaws.com/id/XYZ"
}

resource "aws_iam_role_policy" "oidc_ref" {
  role   = aws_iam_role.app.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "iam:GetOpenIDConnectProvider", Resource = aws_iam_openid_connect_provider.eks.arn }] })
}
