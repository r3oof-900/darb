provider "aws" {
  region              = var.region
  allowed_account_ids = ["111122223333"]
}

provider "aws" {
  alias  = "east"
  region = "us-east-1"
}

variable "region" {
  default = "eu-west-1"
}

variable "bucket" {} # no default and not in tfvars: unresolved

variable "team" {
  default = "unset"
}

locals {
  prefix = "${local.org}-${var.team}"
  org    = "acme"
}

resource "aws_kms_key" "pii" {
  description         = "pii"
  enable_key_rotation = true
}

resource "aws_iam_role_policy" "decrypt" {
  name = "${local.prefix}-decrypt"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = aws_kms_key.pii.arn
    }, {
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "arn:aws:s3:::${var.bucket}/*"
    }]
  })
}

resource "aws_iam_role" "app" {
  name               = upper(local.prefix)
  assume_role_policy = <<EOT
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "${aws_iam_role.other.arn}"}, "Action": "sts:AssumeRole"}]}
EOT
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.eks.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc}:sub"
      values   = ["system:serviceaccount:payments:api"]
    }
  }
}

resource "aws_iam_role" "many" {
  for_each = toset(["a", "b"])
  name     = each.value
  provider = aws.east
}

resource "aws_s3_bucket" "dyn" {
  bucket = "dyn"
  dynamic "grant" {
    for_each = []
    content {}
  }
  lifecycle {
    prevent_destroy = true
  }
}

module "roles" {
  source = "./roles"
}
