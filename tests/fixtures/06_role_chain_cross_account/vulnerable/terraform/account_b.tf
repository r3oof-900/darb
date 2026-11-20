provider "aws" {
  alias               = "analytics"
  region              = "us-east-1"
  allowed_account_ids = ["444455556666"]
}

resource "aws_iam_role" "analytics_admin" {
  provider            = aws.analytics
  name                = "analytics-admin"
  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::111122223333:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_kms_key" "warehouse" {
  provider    = aws.analytics
  description = "warehouse"
}

resource "aws_s3_bucket" "warehouse" {
  provider = aws.analytics
  bucket   = "acme-analytics-warehouse"
  tags = {
    DataClass = "pii"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "warehouse" {
  provider = aws.analytics
  bucket   = aws_s3_bucket.warehouse.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.warehouse.arn
    }
  }
}
