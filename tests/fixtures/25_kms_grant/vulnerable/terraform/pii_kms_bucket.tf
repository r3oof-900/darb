# The PII key's policy names only the key administrator: no statement for
# payments-api, and no delegation to IAM (no account-root statement), so
# no IAM policy can let payments-api use the key.
resource "aws_kms_key" "pii" {
  description         = "customer PII"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "KeyAdministration"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::111122223333:role/key-admin" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
  tags = {
    DataClass = "pii"
  }
}

resource "aws_s3_bucket" "customer_pii" {
  bucket = "acme-customer-pii"
  tags = {
    DataClass = "pii"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.pii.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "customer_pii" {
  bucket                  = aws_s3_bucket.customer_pii.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
