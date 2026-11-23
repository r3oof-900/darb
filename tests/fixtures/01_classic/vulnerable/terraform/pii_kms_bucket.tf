resource "aws_kms_key" "pii" {
  description         = "customer PII"
  enable_key_rotation = true
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

# Object Ownership stated (ACLs disabled), as Block Public Access is: a
# bucket read statically has no default for either (DESIGN.md 4.7).
resource "aws_s3_bucket_ownership_controls" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
