# The bucket's key is not in the input (Phase 6 review, item 2): its key policy is unknown.
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
      kms_master_key_id = "arn:aws:kms:us-east-1:111122223333:key/0b1c2d3e-0000-4000-8000-000000000001"
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
