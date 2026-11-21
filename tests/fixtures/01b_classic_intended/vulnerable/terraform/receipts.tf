resource "aws_kms_key" "receipts" {
  description = "payment receipts"
}

resource "aws_s3_bucket" "receipts" {
  bucket = "acme-payment-receipts"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "receipts" {
  bucket = aws_s3_bucket.receipts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.receipts.arn
    }
  }
}

# Block Public Access, declared so that the scan has no coverage gap for
# this bucket (Phase 5 review: fixtures state the setting instead of a
# raised gap tolerance).
resource "aws_s3_bucket_public_access_block" "receipts" {
  bucket                  = aws_s3_bucket.receipts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
