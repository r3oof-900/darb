resource "aws_kms_key" "receipts" {
  description = "payment receipts"
}

resource "aws_s3_bucket" "receipts" {
  bucket = "acme-payment-receipts"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "receipts" {
  bucket = aws_s3_bucket.receipts.id
  rule {
    # S3 Bucket Key: the KMS encryption context is the bucket ARN (S3 User Guide, Encryption context).
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.receipts.arn
    }
  }
}
