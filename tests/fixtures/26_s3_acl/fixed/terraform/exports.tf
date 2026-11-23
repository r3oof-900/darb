# ACLs disabled (BucketOwnerEnforced): no ACL affects access to the data.
resource "aws_s3_bucket" "exports" {
  bucket = "acme-partner-exports"
  tags = {
    DataClass = "pii"
  }
}

resource "aws_s3_bucket_ownership_controls" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
