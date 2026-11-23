# ACLs enabled (ObjectWriter) and a public-read bucket ACL. Block Public
# Access stops public bucket policies but neither blocks nor ignores public
# ACLs. SSE-S3 by default; no bucket policy.
resource "aws_s3_bucket" "exports" {
  bucket = "acme-partner-exports"
  tags = {
    DataClass = "pii"
  }
}

resource "aws_s3_bucket_ownership_controls" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    object_ownership = "ObjectWriter"
  }
}

resource "aws_s3_bucket_acl" "exports" {
  depends_on = [aws_s3_bucket_ownership_controls.exports]
  bucket     = aws_s3_bucket.exports.id
  acl        = "public-read"
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = false
  restrict_public_buckets = true
}
