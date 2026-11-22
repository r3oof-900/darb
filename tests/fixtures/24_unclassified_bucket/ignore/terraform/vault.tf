# A bucket nobody classified: no tags, no policy, no encryption
# configuration (SSE-S3 by default). Block Public Access is off, which
# DARB-POST-005 reports for a classified bucket only.
resource "aws_s3_bucket" "vault" {
  bucket = "patient-records-vault"
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
