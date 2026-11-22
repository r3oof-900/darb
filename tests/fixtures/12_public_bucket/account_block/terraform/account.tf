# The account's Block Public Access is on: S3 applies the most restrictive
# of the account's and the bucket's settings, so the bucket's own "off"
# no longer opens it (DESIGN.md 12.1, priority 2).
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
