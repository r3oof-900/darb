# A bucket nobody classified: no tags, no policy, no public access block,
# no encryption configuration (SSE-S3 by default).
resource "aws_s3_bucket" "vault" {
  bucket = "patient-records-vault"
}
