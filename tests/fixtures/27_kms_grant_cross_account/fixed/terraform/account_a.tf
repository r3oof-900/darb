# Account A (111122223333): the PII bucket and its key. The key policy names
# only role/key-admin. The bucket policy lets role/reader of account B read
# the objects; the grant gives it Decrypt.
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["111122223333"]
}

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

resource "aws_s3_bucket_policy" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ReaderInAccountB"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::444455556666:role/reader" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.customer_pii.arn}/*"
    }]
  })
}

resource "aws_kms_grant" "reader" {
  name              = "reader-decrypt"
  key_id            = aws_kms_key.pii.arn
  grantee_principal = "arn:aws:iam::444455556666:role/reader"
  operations        = ["Decrypt"]
}
