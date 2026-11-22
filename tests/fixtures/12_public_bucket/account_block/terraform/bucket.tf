# SSE-S3 (the S3 default): anonymous readers need no KMS permission.
resource "aws_s3_bucket" "marketing_leads" {
  bucket = "acme-marketing-leads"
  tags = {
    DataClass = "pii"
  }
}

resource "aws_s3_bucket_public_access_block" "marketing_leads" {
  bucket                  = aws_s3_bucket.marketing_leads.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "marketing_leads" {
  bucket = aws_s3_bucket.marketing_leads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.marketing_leads.arn}/*"
    }]
  })
}
