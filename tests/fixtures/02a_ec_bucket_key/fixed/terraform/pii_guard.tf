resource "aws_s3_bucket_policy" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid          = "OnlyTheReporterRole"
      Effect       = "Deny"
      NotPrincipal = { AWS = ["arn:aws:iam::111122223333:role/pii-reporter", "arn:aws:sts::111122223333:assumed-role/pii-reporter/reporting", "111122223333"] }
      Action       = "s3:*"
      Resource     = ["${aws_s3_bucket.customer_pii.arn}", "${aws_s3_bucket.customer_pii.arn}/*"]
    }]
  })
}
