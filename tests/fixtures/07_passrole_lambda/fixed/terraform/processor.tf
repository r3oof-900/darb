resource "aws_iam_role" "data_processor" {
  name = "data-processor"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "data_processor" {
  name = "read-pii"
  role = aws_iam_role.data_processor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.customer_pii.arn}/*" },
      { Effect = "Allow", Action = "kms:Decrypt", Resource = aws_kms_key.pii.arn },
    ]
  })
}
