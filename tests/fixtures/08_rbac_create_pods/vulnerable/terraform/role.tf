resource "aws_iam_role" "payments_api" {
  name               = "payments-api"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

resource "aws_iam_role_policy" "payments_api" {
  name = "read-pii"
  role = aws_iam_role.payments_api.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.customer_pii.arn}/*" },
      { Effect = "Allow", Action = "kms:Decrypt", Resource = aws_kms_key.pii.arn },
    ]
  })
}
