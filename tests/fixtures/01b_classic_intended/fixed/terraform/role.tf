resource "aws_iam_role" "payments_api" {
  name               = "payments-api"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

resource "aws_iam_role_policy" "payments_api" {
  name = "data-access"
  role = aws_iam_role.payments_api.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      { Sid = "ReadCustomerData", Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.customer_pii.arn}/*" },
      { Sid = "ReadReceipts", Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.receipts.arn}/*" },
      { Sid = "DecryptAnything", Effect = "Allow", Action = ["kms:Decrypt"], Resource = [aws_kms_key.receipts.arn] },
    ]
  })
}
