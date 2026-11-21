resource "aws_iam_role" "app" {
  name               = "app"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

resource "aws_iam_role_policy" "app" {
  name = "data-access"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ReadCustomerData", Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.customer_pii.arn}/*" },
      {
        Sid = "DecryptPII", Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.pii.arn
        Condition = { StringEquals = { "kms:EncryptionContext:aws:s3:arn" = var.pii_bucket_arn } }
      },
      { Sid = "UseOps", Effect = "Allow", Action = ["sts:AssumeRole"], Resource = aws_iam_role.ops.arn },
    ]
  })
}
