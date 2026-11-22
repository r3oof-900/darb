resource "aws_iam_role" "exporter" {
  name               = "records-exporter"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

resource "aws_iam_role_policy" "exporter" {
  name = "vault-access"
  role = aws_iam_role.exporter.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      { Sid = "ReadVault", Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.vault.arn}/*" },
    ]
  })
}
