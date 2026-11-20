resource "aws_kms_key" "shared" {
  description = "shared org key"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Admins", Effect = "Allow", Principal = { AWS = "arn:aws:iam::111122223333:root" }, Action = ["kms:Create*", "kms:Describe*", "kms:Put*"], Resource = "*" },
      {
        Sid       = "OrgDecrypt"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::111122223333:role/pii-reporter" }
        Action    = "kms:Decrypt"
        Resource  = "*"
      },
    ]
  })
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
      kms_master_key_id = aws_kms_key.shared.arn
    }
  }
}

resource "aws_iam_role" "payments_api" {
  name               = "payments-api"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

resource "aws_iam_role_policy" "payments_api" {
  name = "read-pii"
  role = aws_iam_role.payments_api.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.customer_pii.arn}/*" }]
  })
}
