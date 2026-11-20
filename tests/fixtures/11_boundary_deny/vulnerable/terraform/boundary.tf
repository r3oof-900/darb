resource "aws_iam_policy" "workload_boundary" {
  name = "workload-boundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "AllowEverythingElse", Effect = "Allow", Action = "*", Resource = "*" },
      { Sid = "NoCustomerData", Effect = "Deny", Action = "s3:GetObject", Resource = "arn:aws:s3:::acme-customer-pii/*" },
    ]
  })
}
