resource "aws_iam_role" "payments_api" {
  name               = "payments-api"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

resource "aws_iam_role_policy" "payments_api" {
  name = "deploy-functions"
  role = aws_iam_role.payments_api.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "PassAnyRole", Effect = "Allow", Action = "iam:PassRole", Resource = "*" },
      { Sid = "ManageFunctions", Effect = "Allow", Action = ["lambda:CreateFunction", "lambda:InvokeFunction"], Resource = "*" },
    ]
  })
}
