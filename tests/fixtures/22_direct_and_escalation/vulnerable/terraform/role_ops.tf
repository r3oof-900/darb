resource "aws_iam_role" "ops" {
  name = "ops"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = aws_iam_role.app.arn }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "ops" {
  name = "ops"
  role = aws_iam_role.ops.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "RewriteSelf", Effect = "Allow", Action = ["iam:PutRolePolicy"], Resource = "arn:aws:iam::111122223333:role/ops" },
    ]
  })
}
