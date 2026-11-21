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
      { Sid = "ListBuckets", Effect = "Allow", Action = ["s3:ListAllMyBuckets"], Resource = "*" },
    ]
  })
}
