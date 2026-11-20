resource "aws_iam_policy" "workload_boundary" {
  name = "workload-boundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "OnlyQueuesAndLogs", Effect = "Allow", Action = ["sqs:*", "logs:*"], Resource = "*" },
    ]
  })
}
