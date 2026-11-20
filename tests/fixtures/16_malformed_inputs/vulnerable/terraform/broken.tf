resource "aws_iam_role" "half_written" {
  name = "half-written"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
