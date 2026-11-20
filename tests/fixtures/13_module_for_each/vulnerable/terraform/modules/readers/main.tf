variable "names" {
  type = list(string)
}

variable "bucket" {
  type = string
}

resource "aws_iam_role" "r" {
  for_each = toset(var.names)
  name     = "reader-${each.value}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = { "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:sub" = "system:serviceaccount:analytics:${each.value}" } }
    }]
  })
}

resource "aws_iam_role_policy" "read" {
  for_each = toset(var.names)
  name     = "read"
  # each.key (= each.value for a set): a plan records only ["aws_iam_role.r", "each.key"],
  # which names this instance's own key. See docs/DESIGN.md §4.6.
  role     = aws_iam_role.r[each.key].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::${var.bucket}/*" }]
  })
}
