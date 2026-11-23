# The grant gives payments-api kms:Decrypt on the PII key, with no
# encryption-context constraint.
resource "aws_kms_grant" "payments_api" {
  name              = "payments-api-decrypt"
  key_id            = aws_kms_key.pii.arn
  grantee_principal = aws_iam_role.payments_api.arn
  operations        = ["Decrypt"]
}
