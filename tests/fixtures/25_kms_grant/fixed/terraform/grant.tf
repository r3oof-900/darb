# The grant is constrained to another bucket's encryption context: S3 sends
# the PII bucket's (or its objects') ARN, which never equals it.
resource "aws_kms_grant" "payments_api" {
  name              = "payments-api-decrypt"
  key_id            = aws_kms_key.pii.arn
  grantee_principal = aws_iam_role.payments_api.arn
  operations        = ["Decrypt"]
  constraints {
    encryption_context_equals = {
      "aws:s3:arn" = "arn:aws:s3:::acme-payment-receipts"
    }
  }
}
