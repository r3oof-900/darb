provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "k" {
  description = "secrets"
}

resource "aws_secretsmanager_secret" "db" {
  name       = "prod/db"
  kms_key_id = aws_kms_key.k.arn
  tags       = { DataClass = "secret" }
}

resource "aws_secretsmanager_secret_policy" "db" {
  secret_arn = aws_secretsmanager_secret.db.arn
  policy     = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Deny", Principal = "*", Action = "secretsmanager:DeleteSecret", Resource = "*" }] })
}

resource "aws_secretsmanager_secret" "plain" {
  name = "prod/plain"
}

resource "aws_ssm_parameter" "secure" {
  name  = "/prod/db/password"
  type  = "SecureString"
  value = "dummy"
}

resource "aws_ssm_parameter" "url" {
  name  = "/prod/url"
  type  = "String"
  value = "https://example.com"
}
