provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["111122223333"]
}

locals {
  oidc_host     = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
  oidc_provider = "arn:aws:iam::111122223333:oidc-provider/${local.oidc_host}"
}
