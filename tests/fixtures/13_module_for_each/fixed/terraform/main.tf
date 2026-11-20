module "readers" {
  source = "./modules/readers"
  names  = ["etl", "bi", "ml"]
  bucket = "acme-analytics-public"
}

resource "aws_s3_bucket" "customer_pii" {
  bucket = "acme-customer-pii"
  tags = {
    DataClass = "pii"
  }
}
