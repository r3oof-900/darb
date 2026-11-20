resource "aws_eks_cluster" "prod" {
  name     = "prod"
  role_arn = "arn:aws:iam::111122223333:role/eks-cluster"
  vpc_config {
    subnet_ids = ["subnet-0a1b2c3d", "subnet-4e5f6a7b"]
  }
}

resource "aws_iam_role" "node" {
  name = "eks-node"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "node_reads_everything" {
  name = "read-all-objects"
  role = aws_iam_role.node.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }]
  })
}

resource "aws_launch_template" "nodes" {
  name = "eks-nodes"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.prod.name
  node_group_name = "default"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = ["subnet-0a1b2c3d"]
  launch_template {
    id      = aws_launch_template.nodes.id
    version = "1"
  }
  scaling_config {
    desired_size = 3
    max_size     = 5
    min_size     = 1
  }
}

# SSE-S3 (the S3 default): reading the objects needs no KMS permission.
resource "aws_s3_bucket" "exports" {
  bucket = "acme-customer-exports"
  tags = {
    DataClass = "pii"
  }
}
