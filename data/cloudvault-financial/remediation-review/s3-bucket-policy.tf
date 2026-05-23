resource "aws_s3_bucket" "client_docs" {
  bucket = "cloudvault-client-docs"

  tags = {
    Name        = "Client Documents"
    Environment = "production"
    Sensitivity = "high"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "client_docs" {
  bucket = aws_s3_bucket.client_docs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket" "app_assets" {
  bucket = "cloudvault-app-assets"

  tags = {
    Name        = "Application Assets"
    Environment = "production"
    Sensitivity = "low"
  }
}

resource "aws_s3_bucket_policy" "app_assets_public" {
  bucket = aws_s3_bucket.app_assets.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.app_assets.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket" "backups" {
  bucket = "cloudvault-backups"

  tags = {
    Name        = "Database Backups"
    Environment = "production"
    Sensitivity = "high"
  }
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}
