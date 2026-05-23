resource "aws_iam_role" "backup_agent" {
  name = "cloudvault-backup-agent"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name      = "Backup Agent Role"
    ManagedBy = "terraform"
  }
}

resource "aws_iam_role_policy" "backup_agent_s3" {
  name = "backup-agent-s3-access"
  role = aws_iam_role.backup_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BackupAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::cloudvault-backups",
          "arn:aws:s3:::cloudvault-backups/*",
          "arn:aws:s3:::cloudvault-client-docs",
          "arn:aws:s3:::cloudvault-client-docs/*"
        ]
      }
    ]
  })
}
