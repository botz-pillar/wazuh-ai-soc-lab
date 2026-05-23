resource "aws_security_group" "sg_dev" {
  name        = "sg-dev"
  description = "Development server security group - UPDATED"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["98.45.172.0/24"]
  }

  ingress {
    description = "RDP from Priya home"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["98.45.172.88/32", "0.0.0.0/0"]
  }

  ingress {
    description = "App port from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "sg-dev"
    Environment = "development"
    ManagedBy   = "terraform"
  }
}
