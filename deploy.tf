terraform {
    required_providers {
      aws = {
        source  = "hashicorp/aws"
        version = "~> 4.16"
      }
    }
    required_version = ">= 1.2.0"
  }
  
  # Creating Elastic Container Repository for application
  resource "aws_ecr_repository" "my-ecr" {
    name = "my-ecr"
  }
  # Create IAM Role for EC2 to access ECR
resource "aws_iam_role" "ec2_role" {
  name               = "ec2-ecr-access-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach Policy for ECR Access to IAM Role
resource "aws_iam_policy" "ecr_policy" {
  name        = "ecr-access-policy"
  description = "Policy for EC2 to access ECR"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "ecr_policy_attach" {
    role       = aws_iam_role.ec2_role.name
    policy_arn = aws_iam_policy.ecr_policy.arn
  }
  
  # Create Instance Profile for EC2 Role
  resource "aws_iam_instance_profile" "ec2_instance_profile" {
    name = "ec2-instance-profile"
    role = aws_iam_role.ec2_role.name
  }
  resource "aws_instance" "instance" {
	ami           = "ami-0166fe664262f664c" 
	instance_type = "t2.micro"
    iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

	tags = {
		Name = "webserver"
	}
}