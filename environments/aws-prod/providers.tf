terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.70"
    }
  }

  backend "s3" {}
}

# Autenticado 100% via GitHub Actions OIDC (aws-actions/configure-aws-credentials)
# Zero chaves estáticas no código ou nos Secrets do GitHub!
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "OpenTofu"
    }
  }
}
