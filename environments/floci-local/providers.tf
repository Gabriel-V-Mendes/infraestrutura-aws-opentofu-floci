terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.70"
    }
  }

  # Configurado via `tofu init -backend-config=backend.hcl`
  backend "s3" {}
}

# Sem chaves estáticas no código! As credenciais temporárias (OIDC/STS ou sessão do emulador)
# são injetadas via variáveis de ambiente padrão (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN).
provider "aws" {
  region = var.aws_region

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    autoscaling    = var.floci_endpoint
    budgets        = var.floci_endpoint
    cloudwatch     = var.floci_endpoint
    ec2            = var.floci_endpoint
    elb            = var.floci_endpoint
    elbv2          = var.floci_endpoint
    iam            = var.floci_endpoint
    kms            = var.floci_endpoint
    rds            = var.floci_endpoint
    s3             = var.floci_endpoint
    secretsmanager = var.floci_endpoint
    sns            = var.floci_endpoint
    ssm            = var.floci_endpoint
    sts            = var.floci_endpoint
  }

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "OpenTofu"
      Emulator    = "Floci"
    }
  }
}
