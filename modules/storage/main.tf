terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# ==============================================================================
# KMS Customer Managed Key + S3 Bucket Blindado (Criptografia, Versionamento e
# Bloqueio Total de Acesso Público)
# ==============================================================================

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "main" {
  description             = "Chave KMS principal do projeto ${var.project_name} (${var.environment}) para S3, RDS, SNS e Secrets Manager"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowSNSAndCloudWatchToUseKey"
        Effect = "Allow"
        Principal = {
          Service = [
            "sns.amazonaws.com",
            "cloudwatch.amazonaws.com"
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-kms"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.project_name}-${var.environment}"
  target_key_id = aws_kms_key.main.key_id
}

# Justificativa trivy:ignore:AVD-AWS-0089: S3 Server Access Logging omitido por decisao FinOps para evitar provisionar um segundo bucket recursivo de logs de acesso no laboratorio; auditoria de chamadas S3 em producao e feita via AWS CloudTrail Data Events.
# trivy:ignore:AVD-AWS-0089
resource "aws_s3_bucket" "artifacts" {
  # checkov:skip=CKV_AWS_18:Access logging omitido para evitar bucket recursivo de logs na arquitetura economica; em producao usa-se CloudTrail Data Events.
  # checkov:skip=CKV_AWS_144:Cross-region replication desabilitado por design economico Single-Region (us-east-1).
  # checkov:skip=CKV2_AWS_62:Event notifications S3 omitidas pois o bucket armazena apenas artefatos estaticos e backups sem gatilho Lambda/SQS.
  bucket        = "${var.project_name}-${var.environment}-artifacts"
  force_destroy = var.force_destroy

  tags = {
    Name        = "${var.project_name}-${var.environment}-artifacts"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "cleanup-old-versions-and-incomplete-uploads"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts]
}
