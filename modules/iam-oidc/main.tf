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
# Autenticação GitHub Actions na AWS por OIDC (Zero Chaves Estáticas!)
# + Instance Profile de menor privilégio para a instância EC2 da API FastAPI
# ==============================================================================

data "aws_caller_identity" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  name_prefix = "${var.project_name}-${var.environment}"
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = {
    Name        = "${local.name_prefix}-github-oidc"
    Environment = var.environment
  }
}

resource "aws_iam_role" "github_actions_oidc" {
  name        = "${local.name_prefix}-gha-oidc-role"
  description = "Role assumida pelo GitHub Actions via OIDC restrita exclusivamente a ref:refs/heads/main e environment:production"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GitHubActionsOIDCFederationMainAndProdOnly"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_actions.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
            "token.actions.githubusercontent.com:sub" = [
              "repo:${var.github_repository}:ref:refs/heads/main",
              "repo:${var.github_repository}:environment:production"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${local.name_prefix}-gha-oidc-role"
    Environment = var.environment
  }
}

# Justificativa trivy:ignore:AVD-AWS-0057: Apenas as operacoes de leitura (Describe*/List*) e criacao inicial de rede/KMS (ec2:Create*, kms:CreateKey) que a API da AWS nao permite restringir por ARN antes do recurso existir usam Resource "*"; todas as acoes de escrita/delecao estao explicitamente listadas (sem curingas ec2:*, rds:*, kms:* ou secretsmanager:*) e limitadas por ARN do projeto ou Condition aws:ResourceTag/aws:RequestTag.
# trivy:ignore:AVD-AWS-0057
resource "aws_iam_role_policy" "github_actions_iac" {
  # checkov:skip=CKV_AWS_290:As acoes de criacao inicial (ec2:CreateVpc, ec2:CreateSubnet, ec2:CreateSecurityGroup, kms:CreateKey) exigem Resource '*' na API AWS, mas sao condicionadas a aws:RequestTag/Environment.
  # checkov:skip=CKV_AWS_355:Apenas acoes Describe*/List* e Create* sem suporte a resource-level permissions na AWS usam Resource '*'; RDS, KMS, Secrets Manager, SSM, S3, SNS, CloudWatch, Budgets, ALB e ASG estao restritos por ARN ou tag.
  name = "${local.name_prefix}-gha-iac-policy"
  role = aws_iam_role.github_actions_oidc.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowStateBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::${var.state_bucket_name}",
          "arn:aws:s3:::${var.state_bucket_name}/*"
        ]
      },
      {
        Sid    = "AllowProjectBucketsManagementByARN"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:ListBucket",
          "s3:GetBucketVersioning",
          "s3:PutBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:PutEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetLifecycleConfiguration",
          "s3:PutLifecycleConfiguration",
          "s3:GetBucketTagging",
          "s3:PutBucketTagging",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:GetBucketCORS",
          "s3:GetBucketWebsite",
          "s3:GetBucketLogging",
          "s3:GetAccelerateConfiguration",
          "s3:GetBucketRequestPayment",
          "s3:GetBucketObjectLockConfiguration",
          "s3:GetReplicationConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-*"
        ]
      },
      {
        Sid    = "AllowRDSManagementScopedByARN"
        Effect = "Allow"
        Action = [
          "rds:CreateDBSubnetGroup",
          "rds:DeleteDBSubnetGroup",
          "rds:ModifyDBSubnetGroup",
          "rds:DescribeDBSubnetGroups",
          "rds:CreateDBInstance",
          "rds:DeleteDBInstance",
          "rds:ModifyDBInstance",
          "rds:DescribeDBInstances",
          "rds:AddTagsToResource",
          "rds:ListTagsForResource",
          "rds:RemoveTagsFromResource"
        ]
        Resource = [
          "arn:aws:rds:*:${local.account_id}:subgrp:${local.name_prefix}-*",
          "arn:aws:rds:*:${local.account_id}:db:${local.name_prefix}-*"
        ]
      },
      {
        Sid    = "AllowSecretsAndSSMScopedByARN"
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:DeleteSecret",
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecret",
          "secretsmanager:TagResource",
          "secretsmanager:GetResourcePolicy",
          "ssm:PutParameter",
          "ssm:DeleteParameter",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:DescribeParameters",
          "ssm:AddTagsToResource",
          "ssm:ListTagsForResource"
        ]
        Resource = [
          "arn:aws:secretsmanager:*:${local.account_id}:secret:${local.name_prefix}-*",
          "arn:aws:ssm:*:${local.account_id}:parameter/${var.project_name}/${var.environment}/*"
        ]
      },
      {
        Sid    = "AllowKMSScopedByKeyAndAliasARN"
        Effect = "Allow"
        Action = [
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:ListResourceTags",
          "kms:PutKeyPolicy",
          "kms:EnableKeyRotation",
          "kms:ScheduleKeyDeletion",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant",
          "kms:CreateAlias",
          "kms:DeleteAlias",
          "kms:UpdateAlias"
        ]
        Resource = [
          var.kms_key_arn,
          "arn:aws:kms:*:${local.account_id}:alias/${local.name_prefix}*"
        ]
      },
      {
        Sid    = "AllowFinOpsAndObservabilityScopedByARN"
        Effect = "Allow"
        Action = [
          "sns:CreateTopic",
          "sns:DeleteTopic",
          "sns:GetTopicAttributes",
          "sns:SetTopicAttributes",
          "sns:Subscribe",
          "sns:Unsubscribe",
          "sns:GetSubscriptionAttributes",
          "sns:ListTagsForResource",
          "sns:TagResource",
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:ListTagsForResource",
          "cloudwatch:TagResource",
          "budgets:CreateBudget",
          "budgets:ModifyBudget",
          "budgets:DeleteBudget",
          "budgets:ViewBudget",
          "budgets:DescribeBudget",
          "budgets:DescribeNotificationsForBudget",
          "budgets:DescribeSubscribersForNotification"
        ]
        Resource = [
          "arn:aws:sns:*:${local.account_id}:${local.name_prefix}-*",
          "arn:aws:cloudwatch:*:${local.account_id}:alarm:${local.name_prefix}-*",
          "arn:aws:budgets::${local.account_id}:budget/${local.name_prefix}-*"
        ]
      },
      {
        Sid    = "AllowEC2ELBAndASGMutationsScopedByTagAndARN"
        Effect = "Allow"
        Action = [
          "ec2:DeleteVpc",
          "ec2:ModifyVpcAttribute",
          "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:DeleteSubnet",
          "ec2:ModifySubnetAttribute",
          "ec2:DeleteRouteTable",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:AssociateRouteTable",
          "ec2:DisassociateRouteTable",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DeleteLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:AddTags",
          "autoscaling:CreateAutoScalingGroup",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:DeleteAutoScalingGroup",
          "autoscaling:CreateOrUpdateTags"
        ]
        Resource = [
          "arn:aws:ec2:*:${local.account_id}:vpc/*",
          "arn:aws:ec2:*:${local.account_id}:internet-gateway/*",
          "arn:aws:ec2:*:${local.account_id}:subnet/*",
          "arn:aws:ec2:*:${local.account_id}:route-table/*",
          "arn:aws:ec2:*:${local.account_id}:security-group/*",
          "arn:aws:ec2:*:${local.account_id}:launch-template/*",
          "arn:aws:ec2:*:${local.account_id}:instance/*",
          "arn:aws:elasticloadbalancing:*:${local.account_id}:loadbalancer/app/${local.name_prefix}-*/*",
          "arn:aws:elasticloadbalancing:*:${local.account_id}:targetgroup/${local.name_prefix}-*/*",
          "arn:aws:elasticloadbalancing:*:${local.account_id}:listener/app/${local.name_prefix}-*/*/*",
          "arn:aws:autoscaling:*:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/${local.name_prefix}-*"
        ]
        Condition = {
          StringEqualsIfExists = {
            "aws:ResourceTag/Environment" = var.environment
          }
        }
      },
      {
        Sid    = "AllowTaggedResourceCreationWhereARNIsGeneratedByAWS"
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc",
          "ec2:CreateInternetGateway",
          "ec2:CreateSubnet",
          "ec2:CreateRouteTable",
          "ec2:CreateSecurityGroup",
          "ec2:CreateLaunchTemplate",
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateTargetGroup",
          "kms:CreateKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
          }
        }
      },
      {
        Sid    = "AllowReadOnlyDescribeForOpenTofuRefresh"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeAccountAttributes",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeTags",
          "autoscaling:DescribeAutoScalingGroups",
          "kms:ListAliases"
        ]
        Resource = "*"
      }
    ]
  })
}

# ==============================================================================
# Role e Instance Profile para a EC2 da aplicação FastAPI (Menor Privilégio)
# ==============================================================================

resource "aws_iam_role" "ec2_app" {
  name        = "${var.project_name}-${var.environment}-ec2-app-role"
  description = "Role de menor privilegio para a EC2 buscar DATABASE_URL no Secrets Manager e acessar o bucket S3 da aplicacao"

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

  tags = {
    Name        = "${var.project_name}-${var.environment}-ec2-app-role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "ec2_app_least_privilege" {
  name = "${var.project_name}-${var.environment}-ec2-app-policy"
  role = aws_iam_role.ec2_app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadAppSecretsAndParameters"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = [
          "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:${var.project_name}-${var.environment}-*",
          "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:parameter/${var.project_name}/${var.environment}/*"
        ]
      },
      {
        Sid    = "AccessAppArtifactsBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.app_bucket_arn,
          "${var.app_bucket_arn}/*"
        ]
      },
      {
        Sid    = "UseProjectKmsKey"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          var.kms_key_arn
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_app" {
  name = "${var.project_name}-${var.environment}-ec2-app-profile"
  role = aws_iam_role.ec2_app.name
}
