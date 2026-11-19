# ==============================================================================
# Ambiente: aws-prod (OpenTofu validado em emulador Floci e plan contra a AWS)
# ==============================================================================

module "storage" {
  source = "../../modules/storage"

  project_name  = var.project_name
  environment   = var.environment
  force_destroy = false
}

module "budget_alerts" {
  source = "../../modules/budget-alerts"

  project_name       = var.project_name
  environment        = var.environment
  monthly_budget_usd = var.monthly_budget_usd
  alert_email        = var.alert_email
  kms_key_id         = module.storage.kms_key_arn
}

module "iam_oidc" {
  source = "../../modules/iam-oidc"

  project_name      = var.project_name
  environment       = var.environment
  github_repository = var.github_repository
  state_bucket_name = var.state_bucket_name
  app_bucket_arn    = module.storage.artifacts_bucket_arn
  kms_key_arn       = module.storage.kms_key_arn
}

module "network" {
  source = "../../modules/network"

  project_name          = var.project_name
  environment           = var.environment
  vpc_cidr              = var.vpc_cidr
  public_subnet_cidrs   = var.public_subnet_cidrs
  availability_zones    = var.availability_zones
  allowed_ingress_cidrs = var.allowed_ingress_cidrs
}

module "database" {
  source = "../../modules/database"

  project_name         = var.project_name
  environment          = var.environment
  subnet_ids           = module.network.public_subnet_ids
  db_security_group_id = module.network.db_security_group_id
  kms_key_arn          = module.storage.kms_key_arn
  instance_class       = var.db_instance_class
  engine_version       = var.db_engine_version
  db_name              = var.db_name
  db_username          = var.db_username
  db_password          = var.db_password
  multi_az             = var.multi_az
  deletion_protection  = var.deletion_protection
  skip_final_snapshot  = var.skip_final_snapshot
}

module "compute" {
  source = "../../modules/compute"

  project_name            = var.project_name
  environment             = var.environment
  aws_region              = var.aws_region
  vpc_id                  = module.network.vpc_id
  public_subnet_ids       = module.network.public_subnet_ids
  alb_security_group_id   = module.network.alb_security_group_id
  app_security_group_id   = module.network.app_security_group_id
  instance_profile_name   = module.iam_oidc.ec2_instance_profile_name
  kms_key_arn             = module.storage.kms_key_arn
  database_url_secret_arn = module.database.database_url_secret_arn
  ami_id                  = var.ami_id
  instance_type           = var.ec2_instance_type
  app_image               = var.app_image
  min_size                = 1
  max_size                = 1
  desired_capacity        = 1
}
