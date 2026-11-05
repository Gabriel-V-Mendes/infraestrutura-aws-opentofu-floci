variable "project_name" {
  description = "Nome do projeto"
  type        = string
  default     = "devops-api"
}

variable "environment" {
  description = "Identificador do ambiente"
  type        = string
  default     = "floci"
}

variable "aws_region" {
  description = "Regiao AWS padrao"
  type        = string
  default     = "us-east-1"
}

variable "floci_endpoint" {
  description = "Endpoint HTTP do emulador Floci"
  type        = string
  default     = "http://localhost:4566"
}

variable "state_bucket_name" {
  description = "Nome do bucket S3 usado para armazenar o state do OpenTofu"
  type        = string
  default     = "devops-api-tofu-state"
}

variable "github_repository" {
  description = "Repositorio GitHub autorizado na federacao OIDC"
  type        = string
  default     = "Gabriel-V-Mendes/infraestrutura-aws-opentofu-floci"
}

variable "monthly_budget_usd" {
  description = "Orcamento mensal maximo em USD no AWS Budgets"
  type        = string
  default     = "15.0"
}

variable "alert_email" {
  description = "E-mail para alertas de orcamento e CPU"
  type        = string
  default     = "devops-alerts@example.com"
}

variable "vpc_cidr" {
  description = "CIDR da VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDRs das subnets publicas"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "availability_zones" {
  description = "Zonas de disponibilidade"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "allowed_ingress_cidrs" {
  description = "CIDRs permitidos no ALB"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "db_instance_class" {
  description = "Classe da instancia RDS Single-AZ"
  type        = string
  default     = "db.t4g.micro"
}

variable "db_engine_version" {
  description = "Versao do PostgreSQL"
  type        = string
  default     = "17.2"
}

variable "db_name" {
  description = "Nome do banco PostgreSQL"
  type        = string
  default     = "devops"
}

variable "db_username" {
  description = "Usuario do banco PostgreSQL"
  type        = string
  default     = "devops_admin"
}

variable "db_password" {
  description = "Senha do banco PostgreSQL (passada via TF_VAR_db_password)"
  type        = string
  sensitive   = true
}

variable "ami_id" {
  description = "AMI Amazon Linux 2023 do catalogo Floci/AWS"
  type        = string
  default     = "ami-0abcdef1234567891"
}

variable "ec2_instance_type" {
  description = "Tipo da instancia EC2 pequena"
  type        = string
  default     = "t3.micro"
}

variable "app_image" {
  description = "Imagem Docker da FastAPI publicada no GHCR"
  type        = string
  default     = "ghcr.io/gabriel-v-mendes/containerizacaopipelinecicd:latest"
}
