variable "project_name" {
  description = "Nome do projeto"
  type        = string
}

variable "environment" {
  description = "Ambiente (floci-local, prod)"
  type        = string
}

variable "aws_region" {
  description = "Regiao AWS"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "ID da VPC"
  type        = string
}

variable "public_subnet_ids" {
  description = "IDs das subnets publicas"
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "ID do Security Group do ALB"
  type        = string
}

variable "app_security_group_id" {
  description = "ID do Security Group da aplicacao EC2"
  type        = string
}

variable "instance_profile_name" {
  description = "Nome do IAM Instance Profile anexado a EC2"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN da chave KMS para criptografar o volume EBS"
  type        = string
}

variable "database_url_secret_arn" {
  description = "ARN do segredo no Secrets Manager contendo a DATABASE_URL"
  type        = string
}

variable "ami_id" {
  description = "ID da AMI Amazon Linux 2023 (compativel com o catalogo nativo da Floci e AWS)"
  type        = string
  default     = "ami-0abcdef1234567891"
}

variable "instance_type" {
  description = "Tipo da instancia EC2 (t4g.micro ou t3.micro para arquitetura economica)"
  type        = string
  default     = "t3.micro"
}

variable "app_image" {
  description = "Imagem Docker da FastAPI publicada no GHCR pelo pipeline do Projeto 1"
  type        = string
  default     = "ghcr.io/gabriel-v-mendes/containerizacaopipelinecicd:latest"
}

variable "min_size" {
  description = "Quantidade minima de instancias no Auto Scaling Group"
  type        = number
  default     = 1
}

variable "max_size" {
  description = "Quantidade maxima de instancias no Auto Scaling Group"
  type        = number
  default     = 1
}

variable "desired_capacity" {
  description = "Capacidade desejada do Auto Scaling Group (1 instancia por padrao)"
  type        = number
  default     = 1
}
