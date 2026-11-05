variable "project_name" {
  description = "Nome do projeto"
  type        = string
}

variable "environment" {
  description = "Ambiente (floci-local, prod)"
  type        = string
}

variable "github_repository" {
  description = "Repositorio do GitHub autorizado a assumir a role via OIDC (formato owner/repo)"
  type        = string
  default     = "Gabriel-V-Mendes/infraestrutura-aws-opentofu-floci"
}

variable "state_bucket_name" {
  description = "Nome do bucket S3 que armazena o state do OpenTofu"
  type        = string
}

variable "app_bucket_arn" {
  description = "ARN do bucket S3 de artefatos da aplicacao"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN da chave KMS do projeto"
  type        = string
}
