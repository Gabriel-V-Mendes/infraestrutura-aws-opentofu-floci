# Atalhos do Projeto 2 (OpenTofu + Floci). Rode `make` para listar os comandos.
.DEFAULT_GOAL := help
SHELL := /bin/bash

ENV_DIR ?= environments/floci-local
FLOCI_ENDPOINT ?= http://localhost:4566
AWS_REGION ?= us-east-1
TF_VAR_db_password ?= $(shell openssl rand -hex 16)

export FLOCI_ENDPOINT
export AWS_DEFAULT_REGION := $(AWS_REGION)
export AWS_ACCESS_KEY_ID ?= floci-ephemeral
export AWS_SECRET_ACCESS_KEY ?= floci-ephemeral
export TF_VAR_db_password
export TF_VAR_floci_endpoint := $(FLOCI_ENDPOINT)

.PHONY: help up down logs ps fmt lint validate scan checkov secrets bootstrap init plan apply smoke oidc destroy test protect-main

help: ## Lista todos os atalhos disponíveis
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

up: ## Sobe o emulador AWS local Floci (porta 4566) e aguarda ficar saudável
	docker compose up -d --wait

down: ## Derruba o emulador Floci e remove volumes efêmeros
	docker compose down -v

logs: ## Acompanha os logs do Floci
	docker compose logs -f

ps: ## Mostra o status e healthcheck do container Floci
	docker compose ps

fmt: ## Formata todos os arquivos HCL do OpenTofu
	tofu fmt -recursive .

lint: ## Verifica formatação HCL (tofu fmt -check)
	tofu fmt -check -recursive .

validate: init ## Valida sintaxe e tipos dos módulos OpenTofu
	cd $(ENV_DIR) && tofu validate

scan: ## Valida segurança da IaC com Trivy Config (bloqueia CRITICAL/HIGH)
	trivy config --skip-version-check --severity CRITICAL,HIGH --exit-code 1 .

checkov: ## Valida políticas de segurança IaC com Checkov
	checkov -d . --framework terraform --quiet --compact

secrets: ## Verifica ausência de chaves estáticas ou segredos com Gitleaks
	gitleaks git . --redact --verbose
	gitleaks dir . --redact --verbose

bootstrap: up ## Cria o bucket S3 de state versionado no Floci
	./scripts/bootstrap-state.sh

init: bootstrap ## Inicializa o OpenTofu com backend S3 e lock nativo (.tflock)
	cd $(ENV_DIR) && tofu init -backend-config=backend.hcl -backend-config="endpoint=$(FLOCI_ENDPOINT)" -input=false

plan: init ## Gera o plano de execução do OpenTofu
	cd $(ENV_DIR) && tofu plan -input=false -out=tfplan

apply: plan ## Aplica a infraestrutura completa no Floci
	cd $(ENV_DIR) && tofu apply -input=false -auto-approve tfplan

smoke: ## Valida via AWS CLI que todos os 37 recursos estão ativos no Floci
	./scripts/smoke-infra.sh

oidc: ## Testa a federação OIDC (sts:AssumeRoleWithWebIdentity) sem chaves estáticas
	./scripts/verify-oidc.sh

destroy: ## Derruba toda a infraestrutura provisionada (tofu destroy)
	cd $(ENV_DIR) && tofu destroy -input=false -auto-approve

test: up ## Executa o ciclo completo do zero: init -> validate -> plan -> apply -> smoke -> OIDC -> destroy
	./scripts/lifecycle-test.sh

protect-main: ## Aplica branch protection na main (exige gh autenticado)
	./scripts/protect-main.sh
