#!/usr/bin/env bash
# Executa o ciclo completo de infraestrutura do zero contra o emulador Floci:
# bootstrap S3 -> tofu init -> validate -> plan -> apply -> smoke test -> OIDC test -> destroy
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_DIR="${ROOT_DIR}/environments/floci-local"

export FLOCI_ENDPOINT="${FLOCI_ENDPOINT:-http://localhost:4566}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-floci-ephemeral}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-floci-ephemeral}"
export TF_VAR_db_password="${TF_VAR_db_password:-$(openssl rand -hex 16)}"
export TF_VAR_floci_endpoint="$FLOCI_ENDPOINT"

# 1. Bootstrap do bucket de state
"${ROOT_DIR}/scripts/bootstrap-state.sh"

cd "$ENV_DIR"
rm -rf .terraform terraform.tfstate* tfplan 2>/dev/null || true

echo "==> [OpenTofu] 1/5 Inicializando backend S3 com lock nativo (use_lockfile = true)..."
tofu init -backend-config=backend.hcl \
  -backend-config="endpoint=${FLOCI_ENDPOINT}" \
  -input=false -no-color

echo "==> [OpenTofu] 2/5 Validando sintaxe e tipos..."
tofu validate -no-color

echo "==> [OpenTofu] 3/5 Gerando plano de execução..."
tofu plan -input=false -no-color -out=tfplan

echo "==> [OpenTofu] 4/5 Aplicando infraestrutura do zero no Floci..."
tofu apply -input=false -auto-approve -no-color tfplan

# 5. Verificações reais na API do Floci + teste OIDC
"${ROOT_DIR}/scripts/smoke-infra.sh"
"${ROOT_DIR}/scripts/verify-oidc.sh"

echo "==> [OpenTofu] 5/5 Derrubando toda a infraestrutura ao final (tofu destroy)..."
tofu destroy -input=false -auto-approve -no-color
rm -f tfplan

echo "==> [Sucesso] Ciclo completo (init -> plan -> apply -> smoke -> OIDC -> destroy) concluído!"
