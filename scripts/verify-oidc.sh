#!/usr/bin/env bash
# Valida a autenticação OIDC sem chaves estáticas (sts:AssumeRoleWithWebIdentity),
# a Trust Policy restrita (apenas ref:refs/heads/main e environment:production)
# e a ausência de curingas amplos (ec2:*, rds:*, kms:*, secretsmanager:*).
# No GitHub Actions (permissions: id-token: write), requisita um JWT OIDC REAL
# diretamente do provedor https://token.actions.githubusercontent.com.
set -euo pipefail

FLOCI_ENDPOINT="${FLOCI_ENDPOINT:-http://localhost:4566}"
AWS_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
ROLE_NAME="${ROLE_NAME:-devops-api-floci-gha-oidc-role}"
POLICY_NAME="${POLICY_NAME:-devops-api-floci-gha-iac-policy}"
EXPECTED_REPO="${EXPECTED_REPO:-Gabriel-V-Mendes/infraestrutura-aws-opentofu-floci}"

export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-floci-ephemeral}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-floci-ephemeral}"
export AWS_DEFAULT_REGION="$AWS_REGION"

aws_floci() {
  aws --endpoint-url "$FLOCI_ENDPOINT" --region "$AWS_REGION" --no-cli-pager --output json "$@"
}

echo "==> [OIDC 1/4] Consultando Role OIDC e validando Trust Policy restrita..."
ROLE_JSON=$(aws_floci iam get-role --role-name "$ROLE_NAME")
ROLE_ARN=$(echo "$ROLE_JSON" | jq -r '.Role.Arn')
TRUST_DOC=$(echo "$ROLE_JSON" | jq -r '.Role.AssumeRolePolicyDocument | if type == "string" then (gsub("%(?<h>[0-9A-Fa-f]{2})"; "") | .) else tojson end' 2>/dev/null || echo "$ROLE_JSON")

# Extrai o documento de Trust Policy decodificando URL-encoding se necessário
RAW_TRUST=$(python3 -c '
import json, sys, urllib.parse
role = json.loads(sys.stdin.read())["Role"]
doc = role["AssumeRolePolicyDocument"]
if isinstance(doc, str):
    doc = json.loads(urllib.parse.unquote(doc))
print(json.dumps(doc))
' <<< "$ROLE_JSON")

echo "    Role encontrada: $ROLE_ARN"

# Verifica que repo:...:* NÃO existe mais e que apenas main e environment:production são aceitos
if grep -qF ':*' <<< "$RAW_TRUST"; then
  echo "ERRO: Trust policy ainda contém curinga amplo ':*' no subject!" >&2
  exit 1
fi

grep -q "repo:${EXPECTED_REPO}:ref:refs/heads/main" <<< "$RAW_TRUST" || {
  echo "ERRO: Trust policy não contém ref:refs/heads/main para ${EXPECTED_REPO}" >&2
  exit 1
}
grep -q "repo:${EXPECTED_REPO}:environment:production" <<< "$RAW_TRUST" || {
  echo "ERRO: Trust policy não contém environment:production para ${EXPECTED_REPO}" >&2
  exit 1
}
echo "    Trust Policy validada: restrita exclusivamente a ref:refs/heads/main e environment:production."

echo "==> [OIDC 2/4] Auditando menor privilégio na Role Policy (${POLICY_NAME})..."
POLICY_JSON=$(aws_floci iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME")
RAW_POLICY=$(python3 -c '
import json, sys, urllib.parse
doc = json.loads(sys.stdin.read())["PolicyDocument"]
if isinstance(doc, str):
    doc = json.loads(urllib.parse.unquote(doc))
print(json.dumps(doc))
' <<< "$POLICY_JSON")

for FORBIDDEN in '"ec2:*"' '"rds:*"' '"kms:*"' '"secretsmanager:*"' '"s3:*"'; do
  if grep -qF "$FORBIDDEN" <<< "$RAW_POLICY"; then
    echo "ERRO: Permissão curinga proibida encontrada na policy: $FORBIDDEN" >&2
    exit 1
  fi
done
echo "    Menor privilégio validado: zero ec2:*, rds:*, kms:* ou secretsmanager:*."

echo "==> [OIDC 3/4] Obtendo Web Identity Token OIDC..."
if [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
  echo "    Ambiente GitHub Actions detectado: requisitando JWT OIDC REAL de token.actions.githubusercontent.com..."
  OIDC_JWT=$(curl -fsSL \
    -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    -H "Accept: application/json; api-version=2.0" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sts.amazonaws.com" | jq -r '.value')
  CLAIMS=$(python3 -c '
import base64, json, sys
jwt = sys.argv[1]
payload = jwt.split(".")[1]
payload += "=" * (-len(payload) % 4)
data = json.loads(base64.urlsafe_b64decode(payload))
print(f"iss={data.get(\"iss\")} | sub={data.get(\"sub\")} | aud={data.get(\"aud\")}")
' "$OIDC_JWT")
  echo "    Token OIDC real emitido pelo GitHub: ${CLAIMS}"
else
  echo "    Execução fora do GitHub Actions (modo local): gerando token de teste local para o endpoint Floci..."
  HEADER=$(printf '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
  PAYLOAD=$(printf '{"iss":"https://token.actions.githubusercontent.com","sub":"repo:%s:ref:refs/heads/main","aud":"sts.amazonaws.com","exp":9999999999}' "$EXPECTED_REPO" | base64 -w0 | tr '+/' '-_' | tr -d '=')
  OIDC_JWT="${HEADER}.${PAYLOAD}.local"
fi

echo "==> [OIDC 4/4] Executando sts:AssumeRoleWithWebIdentity..."
STS_OUTPUT=$(aws_floci sts assume-role-with-web-identity \
  --role-arn "$ROLE_ARN" \
  --role-session-name "github-actions-oidc-ci" \
  --web-identity-token "$OIDC_JWT")

TEMP_KEY_ID=$(echo "$STS_OUTPUT" | jq -r '.Credentials.AccessKeyId')
TEMP_TOKEN=$(echo "$STS_OUTPUT" | jq -r '.Credentials.SessionToken')
ASSUMED_ARN=$(echo "$STS_OUTPUT" | jq -r '.AssumedRoleUser.Arn')

if [[ -z "$TEMP_KEY_ID" || "$TEMP_KEY_ID" == "null" || -z "$TEMP_TOKEN" ]]; then
  echo "ERRO: Falha ao obter credenciais temporárias via OIDC!" >&2
  exit 1
fi

echo "    AssumedRoleUser: $ASSUMED_ARN"
echo "    Temporary AccessKeyId prefix: ${TEMP_KEY_ID:0:8}*** (com SessionToken efêmero)"
echo "==> [OIDC] Federação OIDC e política de menor privilégio validadas com sucesso!"
