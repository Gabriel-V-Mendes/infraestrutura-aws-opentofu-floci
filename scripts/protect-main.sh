#!/usr/bin/env bash
# Aplica branch protection na branch `main` exigindo os checks obrigatórios de IaC e segurança.
set -euo pipefail

REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
echo "==> Aplicando proteção na branch 'main' de ${REPO}..."

gh api --method PUT "/repos/${REPO}/branches/main/protection" \
  --input - <<'JSON' >/dev/null
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Format & Validate (OpenTofu)",
      "Secret Scan (Gitleaks)",
      "IaC Security Scan (Trivy Config)",
      "E2E Apply, OIDC & Destroy (Floci)"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON

echo "==> Branch 'main' protegida com sucesso! Checks obrigatórios ativados."
