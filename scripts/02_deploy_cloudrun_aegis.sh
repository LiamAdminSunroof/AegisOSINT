#!/bin/bash
# Deploy AEGIS en Cloud Run.
# Secretos REQUERIDOS: ANTHROPIC_API_KEY · AEGIS_API_KEY · AEGIS_ENCRYPTION_KEY
# Secretos OPCIONALES: NEO4J_URI · NEO4J_PASSWORD · ABUSEIPDB_API_KEY · VIRUSTOTAL_API_KEY · OTX_API_KEY · IPINFO_TOKEN · SHODAN_API_KEY · CENSYS_API_ID · CENSYS_API_SECRET · DEHASHED_API_KEY · SERPAPI_KEY · INTEL_X_API_KEY
set -euo pipefail

PROJECT_ID="${1:-sunroof-agent-manager}"
REGION="${2:-us-central1}"
SERVICE="aegis-osint"
RUNTIME_SERVICE_ACCOUNT="${AEGIS_RUNTIME_SERVICE_ACCOUNT:-aegis-runtime@${PROJECT_ID}.iam.gserviceaccount.com}"

# Ruta absoluta a gcloud (compatible con zbook Ubuntu)
GCLOUD="${GCLOUD:-$(which gcloud 2>/dev/null || echo $HOME/google-cloud-sdk/bin/gcloud)}"

echo ">>> Desplegando AEGIS en Cloud Run — $SERVICE @ $PROJECT_ID/$REGION"
echo ">>> Runtime SA sin clave: $RUNTIME_SERVICE_ACCOUNT"

$GCLOUD iam service-accounts describe "$RUNTIME_SERVICE_ACCOUNT" \
  --project "$PROJECT_ID" >/dev/null

# ── Secretos REQUERIDOS ─────────────────────────────────────────────────────
REQUIRED_SECRETS="ANTHROPIC_API_KEY=ANTHROPIC_API_KEY:latest,\
AEGIS_API_KEY=AEGIS_API_KEY:latest,\
AEGIS_ENCRYPTION_KEY=AEGIS_ENCRYPTION_KEY:latest"

# ── Secretos NEO4J (opcionales para grafo) ──────────────────────────────────
OPTIONAL_SECRETS=""
for SECRET_NAME in NEO4J_URI NEO4J_PASSWORD ABUSEIPDB_API_KEY VIRUSTOTAL_API_KEY OTX_API_KEY IPINFO_TOKEN SHODAN_API_KEY CENSYS_API_ID CENSYS_API_SECRET DEHASHED_API_KEY SERPAPI_KEY INTEL_X_API_KEY; do
  if $GCLOUD secrets describe "$SECRET_NAME" --project "$PROJECT_ID" &>/dev/null; then
    OPTIONAL_SECRETS="${OPTIONAL_SECRETS},${SECRET_NAME}=${SECRET_NAME}:latest"
    echo "  [OK] $SECRET_NAME disponible"
  else
    echo "  [SKIP] $SECRET_NAME no configurado (módulo usará fallback)"
  fi
done

ALL_SECRETS="${REQUIRED_SECRETS}${OPTIONAL_SECRETS}"

$GCLOUD run deploy "$SERVICE" \
  --source . \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --memory 4Gi \
  --cpu 4 \
  --timeout 1800 \
  --concurrency 80 \
  --min-instances 0 \
  --max-instances 5 \
  --no-allow-unauthenticated \
  --no-use-http2 \
  --set-secrets="$ALL_SECRETS" \
  --service-account "$RUNTIME_SERVICE_ACCOUNT" \
  --quiet

echo ""
echo ">>> Deploy completo. URL:"
SERVICE_URL=$($GCLOUD run services describe "$SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --format "value(status.url)")
echo "  $SERVICE_URL"
echo ""
echo ">>> Smoke test autenticado:"
IDENTITY_TOKEN=$($GCLOUD auth print-identity-token)
curl -fsS \
  -H "Authorization: Bearer $IDENTITY_TOKEN" \
  "${SERVICE_URL}/health" | python3 -m json.tool
