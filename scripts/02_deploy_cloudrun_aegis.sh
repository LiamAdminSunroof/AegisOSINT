#!/bin/bash
# Deploy AEGIS en Cloud Run.
# Secretos REQUERIDOS: ANTHROPIC_API_KEY · NEO4J_URI · NEO4J_PASSWORD · AEGIS_API_KEY · GOOGLE_SERVICE_ACCOUNT_JSON
# Secretos OPCIONALES: SHODAN_API_KEY · CENSYS_API_ID · CENSYS_API_SECRET · DEHASHED_API_KEY · SERPAPI_KEY · INTEL_X_API_KEY
set -e

PROJECT_ID="${1:-sunroof-agent-manager}"
REGION="${2:-us-central1}"
SERVICE="aegis-osint"

# Ruta absoluta a gcloud (compatible con zbook Ubuntu)
GCLOUD="${GCLOUD:-$(which gcloud 2>/dev/null || echo $HOME/google-cloud-sdk/bin/gcloud)}"

echo ">>> Desplegando AEGIS en Cloud Run — $SERVICE @ $PROJECT_ID/$REGION"

# ── Secretos REQUERIDOS ─────────────────────────────────────────────────────
REQUIRED_SECRETS="ANTHROPIC_API_KEY=ANTHROPIC_API_KEY:latest,\
AEGIS_API_KEY=AEGIS_API_KEY:latest,\
GOOGLE_SERVICE_ACCOUNT_JSON=GOOGLE_SERVICE_ACCOUNT_JSON:latest"

# ── Secretos NEO4J (requeridos para grafo) ──────────────────────────────────
# Si aún no existen en Secret Manager, omitir y la app arrancará sin grafo.
NEO4J_SECRETS=""
if $GCLOUD secrets describe NEO4J_URI --project="$PROJECT_ID" &>/dev/null; then
  NEO4J_SECRETS="${NEO4J_SECRETS},NEO4J_URI=NEO4J_URI:latest"
  echo "  [OK] NEO4J_URI disponible"
else
  echo "  [WARN] NEO4J_URI no existe aún — grafo desactivado hasta configurar Aura"
fi
if $GCLOUD secrets describe NEO4J_PASSWORD --project="$PROJECT_ID" &>/dev/null; then
  NEO4J_SECRETS="${NEO4J_SECRETS},NEO4J_PASSWORD=NEO4J_PASSWORD:latest"
  echo "  [OK] NEO4J_PASSWORD disponible"
fi

# ── Secretos OPCIONALES de APIs OSINT ──────────────────────────────────────
# Tier 0 (gratuitas): ABUSEIPDB_API_KEY · VIRUSTOTAL_API_KEY · OTX_API_KEY · IPINFO_TOKEN
# Tier 1+ (pendiente CFO): SHODAN_API_KEY · CENSYS_* · DEHASHED_API_KEY · SERPAPI_KEY · INTEL_X_API_KEY
OPTIONAL_SECRETS=""
for SECRET_NAME in ABUSEIPDB_API_KEY VIRUSTOTAL_API_KEY OTX_API_KEY IPINFO_TOKEN SHODAN_API_KEY CENSYS_API_ID CENSYS_API_SECRET DEHASHED_API_KEY SERPAPI_KEY INTEL_X_API_KEY; do
  if $GCLOUD secrets describe "$SECRET_NAME" --project="$PROJECT_ID" &>/dev/null; then
    OPTIONAL_SECRETS="${OPTIONAL_SECRETS},${SECRET_NAME}=${SECRET_NAME}:latest"
    echo "  [OK] $SECRET_NAME disponible"
  else
    echo "  [SKIP] $SECRET_NAME no configurado (módulo usará fallback)"
  fi
done

ALL_SECRETS="${REQUIRED_SECRETS}${NEO4J_SECRETS}${OPTIONAL_SECRETS}"

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
  --allow-unauthenticated \
  --no-use-http2 \
  --set-secrets="$ALL_SECRETS" \
  --service-account "sam-sunroof-agents@${PROJECT_ID}.iam.gserviceaccount.com" \
  --quiet

echo ""
echo ">>> Deploy completo. URL:"
SERVICE_URL=$($GCLOUD run services describe "$SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --format "value(status.url)")
echo "  $SERVICE_URL"
echo ""
echo ">>> Smoke test:"
curl -s "${SERVICE_URL}/health" | python3 -m json.tool
