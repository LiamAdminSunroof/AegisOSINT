#!/bin/bash
set -e

PROJECT_ID="${1:-sunroof-agent-manager}"
REGION="${2:-us-central1}"
SERVICE="aegis-osint"

echo ">>> Desplegando AEGIS en Cloud Run — $SERVICE @ $PROJECT_ID/$REGION"

gcloud run deploy "$SERVICE" \
  --source . \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --memory 4Gi \
  --cpu 4 \
  --timeout 1800 \
  --concurrency 80 \
  --min-instances 0 \
  --max-instances 5 \
  --http2 \
  --set-secrets="ANTHROPIC_API_KEY=ANTHROPIC_API_KEY:latest,\
NEO4J_URI=NEO4J_URI:latest,\
NEO4J_PASSWORD=NEO4J_PASSWORD:latest,\
SHODAN_API_KEY=SHODAN_API_KEY:latest,\
CENSYS_API_ID=CENSYS_API_ID:latest,\
CENSYS_API_SECRET=CENSYS_API_SECRET:latest,\
DEHASHED_API_KEY=DEHASHED_API_KEY:latest,\
SERPAPI_KEY=SERPAPI_KEY:latest,\
INTEL_X_API_KEY=INTEL_X_API_KEY:latest,\
AEGIS_API_KEY=AEGIS_API_KEY:latest,\
GOOGLE_SERVICE_ACCOUNT_JSON=GOOGLE_SERVICE_ACCOUNT_JSON:latest" \
  --service-account "sam-sunroof-agents@${PROJECT_ID}.iam.gserviceaccount.com" \
  --quiet

echo ">>> Deploy completo. URL:"
gcloud run services describe "$SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --format "value(status.url)"
