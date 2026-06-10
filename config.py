import os

# ── GCP ──────────────────────────────────────────────────────────────────────
GCP_PROJECT         = "sunroof-agent-manager"
GCP_REGION          = "us-central1"
SERVICE_NAME        = "aegis-osint"
SERVICE_ACCOUNT     = "sam-sunroof-agents@sunroof-agent-manager.iam.gserviceaccount.com"

# ── MODELOS FinOps V4.0 (heredado SAM) ───────────────────────────────────────
MODEL_L1            = "claude-haiku-4-5-20251001"    # 65% — triaje, routing
MODEL_L2            = "claude-sonnet-4-6"            # 30% — análisis, síntesis
MODEL_L3            = "claude-fable-5"               # 5%  — dossiers críticos, SENTINEL

# ── NEO4J AURA ───────────────────────────────────────────────────────────────
NEO4J_URI           = os.environ.get("NEO4J_URI", "")           # bolt+ssc://...
NEO4J_USERNAME      = os.environ.get("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD      = os.environ.get("NEO4J_PASSWORD", "")

# ── ANTHROPIC ─────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")

# ── APIS OSINT (Secret Manager) ───────────────────────────────────────────────
SHODAN_API_KEY      = os.environ.get("SHODAN_API_KEY", "")
CENSYS_API_ID       = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET   = os.environ.get("CENSYS_API_SECRET", "")
DEHASHED_API_KEY    = os.environ.get("DEHASHED_API_KEY", "")
SERPAPI_KEY         = os.environ.get("SERPAPI_KEY", "")
INTEL_X_API_KEY     = os.environ.get("INTEL_X_API_KEY", "")

# ── SAM FEDERATION ────────────────────────────────────────────────────────────
SAM_API_URL         = os.environ.get("SAM_API_URL", "https://sam-sunroof-591203469479.us-central1.run.app")
AEGIS_API_KEY       = os.environ.get("AEGIS_API_KEY", "")  # HMAC compartido con SAM

# ── GOVERNANCE ────────────────────────────────────────────────────────────────
DEFAULT_TTL_DAYS    = 90   # Retención de datos por defecto
MAX_CASE_DEPTH      = 3    # Profundidad máxima de recursión en recolección
MIN_PURPOSE_LEN     = 50   # Caracteres mínimos en purpose del caso

# ── RBAC — usuarios autorizados ───────────────────────────────────────────────
AEGIS_ADMINS        = {"USR-001"}
AEGIS_ANALYSTS      = {"USR-001", "USR-006"}   # OPS puede investigar superficie OT
AEGIS_VIEWERS       = {"USR-001", "USR-006", "USR-003"}

# ── SCORING DE CONFIANZA por tipo de detección ────────────────────────────────
CONFIDENCE_THRESHOLDS = {
    "http_200_with_profile": 0.90,
    "http_200_only":         0.60,
    "redirect":              0.40,
    "api_confirmed":         0.95,
    "breach_record":         0.85,
}

# ── ENTITY RESOLVER — umbrales de fusión ──────────────────────────────────────
RESOLVER_AUTO_MERGE     = 0.85   # Score ≥ 0.85 → fusión automática
RESOLVER_REVIEW_QUEUE   = 0.60   # 0.60–0.85 → cola revisión HITL
# < 0.60 → nueva entidad separada

# ── SENTRY ───────────────────────────────────────────────────────────────────
SENTRY_DSN          = os.environ.get("SENTRY_DSN_AEGIS", "")
