"""
AEGIS FastAPI — Sprint 0 endpoints.
/health · /api/cases · /api/cases/{id} · /api/cases/{id}/search
"""
import os
import json
from datetime import datetime
from typing import Optional

import sentry_sdk
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel

from config import (
    GCP_PROJECT, MODEL_L1, MODEL_L2, SENTRY_DSN, AEGIS_API_KEY,
    AEGIS_ADMINS, AEGIS_ANALYSTS,
)
from core.case_manager import CaseManager, CaseStatus, LEGAL_BASIS_OPTIONS
from collector.engine import CollectionEngine
from collector.base_module import SelectorType

# ── Sentry ───────────────────────────────────────────────────────────────────
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.1, environment="production")

# ── Rate limiting ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["30/minute"])

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(title="AEGIS OSINT Platform", version="0.1.0")
app.state.limiter = limiter

_ALLOWED_ORIGINS = [
    "https://dashboard-xi-eight-96.vercel.app",
    "https://*.sunroof-group.com",
    "https://sunroof-group.com",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_origin_regex=r"https://.*\.sunroof-group\.com",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

_case_mgr = CaseManager()
_engine   = CollectionEngine()


# ── Auth helper ──────────────────────────────────────────────────────────────
def _get_user_id(request: Request) -> str:
    """Extrae user_id del header X-AEGIS-User o del body."""
    uid = request.headers.get("X-AEGIS-User", "")
    if not uid:
        raise HTTPException(status_code=401, detail="X-AEGIS-User header requerido.")
    if uid not in (AEGIS_ADMINS | AEGIS_ANALYSTS):
        raise HTTPException(status_code=403, detail="Usuario no autorizado en AEGIS.")
    return uid


def _verify_api_key(request: Request) -> None:
    """Verifica AEGIS_API_KEY para endpoints de federación SAM."""
    key = request.headers.get("X-AEGIS-Key", "")
    if not AEGIS_API_KEY or key != AEGIS_API_KEY:
        raise HTTPException(status_code=403, detail="API key inválida.")


# ── Schemas ───────────────────────────────────────────────────────────────────
class CreateCaseRequest(BaseModel):
    purpose:          str
    legal_basis:      str
    target_selector:  str
    authorized_by:    str
    scope:            str
    ttl_days:         int = 90


class SearchRequest(BaseModel):
    selector_type:  str
    selector_value: str
    tags:           list[str] = []
    max_depth:      int = 2


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":    "ok",
        "service":   "aegis-osint",
        "version":   "0.1.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/api/cases")
@limiter.limit("10/minute")
async def create_case(request: Request, body: CreateCaseRequest):
    user_id = _get_user_id(request)
    try:
        case = _case_mgr.create_case(
            created_by      = user_id,
            purpose         = body.purpose,
            legal_basis     = body.legal_basis,
            target_selector = body.target_selector,
            authorized_by   = body.authorized_by,
            scope           = body.scope,
            ttl_days        = body.ttl_days,
        )
        return {"case_id": case.id, "status": case.status.value, "created_at": case.created_at.isoformat()}
    except (ValueError, PermissionError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/cases/{case_id}")
async def get_case(case_id: str, request: Request):
    _get_user_id(request)
    case = _case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no encontrado.")
    return case.to_dict()


@app.get("/api/cases")
async def list_cases(request: Request, status: Optional[str] = None, limit: int = 50):
    user_id = _get_user_id(request)
    cases   = _case_mgr.list_cases(user_id=user_id, status=status, limit=limit)
    return {"cases": cases, "total": len(cases)}


@app.post("/api/cases/{case_id}/search")
@limiter.limit("5/minute")
async def search(case_id: str, request: Request, body: SearchRequest):
    user_id = _get_user_id(request)
    case    = _case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no encontrado.")
    try:
        sel_type = SelectorType(body.selector_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"selector_type inválido: {body.selector_type}")

    _case_mgr.update_status(case_id, CaseStatus.COLLECTING, user_id, f"selector={body.selector_value}")
    try:
        findings = await _engine.run_case(
            case_id        = case_id,
            selector_type  = sel_type,
            selector_value = body.selector_value,
            tags           = body.tags,
            max_depth      = body.max_depth,
        )
        _case_mgr.update_status(case_id, CaseStatus.ANALYZING, user_id, f"findings={len(findings)}")
        return {
            "case_id":   case_id,
            "selector":  body.selector_value,
            "findings":  len(findings),
            "results":   [
                {
                    "platform":   f.platform,
                    "url":        f.url,
                    "confidence": f.confidence,
                    "entity_type": f.entity_type,
                }
                for f in findings
            ],
        }
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        _case_mgr.update_status(case_id, CaseStatus.DRAFT, "SYSTEM", f"Error: {e}")
        raise HTTPException(status_code=500, detail=f"Error en recolección: {e}")


@app.get("/api/legal-basis")
async def get_legal_basis():
    return {"legal_basis_options": LEGAL_BASIS_OPTIONS}


# ── Federación SAM ────────────────────────────────────────────────────────────
@app.post("/api/sam/dispatch")
async def sam_dispatch(request: Request):
    """SAM CYBER NODE despacha investigación OSINT a AEGIS."""
    _verify_api_key(request)
    body = await request.json()
    try:
        case = _case_mgr.create_case(
            created_by      = "SAM_CYBER_NODE",
            purpose         = body.get("case_purpose", ""),
            legal_basis     = body.get("legal_basis", "CL_defensa_organizacion"),
            target_selector = body.get("target_selector", ""),
            authorized_by   = "USR-001",
            scope           = body.get("scope", "open_source_only"),
        )
        return {"case_id": case.id, "status": "CREATED", "aegis_url": f"/api/sam/case/{case.id}/result"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/sam/case/{case_id}/result")
async def sam_result(case_id: str, request: Request):
    """SAM recoge el resultado procesado de AEGIS."""
    _verify_api_key(request)
    case = _case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no encontrado.")
    return {"case_id": case_id, "status": case.status.value, "case": case.to_dict()}


# ── Error handler ─────────────────────────────────────────────────────────────
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "Rate limit excedido. Intenta en 1 minuto."})
