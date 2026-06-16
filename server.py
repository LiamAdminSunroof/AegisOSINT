"""
AEGIS FastAPI — Sprint 1 endpoints.
/health · /api/cases · /api/cases/{id} · /api/cases/{id}/search
/api/cases/{id}/analyze · /api/cases/{id}/graph
/api/entities/fusion (HITL queue) · /api/sam/dispatch
"""
import hmac as _hmac
import os
import json
from datetime import datetime
from typing import Optional

import sentry_sdk
import firebase_admin
from firebase_admin import credentials as fb_credentials, auth as fb_auth
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
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
from core.graph_persister import GraphPersister
from core.entity_resolver import EntityResolver
from collector.engine import CollectionEngine
from collector.base_module import SelectorType

# ── Sentry ───────────────────────────────────────────────────────────────────
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.1, environment="production")

# ── Firebase Admin (verificación JWT) ────────────────────────────────────────
if not firebase_admin._apps:
    firebase_admin.initialize_app()

# ── Rate limiting ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["30/minute"])

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(title="AEGIS OSINT Platform", version="0.2.0")
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
    allow_headers=["Authorization", "Content-Type", "X-AEGIS-Key"],
)

_case_mgr  = CaseManager()
_engine    = CollectionEngine()
_persister = GraphPersister()
_resolver  = EntityResolver()


# ── Auth helper ──────────────────────────────────────────────────────────────
def _get_user_id(request: Request) -> str:
    """
    FIX P2: Verifica Firebase ID Token (JWT) en lugar de aceptar X-AEGIS-User sin firma.
    El header X-AEGIS-User era trivialmente falsificable por cualquiera que conociera un UID.
    Ahora requiere Authorization: Bearer <firebase_id_token> criptográficamente firmado.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization: Bearer <firebase_token> requerido.")
    token = auth_header.removeprefix("Bearer ").strip()
    try:
        decoded = fb_auth.verify_id_token(token)
        uid = decoded.get("email", "")
    except fb_auth.ExpiredIdTokenError:
        raise HTTPException(status_code=401, detail="Token expirado. Re-autentícate.")
    except fb_auth.InvalidIdTokenError:
        raise HTTPException(status_code=401, detail="Token Firebase inválido.")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Error de autenticación: {e}")
    if uid not in (AEGIS_ADMINS | AEGIS_ANALYSTS):
        raise HTTPException(status_code=403, detail="Usuario no autorizado en AEGIS.")
    return uid


def _verify_api_key(request: Request) -> None:
    """
    FIX P4: usa hmac.compare_digest para prevenir timing attacks en comparación de API key.
    La comparación == en strings es vulnerable a ataques de canal lateral por tiempo.
    """
    key = request.headers.get("X-AEGIS-Key", "")
    if not AEGIS_API_KEY or not _hmac.compare_digest(key, AEGIS_API_KEY):
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
    persist_graph:  bool = True    # persistir findings a Neo4j automáticamente


class AnalyzeRequest(BaseModel):
    escalate_l3: bool = False      # activar Fable 5 L3 para casos críticos


class FusionApproveRequest(BaseModel):
    reviewed_by: str
    notes:       str = ""


class FusionRejectRequest(BaseModel):
    reviewed_by: str
    reason:      str = ""


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    """FIX M3: health check real que verifica conectividad con Firestore y Neo4j."""
    status: dict = {
        "status":    "ok",
        "service":   "aegis-osint",
        "version":   "0.2.0",
        "timestamp": datetime.utcnow().isoformat(),
    }
    try:
        _case_mgr.db.collection("_health").document("ping").set({"ts": datetime.utcnow().isoformat()})
        status["firestore"] = "ok"
    except Exception as e:
        status["firestore"] = f"error: {e}"
        status["status"] = "degraded"
    try:
        from core.graph_client import GraphClient
        GraphClient.get_driver().verify_connectivity()
        status["neo4j"] = "ok"
    except Exception as e:
        status["neo4j"] = f"unavailable: {e}"
    return status


@app.post("/api/admin/constraints")
async def apply_neo4j_constraints(request: Request):
    """
    One-shot admin endpoint — crea constraints e índices de unicidad en Neo4j Aura.
    Protegido por X-AEGIS-Key (solo USR-001 / operaciones de setup).
    Idempotente: IF NOT EXISTS en cada constraint.
    """
    _verify_api_key(request)
    from core.graph_client import GraphClient
    try:
        GraphClient.apply_constraints()
        return {"status": "ok", "message": "Constraints aplicados en Neo4j Aura."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
    user_id = _get_user_id(request)
    case = _case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no encontrado.")
    # FIX P5: analistas solo pueden ver sus propios casos; admins ven todos
    if user_id not in AEGIS_ADMINS and case.created_by != user_id:
        raise HTTPException(status_code=403, detail="Acceso denegado. Este caso no te pertenece.")
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

        # Persistir en Neo4j si se solicita
        persisted = 0
        if body.persist_graph:
            persisted = _persister.persist_findings(
                findings       = findings,
                case_id        = case_id,
                selector_type  = sel_type,
                selector_value = body.selector_value,
            )

        return {
            "case_id":   case_id,
            "selector":  body.selector_value,
            "findings":  len(findings),
            "persisted": persisted,
            "results":   [
                {
                    "platform":    f.platform,
                    "url":         f.url,
                    "confidence":  f.confidence,
                    "entity_type": f.entity_type,
                    "sensitivity": f.sensitivity.value,
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


# ── Sprint 1: Análisis con AEGIS_ANALYST ──────────────────────────────────────
@app.post("/api/cases/{case_id}/analyze")
@limiter.limit("3/minute")
async def analyze_case(case_id: str, request: Request, body: AnalyzeRequest):
    """Genera dossier de inteligencia con AEGIS_ANALYST (Sonnet L2 / Fable 5 L3)."""
    user_id = _get_user_id(request)
    case    = _case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no encontrado.")

    try:
        from agents.analyst import AegisAnalyst
        analyst = AegisAnalyst()

        # Intentar obtener el grafo del caso desde Neo4j
        graph_ctx = None
        try:
            from core.graph_client import GraphClient
            graph_ctx = GraphClient.get_case_graph(case_id)
        except Exception:
            pass  # Neo4j no disponible aún — dossier sin grafo

        dossier = analyst.generate_dossier(
            case_id        = case_id,
            selector_type  = "unknown",
            selector_value = case.target_selector,
            findings       = [],   # findings ya en Neo4j; dossier se basa en el grafo
            graph_context  = graph_ctx,
            escalate_l3    = body.escalate_l3,
        )

        _case_mgr.update_status(case_id, CaseStatus.REPORTED, user_id, f"model={dossier['model_used']}")
        _case_mgr.append_audit(case_id, "AEGIS_ANALYST", "DOSSIER_GENERATED",
                                f"model={dossier['model_used']} confidence={dossier['confidence']}")
        return dossier

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en análisis: {e}")


@app.get("/api/cases/{case_id}/graph")
async def get_case_graph(case_id: str, request: Request):
    """Retorna el grafo Neo4j del caso para visualización (Cytoscape.js)."""
    _get_user_id(request)
    case = _case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no encontrado.")
    try:
        from core.graph_client import GraphClient
        graph = GraphClient.get_case_graph(case_id)
        return {"case_id": case_id, "graph": graph}
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=f"Neo4j no disponible: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error obteniendo grafo: {e}")


@app.post("/api/cases/{case_id}/query")
@limiter.limit("10/minute")
async def query_graph_nl(case_id: str, request: Request):
    """NL → Cypher query sobre el grafo del caso. Devuelve filas raw."""
    user_id = _get_user_id(request)
    case = _case_mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no encontrado.")
    body = await request.json()
    question = body.get("question", "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="'question' es requerido.")
    try:
        from agents.analyst import AegisAnalyst
        analyst = AegisAnalyst()
        result  = analyst.query_graph_nl(question, case_id)
        return {"case_id": case_id, "question": question, "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en query: {e}")


# ── Sprint 1: HITL Fusion Queue ───────────────────────────────────────────────
@app.get("/api/entities/fusion/pending")
async def list_fusion_pending(request: Request, limit: int = 50):
    """Lista candidatos de fusión HITL pendientes (solo admins)."""
    user_id = _get_user_id(request)
    if user_id not in AEGIS_ADMINS:
        raise HTTPException(status_code=403, detail="Solo administradores AEGIS.")
    candidates = _resolver.list_pending(limit=limit)
    return {"pending": candidates, "total": len(candidates)}


@app.post("/api/entities/fusion/{resolve_id}/approve")
async def approve_fusion(resolve_id: str, request: Request, body: FusionApproveRequest):
    """Aprueba una fusión MISMO_ACTOR_QUE (HITL obligatorio — AEGIS §3.4)."""
    _get_user_id(request)
    try:
        relation = _resolver.approve_fusion(
            resolve_id  = resolve_id,
            reviewed_by = body.reviewed_by,
            notes       = body.notes,
        )
        # Persistir la relación en Neo4j
        try:
            from core.graph_client import GraphClient
            GraphClient.upsert_relation(relation)
        except Exception as e:
            print(f"[fusion_approve] Neo4j no disponible para persistir relación: {e}")
        return {
            "resolve_id": resolve_id,
            "status":     "APPROVED",
            "relation":   {
                "source": relation.source_id,
                "target": relation.target_id,
                "type":   relation.relation.value,
                "confidence": relation.confianza,
            },
        }
    except (PermissionError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/entities/fusion/{resolve_id}/reject")
async def reject_fusion(resolve_id: str, request: Request, body: FusionRejectRequest):
    """Rechaza una fusión propuesta."""
    _get_user_id(request)
    try:
        _resolver.reject_fusion(
            resolve_id  = resolve_id,
            reviewed_by = body.reviewed_by,
            reason      = body.reason,
        )
        return {"resolve_id": resolve_id, "status": "REJECTED"}
    except (PermissionError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Federación SAM ────────────────────────────────────────────────────────────
async def _run_collection_background(case_id: str, sel_type: SelectorType, selector_value: str) -> None:
    """
    FIX M6: Dispara la recolección en background al recibir dispatch de SAM.
    Sin esto el caso quedaba eternamente en DRAFT y SAM nunca recibía resultados.
    """
    try:
        findings = await _engine.run_case(
            case_id        = case_id,
            selector_type  = sel_type,
            selector_value = selector_value,
            tags           = [],
            max_depth      = 2,
        )
        _case_mgr.update_status(case_id, CaseStatus.ANALYZING, "SAM_CYBER_NODE",
                                 f"findings={len(findings)}")
        if findings:
            _persister.persist_findings(
                findings       = findings,
                case_id        = case_id,
                selector_type  = sel_type,
                selector_value = selector_value,
            )
    except Exception as e:
        _case_mgr.update_status(case_id, CaseStatus.DRAFT, "SYSTEM", f"Error background: {e}")
        print(f"[sam_dispatch_bg] Error en recolección caso {case_id}: {e}")


@app.post("/api/sam/dispatch")
async def sam_dispatch(request: Request, background_tasks: BackgroundTasks):
    """SAM CYBER NODE despacha investigación OSINT a AEGIS."""
    _verify_api_key(request)
    body = await request.json()

    selector_value    = body.get("target_selector", "").strip()
    selector_type_raw = body.get("selector_type", "domain")
    try:
        sel_type = SelectorType(selector_type_raw)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"selector_type inválido: {selector_type_raw}")

    try:
        case = _case_mgr.create_case(
            created_by      = "SAM_CYBER_NODE",
            purpose         = body.get("case_purpose", ""),
            legal_basis     = body.get("legal_basis", "CL_defensa_organizacion"),
            target_selector = selector_value,
            authorized_by   = "USR-001",
            scope           = body.get("scope", "open_source_only"),
        )
        # FIX M6: disparar recolección en background inmediatamente
        background_tasks.add_task(_run_collection_background, case.id, sel_type, selector_value)
        _case_mgr.update_status(case.id, CaseStatus.COLLECTING, "SAM_CYBER_NODE",
                                 f"selector={selector_value}")
        return {
            "case_id":   case.id,
            "status":    "COLLECTING",
            "aegis_url": f"/api/sam/case/{case.id}/result",
        }
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
