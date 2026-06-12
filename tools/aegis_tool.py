"""
aegis_tool.py — SAM integration client para AEGIS OSINT Platform.
Invocado por el CYBER NODE de SAM para despachar investigaciones OSINT.
Comunicación via HTTPS con AEGIS Cloud Run (auth via AEGIS_API_KEY).
"""
import httpx
from config import AEGIS_API_URL, AEGIS_API_KEY

_TIMEOUT  = 45.0   # segundos — búsquedas OSINT pueden tomar hasta 30s


def osint_request(
    selector_type:  str,
    selector_value: str,
    purpose:        str,
    requester_id:   str = "USR-001",
    tags:           list = None,
    max_depth:      int  = 2,
) -> dict:
    """
    Crea un caso AEGIS y ejecuta búsqueda OSINT. Retorna resumen de findings.

    Args:
        selector_type:  "username" | "email" | "domain" | "ip"
        selector_value: valor a investigar (ej: "8.8.8.8", "example.com")
        purpose:        propósito legal ≥ 50 chars (compliance)
        requester_id:   ID del colaborador que solicita (default USR-001)
        tags:           filtros opcionales de módulo (ej: ["threat", "ip"])
        max_depth:      profundidad máx de recursión en AEGIS (default 2)

    Returns:
        dict con case_id, findings_count, highlights y URLs de grafo.
    """
    if not AEGIS_API_KEY:
        return {
            "error": "AEGIS_API_KEY no configurada.",
            "hint":  "Agregar AEGIS_API_KEY a Secret Manager GCP y redeploy de SAM.",
        }
    if not AEGIS_API_URL:
        return {
            "error": "AEGIS_API_URL no configurada en config.py de SAM.",
        }
    if len(purpose) < 50:
        return {
            "error": f"purpose demasiado corto ({len(purpose)} chars). Mínimo 50 chars requeridos para compliance.",
        }

    headers = {
        "X-AEGIS-Key":  AEGIS_API_KEY,
        "X-AEGIS-User": requester_id,
        "Content-Type": "application/json",
    }
    base = AEGIS_API_URL.rstrip("/")

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:

            # ── Paso 1: Crear caso ──────────────────────────────────────────
            case_resp = client.post(
                f"{base}/api/cases",
                json={
                    "title":       f"OSINT: {selector_type.upper()} — {selector_value}",
                    "purpose":     purpose,
                    "legal_basis": "legitimate_interest",
                    "scope":       {"selector": selector_value, "type": selector_type},
                    "operator_id": requester_id,
                },
                headers=headers,
            )
            if case_resp.status_code not in (200, 201):
                return {
                    "error":  f"Error creando caso AEGIS: HTTP {case_resp.status_code}",
                    "detail": case_resp.text[:300],
                }

            case_id = case_resp.json().get("case_id", "")
            if not case_id:
                return {"error": "AEGIS no retornó case_id en la respuesta."}

            # ── Paso 2: Disparar búsqueda ──────────────────────────────────
            search_resp = client.post(
                f"{base}/api/cases/{case_id}/search",
                json={
                    "selector_type":  selector_type,
                    "selector_value": selector_value,
                    "tags":           tags or [],
                    "max_depth":      max_depth,
                    "persist_graph":  True,
                },
                headers=headers,
            )
            if search_resp.status_code not in (200, 201):
                return {
                    "case_id": case_id,
                    "warning": f"Caso creado pero búsqueda falló: HTTP {search_resp.status_code}",
                    "aegis_case_url": f"{base}/api/cases/{case_id}",
                }

            findings = search_resp.json().get("findings", [])

    except httpx.TimeoutException:
        return {"error": f"AEGIS no respondió en {_TIMEOUT}s. El caso puede estar procesándose en background."}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:300]}"}

    return {
        "status":          "INVESTIGACION_COMPLETA",
        "case_id":         case_id,
        "selector":        f"{selector_type}:{selector_value}",
        "findings_count":  len(findings),
        "aegis_case_url":  f"{base}/api/cases/{case_id}",
        "aegis_graph_url": f"{base}/api/cases/{case_id}/graph",
        "highlights":      _extract_highlights(findings),
    }


def _extract_highlights(findings: list) -> list[dict]:
    """Top 5 hallazgos por confianza, para el resumen del agente."""
    by_confidence = sorted(findings, key=lambda f: f.get("confidence", 0), reverse=True)
    return [
        {
            "platform":    f.get("platform", ""),
            "entity_type": f.get("entity_type", ""),
            "url":         f.get("url", ""),
            "confidence":  f.get("confidence", 0),
            "sensitivity": f.get("sensitivity", ""),
        }
        for f in by_confidence[:5]
    ]
