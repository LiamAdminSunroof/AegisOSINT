"""
DeHashed breach module — consulta la API de DeHashed para hallazgos de credenciales.
https://www.dehashed.com/docs

Requiere DEHASHED_API_KEY en Secret Manager.
Si el key no está disponible → fallback silencioso (no rompe pipeline).
Los findings de credenciales se marcan Sensitivity.HIGH → AES-256-GCM al persistir.
"""
import asyncio
import json
from typing import Optional

import aiohttp

from collector.base_module import (
    CollectorModule, Finding, RateLimit,
    SelectorType, Sensitivity, MODULE_STATUS_REQUIRES_KEY,
)
from config import DEHASHED_API_KEY

_DEHASHED_BASE  = "https://api.dehashed.com"
_DEFAULT_LIMIT  = 10      # máximo de entries a procesar por consulta
_TIMEOUT        = 15      # segundos


class DeHashedModule:
    """
    Busca en DeHashed por email, username, dominio o IP.
    Retorna entradas de brechas con campos de credenciales (HIGH sensitivity).
    """

    name             = "dehashed_breach"
    family           = "brechas"
    accepts          = [SelectorType.EMAIL, SelectorType.USERNAME, SelectorType.DOMAIN]
    tags             = ["breach", "credentials", "darkweb"]
    rate_limit       = RateLimit(requests_per_second=0.5, burst=2)
    requires_api_key = True
    status           = MODULE_STATUS_REQUIRES_KEY

    async def collect(
        self,
        selector_type:  SelectorType,
        selector_value: str,
        context:        dict,
    ) -> list[Finding]:
        if selector_type not in self.accepts:
            return []
        if not DEHASHED_API_KEY:
            print("[dehashed] DEHASHED_API_KEY no disponible — skip.")
            return []

        query = _build_query(selector_type, selector_value)
        entries = await _query_dehashed(query, DEHASHED_API_KEY)
        if not entries:
            return []

        findings: list[Finding] = []
        for entry in entries[:_DEFAULT_LIMIT]:
            f = _entry_to_finding(entry, selector_type, selector_value)
            if f:
                findings.append(f)

        print(f"[dehashed] {selector_value} → {len(findings)} brechas")
        return findings


def _build_query(selector_type: SelectorType, value: str) -> str:
    """Construye query string para DeHashed."""
    field_map = {
        SelectorType.EMAIL:    f"email:{value}",
        SelectorType.USERNAME: f"username:{value}",
        SelectorType.DOMAIN:   f"domain:{value}",
    }
    return field_map.get(selector_type, value)


async def _query_dehashed(query: str, api_key: str) -> list[dict]:
    """Ejecuta la query contra DeHashed API."""
    # DeHashed requiere Basic Auth: email:api_key
    # Derivamos un user genérico — en producción el key incluye el email
    email_part = "api"
    if ":" in api_key:
        email_part, api_key = api_key.split(":", 1)

    url = f"{_DEHASHED_BASE}/search"
    params = {"query": query, "size": _DEFAULT_LIMIT}

    try:
        async with aiohttp.ClientSession(
            auth=aiohttp.BasicAuth(email_part, api_key),
            timeout=aiohttp.ClientTimeout(total=_TIMEOUT),
            headers={"Accept": "application/json"},
        ) as session:
            async with session.get(url, params=params) as resp:
                if resp.status == 401:
                    print("[dehashed] 401 Unauthorized — verificar DEHASHED_API_KEY.")
                    return []
                if resp.status == 402:
                    print("[dehashed] 402 — sin créditos disponibles en DeHashed.")
                    return []
                if resp.status != 200:
                    print(f"[dehashed] HTTP {resp.status}")
                    return []
                data = await resp.json()
                return data.get("entries", []) or []
    except asyncio.TimeoutError:
        print("[dehashed] Timeout")
        return []
    except Exception as e:
        print(f"[dehashed] Error: {type(e).__name__}: {e}")
        return []


def _entry_to_finding(entry: dict, selector_type: SelectorType, selector_value: str) -> Optional[Finding]:
    if not entry:
        return None

    breach_name = entry.get("database_name", "Unknown")
    email_val   = entry.get("email", "")
    username    = entry.get("username", "")
    has_password = bool(entry.get("password") or entry.get("hashed_password"))

    # Sensibilidad: si hay credenciales → HIGH
    sensitivity = Sensitivity.HIGH if has_password else Sensitivity.MEDIUM

    meta = {
        "breach_name":      breach_name,
        "email":            email_val,
        "username":         username,
        "ip":               entry.get("ip_address", ""),
        "name":             entry.get("name", ""),
        "phone":            entry.get("phone", ""),
        "has_password":     has_password,
        "has_hash":         bool(entry.get("hashed_password")),
        "breach_id":        entry.get("id", ""),
    }
    # Campos HIGH — el GraphPersister cifrará password antes de persistir
    if has_password:
        meta["password"] = entry.get("password") or entry.get("hashed_password") or ""

    new_selectors: list[dict] = []
    if email_val and selector_type != SelectorType.EMAIL:
        new_selectors.append({"type": SelectorType.EMAIL.value, "value": email_val})
    if entry.get("ip_address"):
        new_selectors.append({"type": SelectorType.IP.value, "value": entry["ip_address"]})

    return Finding(
        selector_type  = selector_type,
        selector_value = selector_value,
        entity_type    = "Brecha",
        url            = f"dehashed://breach/{breach_name}",
        platform       = f"DeHashed:{breach_name}",
        confidence     = 0.85,
        metadata       = meta,
        new_selectors  = new_selectors,
        sensitivity    = sensitivity,
    )
