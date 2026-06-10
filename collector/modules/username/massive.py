"""
Username massive checker — Maigret-style.
Lee sites_db/sites.json y verifica en paralelo con aiohttp.
"""
import asyncio
import json
import os
from pathlib import Path

import aiohttp

from collector.base_module import (
    CollectorModule, Finding, RateLimit,
    SelectorType, Sensitivity, MODULE_STATUS_STABLE,
)
from config import CONFIDENCE_THRESHOLDS

SITES_DB_PATH = Path(__file__).parent.parent.parent.parent / "sites_db" / "sites.json"

# Concurrencia máxima por defecto
DEFAULT_CONCURRENCY = 50
DEFAULT_TIMEOUT     = 15  # segundos por petición


def _load_sites() -> list[dict]:
    if not SITES_DB_PATH.exists():
        return []
    with open(SITES_DB_PATH) as f:
        return json.load(f)


class UsernameChecker:
    """
    Verifica un username en N sitios de la base de datos sites.json.
    Lógica de detección: HTTP 200 + no contiene el error_text del sitio.
    """

    name             = "username_massive"
    family           = "identidad"
    accepts          = [SelectorType.USERNAME]
    tags             = ["social", "dev", "forums"]
    rate_limit       = RateLimit(requests_per_second=10.0, burst=50)
    requires_api_key = False
    status           = MODULE_STATUS_STABLE

    async def collect(
        self,
        selector_type:  SelectorType,
        selector_value: str,
        context:        dict,
    ) -> list[Finding]:
        if selector_type != SelectorType.USERNAME:
            return []

        username = selector_value.strip()
        sites    = _load_sites()
        if not sites:
            print("[username_massive] WARN: sites_db/sites.json vacío o no encontrado")
            return []

        semaphore = asyncio.Semaphore(DEFAULT_CONCURRENCY)
        connector = aiohttp.TCPConnector(limit=DEFAULT_CONCURRENCY, ssl=False)
        timeout   = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AEGIS-OSINT/1.0)"},
        ) as session:
            tasks = [
                self._check_site(session, semaphore, site, username, context)
                for site in sites
                if "{username}" in site.get("url_template", "")
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        findings = [r for r in results if isinstance(r, Finding)]
        print(f"[username_massive] {username} → {len(findings)}/{len(sites)} encontrados")
        return findings

    async def _check_site(
        self,
        session:   aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        site:      dict,
        username:  str,
        context:   dict,
    ) -> Finding | None:
        url = site["url_template"].replace("{username}", username)
        error_text = site.get("error_text", "")

        async with semaphore:
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        # Si el sitio tiene error_text y está presente → no existe
                        if error_text and error_text in body:
                            return None
                        # Existe: con perfil detectado = alta confianza
                        has_profile = _detect_profile_signals(body, username, site)
                        confidence  = (
                            CONFIDENCE_THRESHOLDS["http_200_with_profile"]
                            if has_profile
                            else CONFIDENCE_THRESHOLDS["http_200_only"]
                        )
                        return Finding(
                            selector_type  = SelectorType.USERNAME,
                            selector_value = username,
                            entity_type    = "Cuenta",
                            url            = str(resp.url),
                            platform       = site.get("name", url),
                            confidence     = confidence,
                            metadata       = {
                                "site_family": site.get("family", ""),
                                "tags":        site.get("tags", []),
                                "http_status": resp.status,
                                "has_profile": has_profile,
                            },
                            new_selectors  = [],
                            sensitivity    = Sensitivity.LOW,
                        )
                    elif resp.status in (301, 302, 303, 307, 308):
                        return Finding(
                            selector_type  = SelectorType.USERNAME,
                            selector_value = username,
                            entity_type    = "Cuenta",
                            url            = url,
                            platform       = site.get("name", url),
                            confidence     = CONFIDENCE_THRESHOLDS["redirect"],
                            metadata       = {"http_status": resp.status, "tags": site.get("tags", [])},
                            sensitivity    = Sensitivity.LOW,
                        )
            except asyncio.TimeoutError:
                pass
            except aiohttp.ClientError:
                pass
            except Exception as e:
                print(f"[username_massive] Error en {url}: {type(e).__name__}")
        return None


def _detect_profile_signals(body: str, username: str, site: dict) -> bool:
    """Heurística simple: el username aparece en el body con señales de perfil."""
    body_lower  = body.lower()
    uname_lower = username.lower()
    profile_signals = site.get("profile_signals", [])
    if profile_signals:
        return any(sig.lower() in body_lower for sig in profile_signals)
    # Fallback: username presente + alguna señal genérica de perfil
    return uname_lower in body_lower and any(
        kw in body_lower for kw in ("profile", "perfil", "avatar", "bio", "followers", "following")
    )
