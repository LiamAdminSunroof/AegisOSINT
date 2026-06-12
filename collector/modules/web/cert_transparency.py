"""
Certificate Transparency module — subdomain discovery via crt.sh.
Sin API key — ilimitado — CT logs públicos (RFC 6962).
Genera nuevos selectors DOMAIN para recursión en el engine.
"""
import re
from typing import Set

import aiohttp

from collector.base_module import (
    CollectorModule, Finding, RateLimit,
    SelectorType, Sensitivity, MODULE_STATUS_STABLE,
)

_TIMEOUT     = aiohttp.ClientTimeout(total=20)
_WILDCARD_RE = re.compile(r"^\*\.")
_MAX_SUBDOMAINS = 50   # cap para evitar fan-out explosivo


class CertTransparencyModule:
    name             = "cert_transparency"
    family           = "web"
    accepts          = [SelectorType.DOMAIN]
    tags             = ["dns", "web", "subdomain", "ssl", "recon"]
    rate_limit       = RateLimit(requests_per_second=0.5, burst=2)
    requires_api_key = False
    status           = MODULE_STATUS_STABLE

    async def collect(
        self,
        selector_type:  SelectorType,
        selector_value: str,
        context:        dict,
    ) -> list[Finding]:
        if selector_type != SelectorType.DOMAIN:
            return []

        domain = selector_value.strip().lower().rstrip(".")
        if not domain or "." not in domain:
            return []

        subdomains = await _fetch_crtsh(domain)
        subdomains.discard(domain)   # el dominio raíz no es un subdomain

        if not subdomains:
            print(f"[cert_transparency] Sin subdominios para {domain}")
            return []

        capped        = sorted(subdomains)[:_MAX_SUBDOMAINS]
        new_selectors = [
            {"type": SelectorType.DOMAIN.value, "value": sub}
            for sub in capped
        ]

        finding = Finding(
            selector_type  = SelectorType.DOMAIN,
            selector_value = domain,
            entity_type    = "Subdominio",
            url            = f"https://crt.sh/?q=%.{domain}&output=json",
            platform       = "crt.sh",
            confidence     = 0.80,
            metadata       = {
                "subdomain_count": len(subdomains),
                "subdomains":      capped,
                "source":          "certificate_transparency_logs",
                "note":            "Solo mostrando primeros 50" if len(subdomains) > _MAX_SUBDOMAINS else "",
            },
            new_selectors  = new_selectors,
            sensitivity    = Sensitivity.LOW,
        )
        finding.validate()

        print(f"[cert_transparency] {domain} → {len(subdomains)} subdominios únicos")
        return [finding]


async def _fetch_crtsh(domain: str) -> Set[str]:
    """Consulta crt.sh y retorna set de subdominios únicos y válidos."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            async with session.get(url, headers={"Accept": "application/json"}) as resp:
                if resp.status != 200:
                    return set()
                records = await resp.json(content_type=None)

        subdomains: Set[str] = set()
        for record in records:
            name_value = record.get("name_value", "")
            for line in name_value.splitlines():
                line = line.strip().lower()
                line = _WILDCARD_RE.sub("", line)   # quitar wildcard *.
                # Validación mínima: contiene punto, no tiene espacios, pertenece al dominio
                if line and "." in line and " " not in line and domain in line:
                    subdomains.add(line)
        return subdomains

    except Exception as e:
        print(f"[cert_transparency] Error crt.sh: {type(e).__name__}: {e}")
        return set()
