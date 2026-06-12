"""
OTX AlienVault Threat Intelligence module.
API key gratuita — registro en otx.alienvault.com (sin límite documentado).
Soporta: IP, DOMAIN.
Retorna pulsos de threat intel, actores APT y tags maliciosos.
"""
import aiohttp

from collector.base_module import (
    CollectorModule, Finding, RateLimit,
    SelectorType, Sensitivity,
    MODULE_STATUS_STABLE, MODULE_STATUS_REQUIRES_KEY,
)
from config import OTX_API_KEY

_TIMEOUT  = aiohttp.ClientTimeout(total=12)
_OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

# Selector type → segmento de URL OTX
_OTX_PATHS = {
    SelectorType.IP:     "IPv4/{value}/general",
    SelectorType.DOMAIN: "domain/{value}/general",
}

# Tags OTX que clasifican como HIGH sensitivity
_HIGH_SEVERITY_TAGS = {
    "ransomware", "apt", "malware", "c2", "botnet",
    "trojan", "backdoor", "rootkit", "keylogger", "rat",
    "exploit", "zero-day", "0day", "darkweb",
}


class OtxThreatModule:
    name             = "otx_threat"
    family           = "threat"
    accepts          = [SelectorType.IP, SelectorType.DOMAIN]
    tags             = ["threat", "ioc", "intel", "infra", "apt"]
    rate_limit       = RateLimit(requests_per_second=0.5, burst=2)
    requires_api_key = True
    status           = MODULE_STATUS_STABLE if OTX_API_KEY else MODULE_STATUS_REQUIRES_KEY

    async def collect(
        self,
        selector_type:  SelectorType,
        selector_value: str,
        context:        dict,
    ) -> list[Finding]:
        if not OTX_API_KEY:
            return []

        if selector_type not in _OTX_PATHS:
            return []

        path = _OTX_PATHS[selector_type].format(value=selector_value.strip())
        url  = f"{_OTX_BASE}/{path}"

        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                async with session.get(
                    url,
                    headers={"X-OTX-API-KEY": OTX_API_KEY},
                ) as resp:
                    if resp.status != 200:
                        print(f"[otx_threat] HTTP {resp.status} para {selector_value}")
                        return []
                    data = await resp.json()
        except Exception as e:
            print(f"[otx_threat] Error: {type(e).__name__}: {e}")
            return []

        pulse_info  = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0) or 0

        if pulse_count == 0:
            print(f"[otx_threat] {selector_value} → 0 pulsos OTX (limpio)")
            return []

        # Extraer metadata de los pulsos más recientes
        pulses   = (pulse_info.get("pulses") or [])[:10]
        all_tags = list({
            t.lower()
            for p in pulses
            for t in (p.get("tags") or [])
        })[:20]

        is_high = bool(_HIGH_SEVERITY_TAGS & set(all_tags))

        # Confianza: sube con cantidad de pulsos, cap 0.97
        confidence = round(min(0.70 + pulse_count * 0.02, 0.97), 2)

        finding = Finding(
            selector_type  = selector_type,
            selector_value = selector_value,
            entity_type    = "ThreatIntel",
            url            = url,
            platform       = "OTX_AlienVault",
            confidence     = confidence,
            metadata       = {
                "pulse_count":    pulse_count,
                "tags":           all_tags,
                "is_high_threat": is_high,
                "pulses": [
                    {
                        "name":    p.get("name", ""),
                        "created": p.get("created", ""),
                        "author":  p.get("author_name", ""),
                        "tlp":     p.get("tlp", ""),
                        "tags":    (p.get("tags") or [])[:5],
                    }
                    for p in pulses
                ],
            },
            new_selectors  = [],
            sensitivity    = Sensitivity.HIGH if is_high else Sensitivity.MEDIUM,
        )
        finding.validate()

        print(
            f"[otx_threat] {selector_value} → {pulse_count} pulsos OTX "
            f"| sensitivity={'HIGH' if is_high else 'MEDIUM'}"
        )
        return [finding]
