"""
IP Recon module — OSINT pasivo sobre IPs.
Shodan InternetDB (sin key) · ipinfo.io (sin key/token) · AbuseIPDB (free key) · VirusTotal (free key)
Tier 0: $0/mes — cubre ~80% de casos OSINT reales.
"""
import asyncio
import ipaddress

import aiohttp

from collector.base_module import (
    CollectorModule, Finding, RateLimit,
    SelectorType, Sensitivity, MODULE_STATUS_STABLE,
)
from config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, IPINFO_TOKEN

_TIMEOUT = aiohttp.ClientTimeout(total=12)

# IPs/rangos conocidos de infraestructura cloud (contexto adicional)
_CLOUD_ASN_KEYWORDS = {
    "amazon":    "AWS",
    "google":    "GCP",
    "microsoft": "Azure",
    "cloudflare":"Cloudflare",
    "digitalocean": "DigitalOcean",
    "linode":    "Akamai/Linode",
    "vultr":     "Vultr",
    "hetzner":   "Hetzner",
    "ovh":       "OVH",
}


class IpReconModule:
    name             = "ip_recon"
    family           = "infraestructura"
    accepts          = [SelectorType.IP]
    tags             = ["ip", "infra", "network", "threat"]
    rate_limit       = RateLimit(requests_per_second=0.5, burst=2)
    requires_api_key = False   # Shodan InternetDB e ipinfo son 100% gratuitos sin key
    status           = MODULE_STATUS_STABLE

    async def collect(
        self,
        selector_type:  SelectorType,
        selector_value: str,
        context:        dict,
    ) -> list[Finding]:
        if selector_type != SelectorType.IP:
            return []

        ip = selector_value.strip()
        if not _is_valid_public_ip(ip):
            return []

        # Fan-out async — 4 APIs en paralelo
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            results = await asyncio.gather(
                _fetch_shodan_internetdb(session, ip),
                _fetch_ipinfo(session, ip),
                _fetch_abuseipdb(session, ip),
                _fetch_virustotal(session, ip),
                return_exceptions=True,
            )

        shodan_data = results[0] if isinstance(results[0], dict) else {}
        ipinfo_data = results[1] if isinstance(results[1], dict) else {}
        abuse_data  = results[2] if isinstance(results[2], dict) else {}
        vt_data     = results[3] if isinstance(results[3], dict) else {}

        if not any([shodan_data, ipinfo_data, abuse_data, vt_data]):
            print(f"[ip_recon] Sin datos para {ip}")
            return []

        # Hostnames → nuevos selectors de tipo DOMAIN
        hostnames     = shodan_data.get("hostnames", []) or []
        new_selectors = [
            {"type": SelectorType.DOMAIN.value, "value": h}
            for h in hostnames[:5]
            if h and "." in h
        ]

        # Scoring de sensibilidad por threat indicators
        vulns         = shodan_data.get("vulns", []) or []
        abuse_score   = abuse_data.get("abuseConfidenceScore", 0) or 0
        vt_malicious  = vt_data.get("malicious_count", 0) or 0

        if vulns or abuse_score > 50 or vt_malicious > 3:
            sensitivity = Sensitivity.HIGH
        elif abuse_score > 20 or vt_malicious > 0:
            sensitivity = Sensitivity.MEDIUM
        else:
            sensitivity = Sensitivity.LOW

        # Confianza proporcional a fuentes que respondieron
        sources_ok = sum([bool(shodan_data), bool(ipinfo_data), bool(abuse_data), bool(vt_data)])
        confidence = round(min(0.60 + sources_ok * 0.08, 0.95), 2)

        # Identificar provider cloud por ASN
        org         = ipinfo_data.get("org", "")
        cloud_label = _detect_cloud_provider(org)

        platform = f"IP/{ipinfo_data.get('country', '??')}/{(org[:28] or 'ASN desconocido')}"

        finding = Finding(
            selector_type  = SelectorType.IP,
            selector_value = ip,
            entity_type    = "IP",
            url            = f"https://internetdb.shodan.io/{ip}",
            platform       = platform,
            confidence     = confidence,
            metadata       = {
                "ports":        shodan_data.get("ports", []),
                "vulns":        vulns,
                "hostnames":    hostnames,
                "cpes":         shodan_data.get("cpes", []) or [],
                "abuse_score":  abuse_score,
                "abuse_total_reports": abuse_data.get("totalReports", 0),
                "abuse_country":       abuse_data.get("countryCode", ""),
                "abuse_usage_type":    abuse_data.get("usageType", ""),
                "isp":                 abuse_data.get("isp", "") or vt_data.get("as_owner", ""),
                "vt_malicious":        vt_malicious,
                "vt_suspicious":       vt_data.get("suspicious_count", 0),
                "vt_reputation":       vt_data.get("reputation", 0),
                "geo_country":         ipinfo_data.get("country", ""),
                "geo_city":            ipinfo_data.get("city", ""),
                "geo_region":          ipinfo_data.get("region", ""),
                "geo_loc":             ipinfo_data.get("loc", ""),
                "geo_org":             org,
                "geo_timezone":        ipinfo_data.get("timezone", ""),
                "cloud_provider":      cloud_label,
                "sources_queried":     sources_ok,
            },
            new_selectors  = new_selectors,
            sensitivity    = sensitivity,
        )
        finding.validate()

        print(
            f"[ip_recon] {ip} → puertos={len(shodan_data.get('ports', []))} "
            f"CVEs={len(vulns)} abuse={abuse_score} VT={vt_malicious}"
        )
        return [finding]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_valid_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private or addr.is_loopback
            or addr.is_multicast or addr.is_reserved
            or addr.is_unspecified or addr.is_link_local
        )
    except ValueError:
        return False


def _detect_cloud_provider(org: str) -> str:
    org_lower = org.lower()
    for keyword, label in _CLOUD_ASN_KEYWORDS.items():
        if keyword in org_lower:
            return label
    return ""


async def _fetch_shodan_internetdb(session: aiohttp.ClientSession, ip: str) -> dict:
    """Shodan InternetDB — sin API key — puertos, CVEs, hostnames."""
    try:
        async with session.get(f"https://internetdb.shodan.io/{ip}") as resp:
            return await resp.json() if resp.status == 200 else {}
    except Exception:
        return {}


async def _fetch_ipinfo(session: aiohttp.ClientSession, ip: str) -> dict:
    """ipinfo.io — 50k req/mes gratis — geolocalización + ASN."""
    try:
        headers = {"Authorization": f"Bearer {IPINFO_TOKEN}"} if IPINFO_TOKEN else {}
        async with session.get(f"https://ipinfo.io/{ip}/json", headers=headers) as resp:
            return await resp.json() if resp.status == 200 else {}
    except Exception:
        return {}


async def _fetch_abuseipdb(session: aiohttp.ClientSession, ip: str) -> dict:
    """AbuseIPDB — 1.000 req/día gratis — reputación + categorías de abuso."""
    if not ABUSEIPDB_API_KEY:
        return {}
    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params  = {"ipAddress": ip, "maxAgeInDays": 90}
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params,
        ) as resp:
            data = await resp.json() if resp.status == 200 else {}
            return data.get("data", {})
    except Exception:
        return {}


async def _fetch_virustotal(session: aiohttp.ClientSession, ip: str) -> dict:
    """VirusTotal — 500/día gratis — análisis antivirus de la IP."""
    if not VIRUSTOTAL_API_KEY:
        return {}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        async with session.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
        ) as resp:
            if resp.status != 200:
                return {}
            data  = await resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "country":         attrs.get("country", ""),
                "as_owner":        attrs.get("as_owner", ""),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count":stats.get("suspicious", 0),
                "harmless_count":  stats.get("harmless", 0),
                "reputation":      attrs.get("reputation", 0),
            }
    except Exception:
        return {}
