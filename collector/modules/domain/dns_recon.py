"""
DNS Recon module — OSINT pasivo sobre dominios.
Registros A · AAAA · MX · TXT · NS · CNAME · SOA.
Sin API key — DNS público.
Genera nuevos selectors: IPs encontradas.
"""
import asyncio
import socket
from typing import Optional

from collector.base_module import (
    CollectorModule, Finding, RateLimit,
    SelectorType, Sensitivity, MODULE_STATUS_STABLE,
)

# Record types a consultar
_DNS_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

# TLDs de riesgo elevado (dominios de phishing frecuentes)
_HIGH_RISK_TLDS = {".ru", ".tk", ".top", ".xyz", ".work", ".club", ".click", ".gq", ".ml", ".cf", ".ga"}

# CDNs/hosting conocidos (para enriquecer metadata)
_KNOWN_PROVIDERS = {
    "cloudflare":   ["cloudflare.com", "cloudflare.net"],
    "aws":          ["amazonaws.com", "aws.amazon.com", "cloudfront.net"],
    "gcp":          ["googleapis.com", "cloud.google.com", "googlehosted.com"],
    "azure":        ["azure.com", "azurewebsites.net", "windows.net"],
    "vercel":       ["vercel.app", "vercel.com"],
    "github":       ["github.io", "githubusercontent.com"],
    "shopify":      ["shopify.com", "myshopify.com"],
    "godaddy":      ["domaincontrol.com", "godaddy.com"],
}


class DnsReconModule:
    name             = "dns_recon"
    family           = "infraestructura"
    accepts          = [SelectorType.DOMAIN]
    tags             = ["dns", "infra", "domain"]
    rate_limit       = RateLimit(requests_per_second=1.0, burst=3)
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

        # Verificar scope — DNS es passivo y solo lectura, siempre permitido
        loop   = asyncio.get_event_loop()
        records = await loop.run_in_executor(None, _sync_dns_lookup, domain)

        if not records:
            print(f"[dns_recon] Sin registros DNS para {domain}")
            return []

        findings: list[Finding] = []
        new_selectors: list[dict] = []

        # IPs A/AAAA → nuevos selectors IP
        ips_a = records.get("A", [])
        ips_aaaa = records.get("AAAA", [])
        for ip in ips_a + ips_aaaa:
            new_selectors.append({"type": SelectorType.IP.value, "value": ip})

        # Análisis de riesgo
        tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
        is_high_risk_tld = tld in _HIGH_RISK_TLDS
        provider = _detect_provider(records)

        # Subdominios de interés en TXT (SPF/DMARC/DKIM revelan infraestructura)
        txt_records = records.get("TXT", [])
        infra_signals = _analyze_txt(txt_records)

        # Confianza: dominio con registros A/MX = real
        has_web = bool(ips_a or ips_aaaa)
        has_mail = bool(records.get("MX"))
        confidence = 0.60
        if has_web:
            confidence = 0.85
        if has_web and has_mail:
            confidence = 0.92

        findings.append(Finding(
            selector_type  = SelectorType.DOMAIN,
            selector_value = domain,
            entity_type    = "Dominio",
            url            = f"https://{domain}",
            platform       = "DNS",
            confidence     = confidence,
            metadata       = {
                "records":         records,
                "provider":        provider,
                "is_high_risk_tld": is_high_risk_tld,
                "has_web":         has_web,
                "has_mail":        has_mail,
                "infra_signals":   infra_signals,
                "tld":             tld,
                "ip_count":        len(ips_a + ips_aaaa),
            },
            new_selectors  = new_selectors,
            sensitivity    = Sensitivity.LOW,
        ))

        # Finding extra: registros MX como dominios relacionados
        for mx_host in records.get("MX", []):
            mx_clean = mx_host.split(" ")[-1].rstrip(".") if " " in mx_host else mx_host.rstrip(".")
            if mx_clean and mx_clean != domain:
                findings.append(Finding(
                    selector_type  = SelectorType.DOMAIN,
                    selector_value = domain,
                    entity_type    = "Dominio",
                    url            = f"https://{mx_clean}",
                    platform       = f"MX:{mx_clean}",
                    confidence     = 0.70,
                    metadata       = {"parent_domain": domain, "record_type": "MX"},
                    new_selectors  = [{"type": SelectorType.DOMAIN.value, "value": mx_clean}],
                    sensitivity    = Sensitivity.LOW,
                ))

        print(f"[dns_recon] {domain} → {len(findings)} findings | IPs: {len(new_selectors)}")
        return findings


def _sync_dns_lookup(domain: str) -> dict:
    """Resolución DNS síncrona usando dnspython o fallback socket."""
    try:
        import dns.resolver
        import dns.exception
        results = {}
        for rtype in _DNS_TYPES:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5.0)
                results[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.exception.Timeout, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass
        return results
    except ImportError:
        # Fallback minimal: solo A record con socket
        try:
            ips = [r[4][0] for r in socket.getaddrinfo(domain, None)]
            return {"A": list(set(ips))} if ips else {}
        except Exception:
            return {}


def _detect_provider(records: dict) -> Optional[str]:
    all_vals = []
    for rtype, vals in records.items():
        all_vals.extend([v.lower() for v in vals])
    combined = " ".join(all_vals)
    for provider, patterns in _KNOWN_PROVIDERS.items():
        if any(p in combined for p in patterns):
            return provider
    return None


def _analyze_txt(txt_records: list[str]) -> dict:
    """Extrae señales de infraestructura de registros TXT."""
    signals = {"spf": False, "dmarc": False, "dkim": False, "services": []}
    service_patterns = {
        "google_workspace": "google-site-verification",
        "microsoft365":     "ms=ms",
        "hubspot":          "hubspot",
        "stripe":           "stripe-verification",
        "sendgrid":         "sendgrid",
        "mailchimp":        "mailchimp",
        "zendesk":          "zendesk",
        "salesforce":       "salesforce",
        "atlassian":        "atlassian",
        "shopify":          "shopify",
    }
    for txt in txt_records:
        t = txt.lower()
        if t.startswith("v=spf1"):
            signals["spf"] = True
        if "v=dmarc1" in t:
            signals["dmarc"] = True
        if "v=dkim1" in t or "k=rsa" in t:
            signals["dkim"] = True
        for svc, pattern in service_patterns.items():
            if pattern in t and svc not in signals["services"]:
                signals["services"].append(svc)
    return signals
