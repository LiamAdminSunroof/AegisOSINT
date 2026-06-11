"""
Email probe module — OSINT pasivo sobre direcciones de email.
- Valida formato
- MX lookup del dominio
- Detección de proveedores desechables (disposable)
- Genera nuevos selectors: dominio + username
Sin API key — todo pasivo.
"""
import asyncio
import re
import socket
from typing import Optional

import aiohttp

from collector.base_module import (
    CollectorModule, Finding, RateLimit,
    SelectorType, Sensitivity, MODULE_STATUS_STABLE,
)

# Proveedores desechables conocidos
_DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "guerrillamail.com", "10minutemail.com",
    "yopmail.com", "throwaway.email", "trashmail.com", "fakeinbox.com",
    "sharklasers.com", "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "spam4.me", "spamgourmet.com", "dispostable.com", "mailnull.com",
    "spamhereplease.com", "spam.la", "deadaddress.com", "emailondeck.com",
}

# Grandes proveedores gratuitos (señal de correo personal, no corporativo)
_FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "protonmail.com", "proton.me", "tutanota.com",
    "aol.com", "mail.com", "gmx.com", "zoho.com",
    # LATAM
    "yahoo.com.mx", "yahoo.es", "hotmail.es", "hotmail.com.mx",
    "gmail.cl", "terra.cl", "vtr.cl", "entel.cl",
}

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$")


class EmailMxProbe:
    name             = "email_mx_probe"
    family           = "identidad"
    accepts          = [SelectorType.EMAIL]
    tags             = ["email", "domain", "identity"]
    rate_limit       = RateLimit(requests_per_second=2.0, burst=5)
    requires_api_key = False
    status           = MODULE_STATUS_STABLE

    async def collect(
        self,
        selector_type:  SelectorType,
        selector_value: str,
        context:        dict,
    ) -> list[Finding]:
        if selector_type != SelectorType.EMAIL:
            return []

        email = selector_value.strip().lower()
        if not _EMAIL_RE.match(email):
            print(f"[email_mx_probe] Formato inválido: {email}")
            return []

        local, domain = email.split("@", 1)
        findings: list[Finding] = []

        # 1. MX lookup async
        mx_info = await _mx_lookup(domain)
        is_disposable = domain in _DISPOSABLE_DOMAINS
        is_free = domain in _FREE_PROVIDERS

        email_type = "corporate"
        if is_disposable:
            email_type = "disposable"
        elif is_free:
            email_type = "free_provider"

        confidence = 0.7
        if mx_info:
            confidence = 0.85
        if is_disposable:
            confidence = 0.95  # alta confianza de que es temporal

        findings.append(Finding(
            selector_type  = SelectorType.EMAIL,
            selector_value = email,
            entity_type    = "Email",
            url            = f"mailto:{email}",
            platform       = f"Email({domain})",
            confidence     = confidence,
            metadata       = {
                "domain":       domain,
                "local_part":   local,
                "mx_records":   mx_info,
                "is_disposable": is_disposable,
                "is_free":       is_free,
                "email_type":   email_type,
            },
            new_selectors  = [
                {"type": SelectorType.DOMAIN.value,   "value": domain},
                {"type": SelectorType.USERNAME.value, "value": local},
            ],
            sensitivity    = Sensitivity.LOW,
        ))

        # 2. Verificación gravatar (avatar asociado → confirma email activo)
        gravatar = await _check_gravatar(email)
        if gravatar:
            findings.append(Finding(
                selector_type  = SelectorType.EMAIL,
                selector_value = email,
                entity_type    = "Cuenta",
                url            = gravatar["profile_url"],
                platform       = "Gravatar",
                confidence     = 0.90,
                metadata       = {"avatar_url": gravatar["avatar_url"], "hash": gravatar["hash"]},
                sensitivity    = Sensitivity.LOW,
            ))

        print(f"[email_mx_probe] {email} → {len(findings)} findings (mx={bool(mx_info)}, type={email_type})")
        return findings


async def _mx_lookup(domain: str) -> list[str]:
    """DNS MX lookup asíncrono usando socket en thread pool."""
    try:
        loop = asyncio.get_event_loop()
        mx_info = await loop.run_in_executor(None, _sync_mx_lookup, domain)
        return mx_info
    except Exception:
        return []


def _sync_mx_lookup(domain: str) -> list[str]:
    try:
        import dns.resolver  # dnspython opcional
        answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
        return sorted([str(r.exchange).rstrip(".") for r in answers])
    except ImportError:
        # Fallback sin dnspython: verificar A record existe
        try:
            socket.setdefaulttimeout(5)
            socket.getaddrinfo(domain, None)
            return [f"A:{domain}"]
        except Exception:
            return []
    except Exception:
        return []


async def _check_gravatar(email: str) -> Optional[dict]:
    """Verifica si el email tiene perfil Gravatar (hash MD5 del email)."""
    import hashlib
    email_hash = hashlib.md5(email.encode()).hexdigest()
    profile_url = f"https://www.gravatar.com/{email_hash}"
    avatar_url  = f"https://www.gravatar.com/avatar/{email_hash}?d=404"

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as session:
            async with session.get(avatar_url) as resp:
                if resp.status == 200:
                    return {
                        "hash":        email_hash,
                        "avatar_url":  avatar_url,
                        "profile_url": profile_url,
                    }
    except Exception:
        pass
    return None
