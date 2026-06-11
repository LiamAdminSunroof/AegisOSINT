"""
AEGIS_ORCHESTRATOR — agente de triaje y validación de casos.
Modelo: Haiku L1 (claude-haiku-4-5-20251001).
Función: valida que el requerimiento OSINT cumpla los guardarraíles legales y de gobernanza
         antes de despachar al motor de recolección.
"""
import json
from typing import Optional

import anthropic

from config import ANTHROPIC_API_KEY, MODEL_L1
from core.case_manager import LEGAL_BASIS_OPTIONS, CaseScope
from collector.base_module import SelectorType

_SYSTEM_PROMPT = """Eres AEGIS_ORCHESTRATOR, el agente de triaje y gobernanza del ecosistema OSINT AEGIS.
Tu función es validar si una solicitud de investigación OSINT cumple los siguientes criterios antes de autorizarla:

CRITERIOS DE VALIDACIÓN:
1. El objetivo (selector) debe ser una entidad válida (email, username, dominio, IP, nombre, teléfono).
2. El purpose debe ser específico, con ≥50 caracteres y justificación legítima.
3. El scope debe ser "own_assets", "authorized_third_party" u "open_source_only".
4. La base legal debe ser válida (CL/MX/GDPR — interés legítimo).
5. PROHIBIDO investigar infraestructura OT de SunRoof (plantas FV, Teltonika, ZeroTier).
6. PROHIBIDO si el selector es claramente un activista, periodista o figura política sin autorización explícita.

RESPONDE SIEMPRE en JSON con este schema:
{
  "approved": true/false,
  "selector_type": "username|email|domain|ip|phone|name",
  "risk_level": "LOW|MEDIUM|HIGH",
  "reason": "string",
  "suggested_legal_basis": "string o null",
  "warnings": ["string"]
}"""


class AegisOrchestrator:
    """
    Valida y triaje de solicitudes OSINT antes de crear el caso.
    """

    def __init__(self):
        if not ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY no configurado.")
        self._client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    def validate_request(
        self,
        target_selector:  str,
        purpose:          str,
        scope:            str,
        legal_basis:      str,
        requested_by:     str,
    ) -> dict:
        """
        Valida una solicitud de investigación OSINT.
        Retorna dict con approved, risk_level, reason, warnings.
        """
        prompt = f"""Valida la siguiente solicitud de investigación OSINT:

Objetivo: `{target_selector}`
Propósito: "{purpose}"
Scope: {scope}
Base legal: {legal_basis} — {LEGAL_BASIS_OPTIONS.get(legal_basis, "desconocida")}
Solicitado por: {requested_by}

Bases legales disponibles: {json.dumps(list(LEGAL_BASIS_OPTIONS.keys()))}

¿Debe ser aprobada? Responde en JSON según el schema indicado."""

        try:
            response = self._client.messages.create(
                model      = MODEL_L1,
                max_tokens = 512,
                system     = _SYSTEM_PROMPT,
                messages   = [{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            # Limpiar markdown si aplica
            if raw.startswith("```"):
                raw = raw.strip("```").strip()
                if raw.lower().startswith("json"):
                    raw = raw[4:].strip()
            result = json.loads(raw)
            return result
        except (json.JSONDecodeError, Exception) as e:
            # Fallback seguro: denegar ante duda
            return {
                "approved":              False,
                "selector_type":         "unknown",
                "risk_level":            "HIGH",
                "reason":                f"Error en validación: {e}. Por seguridad, solicitud denegada.",
                "suggested_legal_basis": None,
                "warnings":              ["Validación falló — requiere revisión manual."],
            }

    def classify_selector(self, selector_value: str) -> Optional[SelectorType]:
        """Intenta inferir el tipo de selector a partir del valor."""
        import re
        s = selector_value.strip()
        if re.match(r"^[^@]+@[^@]+\.[^@]+$", s):
            return SelectorType.EMAIL
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
            return SelectorType.IP
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", s) and "." in s:
            return SelectorType.DOMAIN
        if re.match(r"^\+?\d{7,15}$", s.replace(" ", "").replace("-", "")):
            return SelectorType.PHONE
        # Default: username
        return SelectorType.USERNAME
