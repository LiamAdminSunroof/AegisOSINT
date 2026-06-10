from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


class SelectorType(str, Enum):
    USERNAME = "username"
    EMAIL    = "email"
    PHONE    = "phone"
    DOMAIN   = "domain"
    IP       = "ip"
    IMAGE    = "image"
    NAME     = "name"


class Sensitivity(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"   # → AES-256-GCM antes de persistir


@dataclass
class RateLimit:
    requests_per_second: float = 1.0
    burst: int = 3


@dataclass
class Finding:
    """Hallazgo normalizado de un módulo OSINT."""
    selector_type:   SelectorType
    selector_value:  str
    entity_type:     str             # "Cuenta", "Brecha", "IP", etc.
    url:             str
    platform:        str
    confidence:      float           # 0.0–1.0
    metadata:        dict            = field(default_factory=dict)
    new_selectors:   list[dict]      = field(default_factory=list)  # para recursión
    evidence_url:    str             = ""    # GCS path del snapshot forense
    evidence_hash:   str             = ""    # SHA-256
    lineage:         dict            = field(default_factory=dict)
    sensitivity:     Sensitivity     = Sensitivity.LOW

    def validate(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence debe ser 0.0-1.0, recibido: {self.confidence}")
        if not self.platform:
            raise ValueError("Finding.platform es obligatorio")
        if not self.entity_type:
            raise ValueError("Finding.entity_type es obligatorio")


MODULE_STATUS_STABLE   = "stable"
MODULE_STATUS_UNSTABLE = "unstable"   # fallback silencioso, no rompe pipeline
MODULE_STATUS_REQUIRES_KEY = "requires_api_key"


@runtime_checkable
class CollectorModule(Protocol):
    name:             str
    family:           str          # identidad | infraestructura | brechas | web | imagen
    accepts:          list[SelectorType]
    tags:             list[str]    # social, dev, country_CL, infra, etc.
    rate_limit:       RateLimit
    requires_api_key: bool
    status:           str          # MODULE_STATUS_*

    async def collect(
        self,
        selector_type:  SelectorType,
        selector_value: str,
        context:        dict,
    ) -> list[Finding]: ...
