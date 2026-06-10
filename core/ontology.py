from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class EntityType(str, Enum):
    PERSONA       = "Persona"
    USERNAME      = "Username"
    EMAIL         = "Email"
    TELEFONO      = "Telefono"
    CUENTA        = "Cuenta"
    DOMINIO       = "Dominio"
    IP            = "IP"
    DISPOSITIVO   = "Dispositivo"
    ORGANIZACION  = "Organizacion"
    BRECHA        = "Brecha"
    EVIDENCIA     = "Evidencia"
    PLATAFORMA    = "Plataforma"


class RelationType(str, Enum):
    USA           = "USA"           # Persona → Username/Email/Telefono
    CONTROLA      = "CONTROLA"      # Persona → Cuenta
    IDENTIFICA    = "IDENTIFICA"    # Username → Cuenta
    REGISTRA      = "REGISTRA"      # Email → Cuenta
    EXPUESTO_EN   = "EXPUESTO_EN"   # Email → Brecha
    ALOJADA_EN    = "ALOJADA_EN"    # Cuenta → Plataforma
    POSEE         = "POSEE"         # Organizacion → Dominio
    RESUELVE_A    = "RESUELVE_A"    # Dominio → IP
    EXPONE        = "EXPONE"        # IP → Dispositivo
    ASOCIADA_A    = "ASOCIADA_A"    # Persona → Organizacion
    MISMO_ACTOR   = "MISMO_ACTOR_QUE"   # REQUIERE HITL — fusión de identidades
    RESPALDA      = "RESPALDA"      # Evidencia → cualquier relación


class Sensitivity(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"   # Credenciales, PII, documentos identidad → AES-256-GCM


@dataclass
class BaseEntity:
    """Propiedades obligatorias en TODOS los nodos del grafo."""
    id:          str
    entity_type: EntityType
    confianza:   float       # 0.0–1.0 — sin confianza no entra al grafo
    fuente:      str         # módulo que lo descubrió
    origen_caso: str         # case_id que originó el hallazgo
    created_at:  datetime    = field(default_factory=datetime.utcnow)
    sensitivity: Sensitivity = Sensitivity.LOW
    metadata:    dict        = field(default_factory=dict)

    def validate(self) -> None:
        if not self.id:
            raise ValueError("Entity.id es obligatorio")
        if not (0.0 <= self.confianza <= 1.0):
            raise ValueError(f"confianza debe ser 0.0-1.0, recibido: {self.confianza}")
        if not self.fuente:
            raise ValueError("Entity.fuente es obligatorio — sin procedencia no entra al grafo")
        if not self.origen_caso:
            raise ValueError("Entity.origen_caso es obligatorio")


@dataclass
class PersonaEntity(BaseEntity):
    nombre:   Optional[str] = None
    alias:    list[str]     = field(default_factory=list)
    pais:     Optional[str] = None

    def __post_init__(self):
        self.entity_type = EntityType.PERSONA


@dataclass
class UsernameEntity(BaseEntity):
    value:    str = ""

    def __post_init__(self):
        self.entity_type = EntityType.USERNAME


@dataclass
class EmailEntity(BaseEntity):
    address:  str = ""

    def __post_init__(self):
        self.entity_type = EntityType.EMAIL


@dataclass
class DominioEntity(BaseEntity):
    name:     str = ""
    tld:      str = ""

    def __post_init__(self):
        self.entity_type = EntityType.DOMINIO


@dataclass
class IPEntity(BaseEntity):
    address:  str           = ""
    asn:      Optional[str] = None
    org:      Optional[str] = None
    country:  Optional[str] = None

    def __post_init__(self):
        self.entity_type = EntityType.IP


@dataclass
class CuentaEntity(BaseEntity):
    url:      str = ""
    platform: str = ""
    username: str = ""
    activa:   bool = True

    def __post_init__(self):
        self.entity_type = EntityType.CUENTA


@dataclass
class BrechaEntity(BaseEntity):
    nombre:         str           = ""
    fecha_brecha:   Optional[str] = None
    registros:      int           = 0
    tipos_dato:     list[str]     = field(default_factory=list)

    def __post_init__(self):
        self.entity_type = EntityType.BRECHA


@dataclass
class EntityRelation:
    """Relación entre dos entidades del grafo."""
    source_id:    str
    target_id:    str
    relation:     RelationType
    confianza:    float
    evidencia_id: Optional[str] = None
    metadata:     dict          = field(default_factory=dict)
    created_at:   datetime      = field(default_factory=datetime.utcnow)
    reviewed_by:  Optional[str] = None  # USER_ID — obligatorio para MISMO_ACTOR_QUE

    def validate(self) -> None:
        if self.relation == RelationType.MISMO_ACTOR and not self.reviewed_by:
            raise ValueError(
                "MISMO_ACTOR_QUE requiere reviewed_by (aprobación humana HITL). "
                "Usa /api/entities/resolve con aprobación explícita."
            )
        if not (0.0 <= self.confianza <= 1.0):
            raise ValueError(f"confianza debe ser 0.0-1.0, recibido: {self.confianza}")
