import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Literal, Optional

from google.cloud import firestore

from config import GCP_PROJECT, DEFAULT_TTL_DAYS, MIN_PURPOSE_LEN, AEGIS_ADMINS


LEGAL_BASIS_OPTIONS = {
    # Chile — Ley 21.719
    "CL_defensa_organizacion": "Ley 21.719 Art. 13 — interés legítimo defensa",
    "CL_threat_intelligence":  "Ley 21.719 Art. 13 — interés legítimo seguridad",
    "CL_due_diligence":        "Ley 21.719 Art. 13 — interés legítimo contractual",
    # México — LFPDPPP
    "MX_defensa_organizacion": "LFPDPPP Art. 10 — interés legítimo defensa propia",
    "MX_threat_intelligence":  "LFPDPPP Art. 10 — seguridad informática",
    "MX_due_diligence":        "LFPDPPP Art. 10 — relación contractual",
    # Transfronterizo
    "GDPR_legitimate_interest": "GDPR Art. 6(1)(f) — interés legítimo",
}

CaseScope = Literal["own_assets", "authorized_third_party", "open_source_only"]


class CaseStatus(str, Enum):
    DRAFT       = "DRAFT"
    AUTHORIZED  = "AUTHORIZED"
    COLLECTING  = "COLLECTING"
    ANALYZING   = "ANALYZING"
    REPORTED    = "REPORTED"
    MONITORING  = "MONITORING"
    CLOSED      = "CLOSED"
    PURGED      = "PURGED"


@dataclass
class AuditEvent:
    ts:        str   # ISO datetime
    actor:     str   # USER_ID
    action:    str
    detail:    str


@dataclass
class OsintCase:
    id:               str
    created_by:       str
    purpose:          str         # ≥50 chars — obligatorio
    legal_basis:      str         # clave de LEGAL_BASIS_OPTIONS
    target_selector:  str
    authorized_by:    str
    scope:            CaseScope
    status:           CaseStatus  = CaseStatus.DRAFT
    ttl_days:         int         = DEFAULT_TTL_DAYS
    created_at:       datetime    = field(default_factory=datetime.utcnow)
    closed_at:        Optional[datetime] = None
    audit_log:        list        = field(default_factory=list)  # WORM — append-only

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "created_by":       self.created_by,
            "purpose":          self.purpose,
            "legal_basis":      self.legal_basis,
            "legal_basis_text": LEGAL_BASIS_OPTIONS.get(self.legal_basis, ""),
            "target_selector":  self.target_selector,
            "authorized_by":    self.authorized_by,
            "scope":            self.scope,
            "status":           self.status.value,
            "ttl_days":         self.ttl_days,
            "created_at":       self.created_at.isoformat(),
            "closed_at":        self.closed_at.isoformat() if self.closed_at else None,
            "audit_log":        self.audit_log,
            "purge_at":         (self.created_at + timedelta(days=self.ttl_days)).isoformat(),
        }


class CaseManager:
    """CRUD de casos OSINT con audit log WORM en Firestore."""

    COLLECTION = "aegis_cases"

    def __init__(self):
        self._db: Optional[firestore.Client] = None

    @property
    def db(self) -> firestore.Client:
        if self._db is None:
            self._db = firestore.Client(project=GCP_PROJECT)
        return self._db

    def create_case(
        self,
        created_by:      str,
        purpose:         str,
        legal_basis:     str,
        target_selector: str,
        authorized_by:   str,
        scope:           CaseScope,
        ttl_days:        int = DEFAULT_TTL_DAYS,
    ) -> OsintCase:
        # Validaciones de gobernanza — no negociables
        if len(purpose.strip()) < MIN_PURPOSE_LEN:
            raise ValueError(
                f"purpose debe tener ≥{MIN_PURPOSE_LEN} caracteres. "
                f"Recibido: {len(purpose.strip())} chars."
            )
        if legal_basis not in LEGAL_BASIS_OPTIONS:
            raise ValueError(
                f"legal_basis inválido: '{legal_basis}'. "
                f"Opciones: {list(LEGAL_BASIS_OPTIONS.keys())}"
            )
        if not authorized_by:
            raise ValueError("authorized_by es obligatorio.")
        if scope not in ("own_assets", "authorized_third_party", "open_source_only"):
            raise ValueError(f"scope inválido: '{scope}'.")

        case = OsintCase(
            id               = str(uuid.uuid4()),
            created_by       = created_by,
            purpose          = purpose,
            legal_basis      = legal_basis,
            target_selector  = target_selector,
            authorized_by    = authorized_by,
            scope            = scope,
            ttl_days         = ttl_days,
        )

        # Audit log inicial
        case.audit_log.append({
            "ts":     datetime.utcnow().isoformat(),
            "actor":  created_by,
            "action": "CASE_CREATED",
            "detail": f"scope={scope}, legal_basis={legal_basis}",
        })

        self.db.collection(self.COLLECTION).document(case.id).set(case.to_dict())
        return case

    def get_case(self, case_id: str) -> Optional[OsintCase]:
        doc = self.db.collection(self.COLLECTION).document(case_id).get()
        if not doc.exists:
            return None
        d = doc.to_dict()
        return OsintCase(
            id               = d["id"],
            created_by       = d["created_by"],
            purpose          = d["purpose"],
            legal_basis      = d["legal_basis"],
            target_selector  = d["target_selector"],
            authorized_by    = d["authorized_by"],
            scope            = d["scope"],
            status           = CaseStatus(d["status"]),
            ttl_days         = d["ttl_days"],
            created_at       = datetime.fromisoformat(d["created_at"]),
            closed_at        = datetime.fromisoformat(d["closed_at"]) if d.get("closed_at") else None,
            audit_log        = d.get("audit_log", []),
        )

    def update_status(self, case_id: str, new_status: CaseStatus, actor: str, detail: str = "") -> None:
        """Actualiza status + append audit log (WORM)."""
        ref = self.db.collection(self.COLLECTION).document(case_id)
        audit_entry = {
            "ts":     datetime.utcnow().isoformat(),
            "actor":  actor,
            "action": f"STATUS_CHANGED_TO_{new_status.value}",
            "detail": detail,
        }
        ref.update({
            "status":    new_status.value,
            "audit_log": firestore.ArrayUnion([audit_entry]),
        })

    def append_audit(self, case_id: str, actor: str, action: str, detail: str) -> None:
        """Append-only al audit log — WORM."""
        entry = {
            "ts":     datetime.utcnow().isoformat(),
            "actor":  actor,
            "action": action,
            "detail": detail,
        }
        self.db.collection(self.COLLECTION).document(case_id).update({
            "audit_log": firestore.ArrayUnion([entry]),
        })

    def list_cases(self, user_id: str, status: Optional[str] = None, limit: int = 50) -> list[dict]:
        query = self.db.collection(self.COLLECTION)
        if user_id not in AEGIS_ADMINS:
            query = query.where("created_by", "==", user_id)
        if status:
            query = query.where("status", "==", status)
        query = query.order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit)
        return [doc.to_dict() for doc in query.stream()]
