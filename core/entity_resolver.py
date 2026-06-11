"""
Entity resolver — deduplica y fusiona entidades del grafo.
Fuzzy matching via thefuzz + cola HITL para MISMO_ACTOR_QUE.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from google.cloud import firestore

from config import GCP_PROJECT, RESOLVER_AUTO_MERGE, RESOLVER_REVIEW_QUEUE, AEGIS_ADMINS
from core.ontology import BaseEntity, EntityRelation, RelationType, Sensitivity

try:
    from thefuzz import fuzz
    _HAS_FUZZ = True
except ImportError:
    _HAS_FUZZ = False


# ── HITL queue Firestore collection ──────────────────────────────────────────
HITL_COLLECTION = "aegis_fusion_queue"


@dataclass
class ResolveCandidate:
    id:          str
    entity_a_id: str
    entity_b_id: str
    score:       float          # 0.0–1.0 similitud
    evidence:    list[str]      = field(default_factory=list)
    status:      str            = "PENDING"   # PENDING | APPROVED | REJECTED
    created_at:  str            = field(default_factory=lambda: datetime.utcnow().isoformat())
    reviewed_by: Optional[str]  = None
    reviewed_at: Optional[str]  = None
    notes:       Optional[str]  = None


class EntityResolver:
    """
    Identifica candidatos a fusión (MISMO_ACTOR_QUE).
    Score ≥ RESOLVER_AUTO_MERGE → propuesta HITL de alta confianza.
    Score en [RESOLVER_REVIEW_QUEUE, RESOLVER_AUTO_MERGE) → cola HITL normal.
    Score < RESOLVER_REVIEW_QUEUE → entidades separadas.

    NUNCA fusiona automáticamente — siempre requiere aprobación humana (AEGIS §3.4).
    """

    def __init__(self):
        self._db: Optional[firestore.Client] = None

    @property
    def db(self) -> firestore.Client:
        if self._db is None:
            self._db = firestore.Client(project=GCP_PROJECT)
        return self._db

    def compute_similarity(self, entity_a: BaseEntity, entity_b: BaseEntity) -> float:
        """Calcula similitud entre dos entidades del mismo tipo."""
        if entity_a.entity_type != entity_b.entity_type:
            return 0.0
        if not _HAS_FUZZ:
            return 0.0

        # Extraer valor representativo según tipo
        val_a = _entity_repr(entity_a)
        val_b = _entity_repr(entity_b)
        if not val_a or not val_b:
            return 0.0

        token_sort = fuzz.token_sort_ratio(val_a.lower(), val_b.lower()) / 100.0
        partial    = fuzz.partial_ratio(val_a.lower(), val_b.lower()) / 100.0
        return max(token_sort, partial)

    def maybe_queue_fusion(
        self,
        entity_a: BaseEntity,
        entity_b: BaseEntity,
        case_id:  str,
    ) -> Optional[ResolveCandidate]:
        """
        Si el score supera el umbral de revisión, crea entrada en la cola HITL.
        Retorna el candidato creado o None si el score es insuficiente.
        """
        if entity_a.id == entity_b.id:
            return None

        score = self.compute_similarity(entity_a, entity_b)
        if score < RESOLVER_REVIEW_QUEUE:
            return None

        candidate = ResolveCandidate(
            id          = str(uuid.uuid4()),
            entity_a_id = entity_a.id,
            entity_b_id = entity_b.id,
            score       = score,
            evidence    = [f"case:{case_id}", f"type:{entity_a.entity_type.value}"],
            status      = "PENDING",
        )
        self.db.collection(HITL_COLLECTION).document(candidate.id).set({
            "id":          candidate.id,
            "entity_a_id": candidate.entity_a_id,
            "entity_b_id": candidate.entity_b_id,
            "score":       candidate.score,
            "evidence":    candidate.evidence,
            "status":      candidate.status,
            "created_at":  candidate.created_at,
            "case_id":     case_id,
        })
        return candidate

    def approve_fusion(
        self,
        resolve_id: str,
        reviewed_by: str,
        notes: str = "",
    ) -> EntityRelation:
        """
        Aprueba la fusión HITL. Crea la relación MISMO_ACTOR_QUE.
        Requiere que reviewed_by sea un usuario en AEGIS_ADMINS.
        """
        if reviewed_by not in AEGIS_ADMINS:
            raise PermissionError(f"{reviewed_by} no tiene permiso para aprobar fusiones.")

        ref = self.db.collection(HITL_COLLECTION).document(resolve_id)
        doc = ref.get()
        if not doc.exists:
            raise ValueError(f"Candidato de fusión {resolve_id} no encontrado.")
        d = doc.to_dict()
        if d["status"] != "PENDING":
            raise ValueError(f"Candidato {resolve_id} ya fue procesado (status={d['status']}).")

        ref.update({
            "status":      "APPROVED",
            "reviewed_by": reviewed_by,
            "reviewed_at": datetime.utcnow().isoformat(),
            "notes":       notes,
        })

        return EntityRelation(
            source_id    = d["entity_a_id"],
            target_id    = d["entity_b_id"],
            relation     = RelationType.MISMO_ACTOR,
            confianza    = d["score"],
            reviewed_by  = reviewed_by,
            metadata     = {"resolve_id": resolve_id, "notes": notes},
        )

    def reject_fusion(self, resolve_id: str, reviewed_by: str, reason: str = "") -> None:
        ref = self.db.collection(HITL_COLLECTION).document(resolve_id)
        doc = ref.get()
        if not doc.exists:
            raise ValueError(f"Candidato {resolve_id} no encontrado.")
        if doc.to_dict().get("status") != "PENDING":
            raise ValueError(f"Candidato {resolve_id} ya fue procesado.")
        ref.update({
            "status":      "REJECTED",
            "reviewed_by": reviewed_by,
            "reviewed_at": datetime.utcnow().isoformat(),
            "notes":       reason,
        })

    def list_pending(self, limit: int = 50) -> list[dict]:
        return [
            doc.to_dict()
            for doc in self.db.collection(HITL_COLLECTION)
            .where("status", "==", "PENDING")
            .order_by("score", direction=firestore.Query.DESCENDING)
            .limit(limit)
            .stream()
        ]


def _entity_repr(entity: BaseEntity) -> str:
    """Extrae un string representativo del valor principal de la entidad."""
    for attr in ("value", "address", "name", "nombre", "url", "platform"):
        v = getattr(entity, attr, None)
        if v and isinstance(v, str):
            return v
    return ""
