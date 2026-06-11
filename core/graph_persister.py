"""
Persiste Findings del motor de recolección como nodos + relaciones en Neo4j Aura.
Convierte Finding (collector) → BaseEntity + EntityRelation (ontology) → GraphClient.
"""
import hashlib
from typing import Optional

from collector.base_module import Finding, SelectorType, Sensitivity as FindingSensitivity
from core.graph_client import GraphClient
from core.ontology import (
    BaseEntity, EntityRelation, EntityType, RelationType, Sensitivity,
    UsernameEntity, EmailEntity, CuentaEntity, DominioEntity, IPEntity, BrechaEntity,
)
from core.crypto import maybe_encrypt


def _make_id(*parts: str) -> str:
    """ID determinista para evitar duplicados."""
    raw = ":".join(p.lower().strip() for p in parts if p)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _map_sensitivity(s: FindingSensitivity) -> Sensitivity:
    mapping = {
        FindingSensitivity.LOW:    Sensitivity.LOW,
        FindingSensitivity.MEDIUM: Sensitivity.MEDIUM,
        FindingSensitivity.HIGH:   Sensitivity.HIGH,
    }
    return mapping.get(s, Sensitivity.LOW)


class GraphPersister:
    """
    Toma una lista de Findings y los persiste en Neo4j:
    1. Crea el nodo selector (Username / Email / Dominio / IP).
    2. Por cada Finding, crea un nodo Cuenta + relación IDENTIFICA/REGISTRA/ALOJADA_EN.
    3. Cifra campos HIGH sensitivity antes de persistir.
    """

    def persist_findings(
        self,
        findings: list[Finding],
        case_id:  str,
        selector_type: SelectorType,
        selector_value: str,
    ) -> int:
        """Persiste findings en Neo4j. Retorna cantidad de nodos creados/actualizados."""
        if not findings:
            return 0

        try:
            driver = GraphClient.get_driver()
        except RuntimeError as e:
            print(f"[graph_persister] Neo4j no disponible — skip: {e}")
            return 0

        # 1. Nodo raíz (selector)
        selector_entity = _build_selector_entity(selector_type, selector_value, case_id)
        if selector_entity:
            GraphClient.upsert_entity(selector_entity)

        count = 0
        for finding in findings:
            try:
                cuenta = _finding_to_cuenta(finding, case_id)
                GraphClient.upsert_entity(cuenta)
                count += 1

                # Relación selector → cuenta
                if selector_entity:
                    rel = _build_relation(selector_entity, cuenta, finding, case_id)
                    if rel:
                        GraphClient.upsert_relation(rel)
            except Exception as e:
                print(f"[graph_persister] Error persistiendo finding {finding.platform}: {e}")

        print(f"[graph_persister] Persistidos {count}/{len(findings)} findings en Neo4j (caso={case_id})")
        return count


def _build_selector_entity(
    selector_type: SelectorType,
    selector_value: str,
    case_id: str,
) -> Optional[BaseEntity]:
    eid = _make_id(selector_type.value, selector_value)
    common = dict(
        id          = eid,
        confianza   = 1.0,
        fuente      = "CASE_SELECTOR",
        origen_caso = case_id,
        sensitivity = Sensitivity.LOW,
    )
    if selector_type == SelectorType.USERNAME:
        return UsernameEntity(**common, entity_type=EntityType.USERNAME, value=selector_value)
    if selector_type == SelectorType.EMAIL:
        return EmailEntity(**common, entity_type=EntityType.EMAIL, address=selector_value)
    if selector_type == SelectorType.DOMAIN:
        parts = selector_value.split(".")
        return DominioEntity(
            **common, entity_type=EntityType.DOMINIO,
            name=selector_value, tld=parts[-1] if len(parts) > 1 else "",
        )
    if selector_type == SelectorType.IP:
        return IPEntity(**common, entity_type=EntityType.IP, address=selector_value)
    return None


def _finding_to_cuenta(finding: Finding, case_id: str) -> CuentaEntity:
    eid = _make_id("cuenta", finding.platform, finding.url or finding.selector_value)
    sens = _map_sensitivity(finding.sensitivity)

    url_val = maybe_encrypt(finding.url, sens.value)

    meta = dict(finding.metadata)
    if sens == Sensitivity.HIGH:
        for k in ("email", "password", "hash", "credential"):
            if k in meta:
                meta[k] = maybe_encrypt(str(meta[k]), "HIGH")

    return CuentaEntity(
        id          = eid,
        entity_type = EntityType.CUENTA,
        confianza   = finding.confidence,
        fuente      = finding.fuente if hasattr(finding, "fuente") else finding.platform,
        origen_caso = case_id,
        sensitivity = sens,
        url         = url_val,
        platform    = finding.platform,
        username    = finding.selector_value if finding.selector_type == SelectorType.USERNAME else "",
        activa      = True,
        metadata    = meta,
    )


def _build_relation(
    selector: BaseEntity,
    cuenta:   CuentaEntity,
    finding:  Finding,
    case_id:  str,
) -> Optional[EntityRelation]:
    rel_map = {
        SelectorType.USERNAME: RelationType.IDENTIFICA,
        SelectorType.EMAIL:    RelationType.REGISTRA,
        SelectorType.DOMAIN:   RelationType.POSEE,
        SelectorType.IP:       RelationType.EXPONE,
    }
    rel_type = rel_map.get(finding.selector_type, RelationType.USA)
    return EntityRelation(
        source_id   = selector.id,
        target_id   = cuenta.id,
        relation    = rel_type,
        confianza   = finding.confidence,
        metadata    = {"case_id": case_id, "platform": finding.platform},
    )
