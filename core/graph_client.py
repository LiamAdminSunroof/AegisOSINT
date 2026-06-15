import threading
from typing import Optional, Any

from neo4j import GraphDatabase, Driver

from config import NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD
from core.ontology import BaseEntity, EntityRelation, EntityType

# FIX P6: whitelist inmutable de labels — previene Cypher injection via f-string
_VALID_LABELS = frozenset(e.value for e in EntityType)

# FIX M4: lock para inicialización thread-safe del singleton
_driver_lock = threading.Lock()


class GraphClient:
    """
    Cliente Neo4j Aura (Bolt/URI).
    Conexión managed — NO instancia local en Cloud Run (efímero destruiría el grafo).
    Credenciales: NEO4J_URI + NEO4J_PASSWORD desde Secret Manager.
    """

    _driver: Optional[Driver] = None

    @classmethod
    def get_driver(cls) -> Driver:
        """FIX M4: double-checked locking para inicialización thread-safe del singleton."""
        if cls._driver is None:
            with _driver_lock:
                if cls._driver is None:
                    if not NEO4J_URI or not NEO4J_PASSWORD:
                        raise RuntimeError(
                            "NEO4J_URI y NEO4J_PASSWORD son obligatorios. "
                            "Configura AuraDB en console.neo4j.io y añade secretos en Secret Manager."
                        )
                    cls._driver = GraphDatabase.driver(
                        NEO4J_URI,
                        auth=(NEO4J_USERNAME, NEO4J_PASSWORD),
                    )
        return cls._driver

    @classmethod
    def close(cls) -> None:
        with _driver_lock:
            if cls._driver:
                cls._driver.close()
                cls._driver = None

    @classmethod
    def upsert_entity(cls, entity: BaseEntity) -> None:
        """Crea o actualiza un nodo con propiedades de procedencia obligatorias."""
        entity.validate()  # lanza ValueError si falta confianza/fuente/origen_caso
        label = entity.entity_type.value

        # FIX P6: validar label contra whitelist antes de interpolarlo en Cypher
        if label not in _VALID_LABELS:
            raise ValueError(
                f"EntityType '{label}' no pertenece al esquema autorizado. "
                f"Válidos: {sorted(_VALID_LABELS)}"
            )

        props = {
            "id":          entity.id,
            "confianza":   entity.confianza,
            "fuente":      entity.fuente,
            "origen_caso": entity.origen_caso,
            "created_at":  entity.created_at.isoformat(),
            "sensitivity": entity.sensitivity.value,
            **entity.metadata,
        }
        # Añadir propiedades específicas del tipo
        if hasattr(entity, "value"):    props["value"]    = entity.value
        if hasattr(entity, "address"):  props["address"]  = entity.address
        if hasattr(entity, "url"):      props["url"]      = entity.url
        if hasattr(entity, "name"):     props["name"]     = entity.name
        if hasattr(entity, "nombre"):   props["nombre"]   = entity.nombre or ""
        if hasattr(entity, "platform"): props["platform"] = entity.platform

        cypher = f"MERGE (n:{label} {{id: $id}}) SET n += $props RETURN n"
        with cls.get_driver().session() as session:
            session.run(cypher, id=entity.id, props=props)

    @classmethod
    def upsert_relation(cls, rel: EntityRelation) -> None:
        """Crea o actualiza una relación entre dos nodos."""
        rel.validate()  # lanza ValueError si MISMO_ACTOR_QUE sin reviewed_by
        cypher = (
            "MATCH (a {id: $source_id}), (b {id: $target_id}) "
            f"MERGE (a)-[r:{rel.relation.value}]->(b) "
            "SET r += $props RETURN r"
        )
        props = {
            "confianza":    rel.confianza,
            "created_at":  rel.created_at.isoformat(),
            "evidencia_id": rel.evidencia_id or "",
            "reviewed_by":  rel.reviewed_by or "",
            **rel.metadata,
        }
        with cls.get_driver().session() as session:
            session.run(cypher, source_id=rel.source_id, target_id=rel.target_id, props=props)

    @classmethod
    def get_case_graph(cls, case_id: str) -> dict:
        """Retorna nodos + relaciones del caso para Cytoscape.js."""
        cypher = """
        MATCH (n {origen_caso: $case_id})
        OPTIONAL MATCH (n)-[r]->(m {origen_caso: $case_id})
        RETURN n, r, m
        """
        nodes, edges = {}, []
        with cls.get_driver().session() as session:
            for record in session.run(cypher, case_id=case_id):
                n = record["n"]
                if n and n.element_id not in nodes:
                    nodes[n.element_id] = {
                        "data": {"id": n.element_id, **dict(n)},
                        "classes": list(n.labels)[0] if n.labels else "Unknown",
                    }
                if record["r"] and record["m"]:
                    m = record["m"]
                    if m.element_id not in nodes:
                        nodes[m.element_id] = {
                            "data": {"id": m.element_id, **dict(m)},
                            "classes": list(m.labels)[0] if m.labels else "Unknown",
                        }
                    r = record["r"]
                    edges.append({
                        "data": {
                            "id":     r.element_id,
                            "source": n.element_id,
                            "target": m.element_id,
                            "type":   r.type,
                            **dict(r),
                        }
                    })
        return {"nodes": list(nodes.values()), "edges": edges}

    @classmethod
    def query_case_nodes(cls, case_id: str, entity_type: Optional[str] = None,
                         limit: int = 500) -> list[dict]:
        """
        FIX P3: Reemplaza run_cypher() que aceptaba Cypher arbitrario de Claude (peligroso).
        API de solo lectura tipada y parametrizada — sin posibilidad de inyección.
        """
        if entity_type is not None and entity_type not in _VALID_LABELS:
            raise ValueError(f"entity_type '{entity_type}' no válido. Válidos: {sorted(_VALID_LABELS)}")
        if entity_type:
            cypher = f"MATCH (n:{entity_type} {{origen_caso: $case_id}}) RETURN n LIMIT $limit"
        else:
            cypher = "MATCH (n {origen_caso: $case_id}) RETURN n LIMIT $limit"
        with cls.get_driver().session() as session:
            result = session.run(cypher, case_id=case_id, limit=limit)
            return [dict(record["n"]) for record in result]

    @classmethod
    def query_entity_relations(cls, entity_id: str, depth: int = 1) -> dict:
        """Retorna relaciones de un nodo hasta profundidad 3 — solo lectura, parametrizado."""
        depth = min(max(depth, 1), 3)
        cypher = f"""
        MATCH path = (n {{id: $entity_id}})-[*1..{depth}]-(m)
        RETURN n, relationships(path) AS rels, collect(m) AS neighbors
        LIMIT 200
        """
        with cls.get_driver().session() as session:
            result = session.run(cypher, entity_id=entity_id)
            return {"entity_id": entity_id, "depth": depth, "rows": [dict(r) for r in result]}

    @classmethod
    def apply_constraints(cls) -> None:
        """Crea constraints e índices de unicidad. Ejecutar una sola vez al setup."""
        constraints = [
            "CREATE CONSTRAINT persona_id IF NOT EXISTS FOR (p:Persona) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT cuenta_url IF NOT EXISTS FOR (c:Cuenta) REQUIRE c.url IS UNIQUE",
            "CREATE CONSTRAINT dominio_name IF NOT EXISTS FOR (d:Dominio) REQUIRE d.name IS UNIQUE",
            "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
            "CREATE CONSTRAINT email_addr IF NOT EXISTS FOR (e:Email) REQUIRE e.address IS UNIQUE",
            "CREATE CONSTRAINT username_val IF NOT EXISTS FOR (u:Username) REQUIRE u.value IS UNIQUE",
            "CREATE CONSTRAINT org_id IF NOT EXISTS FOR (o:Organizacion) REQUIRE o.id IS UNIQUE",
            "CREATE CONSTRAINT brecha_id IF NOT EXISTS FOR (b:Brecha) REQUIRE b.id IS UNIQUE",
            "CREATE CONSTRAINT caso_id IF NOT EXISTS FOR (c:Caso) REQUIRE c.id IS UNIQUE",
        ]
        with cls.get_driver().session() as session:
            for constraint in constraints:
                session.run(constraint)
        print("[GraphClient] Constraints aplicados en Neo4j Aura.")
