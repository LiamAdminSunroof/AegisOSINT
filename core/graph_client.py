from neo4j import GraphDatabase, Driver
from typing import Optional, Any

from config import NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD
from core.ontology import BaseEntity, EntityRelation, EntityType


class GraphClient:
    """
    Cliente Neo4j Aura (Bolt/URI).
    Conexión managed — NO instancia local en Cloud Run (efímero destruiría el grafo).
    Credenciales: NEO4J_URI + NEO4J_PASSWORD desde Secret Manager.
    """

    _driver: Optional[Driver] = None

    @classmethod
    def get_driver(cls) -> Driver:
        if cls._driver is None:
            if not NEO4J_URI or not NEO4J_PASSWORD:
                raise RuntimeError(
                    "NEO4J_URI y NEO4J_PASSWORD son obligatorios. "
                    "Configura la instancia AuraDB en console.neo4j.io y "
                    "añade los secretos en Secret Manager."
                )
            cls._driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USERNAME, NEO4J_PASSWORD),
            )
        return cls._driver

    @classmethod
    def close(cls) -> None:
        if cls._driver:
            cls._driver.close()
            cls._driver = None

    @classmethod
    def upsert_entity(cls, entity: BaseEntity) -> None:
        """Crea o actualiza un nodo con propiedades de procedencia obligatorias."""
        entity.validate()  # lanza ValueError si falta confianza/fuente/origen_caso
        label = entity.entity_type.value
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
    def run_cypher(cls, cypher: str, params: dict = None) -> list[dict]:
        """Ejecuta Cypher arbitrario (solo lectura) para AEGIS_ANALYST."""
        if any(kw in cypher.upper() for kw in ("CREATE", "MERGE", "DELETE", "SET", "REMOVE")):
            raise PermissionError("run_cypher es de solo lectura. Usa upsert_entity/upsert_relation para escritura.")
        with cls.get_driver().session() as session:
            result = session.run(cypher, **(params or {}))
            return [dict(record) for record in result]

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
