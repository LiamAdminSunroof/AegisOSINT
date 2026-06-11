"""
AEGIS_ANALYST — genera dossiers OSINT a partir de findings + grafo Neo4j.
Modelo: Sonnet L2 (claude-sonnet-4-6).
Input: case_id + findings + cypher_context
Output: dossier estructurado en Markdown con firma AEGIS.
"""
import json
from datetime import datetime
from typing import Optional

import anthropic

from config import ANTHROPIC_API_KEY, MODEL_L2, MODEL_L3
from collector.base_module import Finding
from core.graph_client import GraphClient

_SYSTEM_PROMPT = """Eres AEGIS_ANALYST, el agente de inteligencia OSINT del ecosistema SunRoof.
Tu función es analizar findings de fuentes abiertas y producir dossiers de inteligencia accionables.

MANDATOS IRREVOCABLES:
1. Solo analizas datos OSINT (fuentes abiertas) proporcionados en el contexto. No inventas datos.
2. Todo dato citado debe tener fuente explícita del finding.
3. Sensibilidad HIGH: menciona la existencia pero NO el contenido en el dossier (e.g., "credencial cifrada detectada").
4. Si la evidencia es insuficiente para una conclusión, debes decirlo explícitamente.
5. AIR-GAP OT: nunca recomiendes acciones sobre infraestructura OT, plantas FV ni portales SaaS.
6. Formato: Markdown estructurado con secciones, confianza y firma AEGIS al final.

ESCALA DE CONFIANZA:
- ALTA (0.85–1.0): múltiples fuentes independientes coincidentes
- MEDIA (0.60–0.84): una fuente confiable o múltiples fuentes menores
- BAJA (0.0–0.59): indicio sin confirmación — marcar como hipótesis"""

_ANALYST_TEMPLATE = """# DOSSIER DE INTELIGENCIA OSINT
## Caso: {case_id}
**Objetivo:** `{selector_value}` ({selector_type})
**Fecha análisis:** {timestamp}
**Analista:** AEGIS_ANALYST (Sonnet L2)

---

## RESUMEN EJECUTIVO
{executive_summary}

---

## HALLAZGOS POR MÓDULO

{findings_by_module}

---

## GRAFO DE RELACIONES
{graph_summary}

---

## INDICADORES DE RIESGO
{risk_indicators}

---

## RECOMENDACIONES
{recommendations}

---

*[ORIGEN: AEGIS_ANALYST | SENTINEL_OSINT: PENDIENTE | CONFIANZA: {overall_confidence} | CASO: {case_id} | ESTADO: BORRADOR]*"""


class AegisAnalyst:
    """
    Invoca a Claude Sonnet L2 para sintetizar findings en un dossier OSINT.
    Escalado a Fable 5 L3 solo si el caso tiene >50 findings o criticidad alta.
    """

    def __init__(self):
        if not ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY no configurado.")
        self._client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    def generate_dossier(
        self,
        case_id:        str,
        selector_type:  str,
        selector_value: str,
        findings:       list[Finding],
        graph_context:  Optional[dict] = None,
        escalate_l3:    bool = False,
    ) -> dict:
        """
        Genera el dossier. Retorna dict con keys: dossier_md, confidence, model_used.
        """
        model = MODEL_L3 if (escalate_l3 or len(findings) > 50) else MODEL_L2

        findings_text = _serialize_findings(findings)
        graph_text    = _serialize_graph(graph_context) if graph_context else "Grafo no disponible (Neo4j pendiente)."

        graph_nodes = (graph_context or {}).get("nodes", [])
        effective_cnt = len(findings) if findings else len(graph_nodes)
        prompt = f"""Analiza los siguientes findings OSINT del caso {case_id} para el objetivo `{selector_value}` ({selector_type}).

## Findings directos recolectados ({len(findings)} total):
{findings_text}

## Grafo de relaciones Neo4j ({len(graph_nodes)} nodos persistidos):
{graph_text}

Nota: {effective_cnt} entidades totales disponibles (findings directos + nodos del grafo).
Basa tu análisis en los NODOS DEL GRAFO si los findings directos son 0.

Genera un dossier de inteligencia completo en Markdown siguiendo tu mandato.
Incluye:
1. Resumen ejecutivo (3-5 líneas)
2. Hallazgos agrupados por módulo/plataforma con nivel de confianza
3. Grafo de relaciones (nodos + edges relevantes)
4. Indicadores de riesgo (IPs, brechas, señales de infraestructura)
5. Recomendaciones accionables (sin mencionar OT)
6. Firma AEGIS al final

Si hay findings con sensitivity=HIGH, menciona SOLO "credencial cifrada detectada en [plataforma]" sin revelar el contenido."""

        response = self._client.messages.create(
            model      = model,
            max_tokens = 4096,
            system     = _SYSTEM_PROMPT,
            messages   = [{"role": "user", "content": prompt}],
        )

        dossier_md = response.content[0].text if response.content else ""
        findings_cnt = len(findings) if findings else len(graph_nodes)
        confidence = _estimate_confidence(findings) if findings else _estimate_confidence_from_graph(graph_nodes)

        return {
            "dossier_md":   dossier_md,
            "confidence":   confidence,
            "model_used":   model,
            "findings_cnt": findings_cnt,
            "generated_at": datetime.utcnow().isoformat(),
            "case_id":      case_id,
        }

    def query_graph_nl(self, question: str, case_id: str) -> str:
        """NL → Cypher → resultado. Solo lectura."""
        # Paso 1: NL → Cypher con Haiku L1
        from config import MODEL_L1
        cypher_resp = self._client.messages.create(
            model      = MODEL_L1,
            max_tokens = 256,
            system     = (
                "Eres un experto en Cypher (Neo4j). Convierte la pregunta del usuario en una query Cypher "
                "de SOLO LECTURA (MATCH/RETURN). El grafo tiene nodos: Persona, Username, Email, Cuenta, "
                "Dominio, IP, Brecha, Organizacion. Todos tienen la propiedad `origen_caso`. "
                f"Filtra siempre por origen_caso='{case_id}'. Retorna SOLO el Cypher, sin explicación."
            ),
            messages   = [{"role": "user", "content": question}],
        )
        cypher = cypher_resp.content[0].text.strip().strip("```").strip()
        if cypher.lower().startswith("cypher"):
            cypher = cypher[6:].strip()

        try:
            rows = GraphClient.run_cypher(cypher, {"case_id": case_id})
            return json.dumps(rows, default=str, ensure_ascii=False, indent=2)
        except Exception as e:
            return f"Error ejecutando Cypher: {e}\nQuery: {cypher}"


def _serialize_findings(findings: list[Finding]) -> str:
    lines = []
    by_platform: dict[str, list[Finding]] = {}
    for f in findings:
        by_platform.setdefault(f.platform, []).append(f)
    for platform, flist in by_platform.items():
        lines.append(f"\n### {platform} ({len(flist)} resultados)")
        for f in flist[:5]:  # máx 5 por plataforma en el prompt
            sens_flag = " ⚠️ HIGH" if f.sensitivity.value == "HIGH" else ""
            lines.append(
                f"  - URL: {f.url} | Confianza: {f.confidence:.2f} | "
                f"Tipo: {f.entity_type}{sens_flag}"
            )
            if f.metadata:
                key_meta = {k: v for k, v in f.metadata.items()
                            if k not in ("password", "hash", "credential") and v}
                if key_meta:
                    lines.append(f"    Metadata: {json.dumps(key_meta, ensure_ascii=False)[:200]}")
        if len(flist) > 5:
            lines.append(f"  - ... y {len(flist) - 5} más")
    return "\n".join(lines) or "Sin findings disponibles."


def _serialize_graph(graph_context: dict) -> str:
    nodes = graph_context.get("nodes", [])
    edges = graph_context.get("edges", [])
    if not nodes:
        return "Grafo vacío."
    lines = [f"Nodos: {len(nodes)} | Relaciones: {len(edges)}"]
    for node in nodes[:20]:
        # "classes" está en la raíz del nodo (formato Cytoscape.js), propiedades en "data"
        label = node.get("classes", "?")
        data  = node.get("data", {})
        props = {k: v for k, v in data.items() if k not in ("id",) and v}
        lines.append(f"  [{label}] {json.dumps(props, ensure_ascii=False)[:160]}")
    if len(nodes) > 20:
        lines.append(f"  ... y {len(nodes) - 20} nodos más")
    return "\n".join(lines)


def _estimate_confidence(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    avg = sum(f.confidence for f in findings) / len(findings)
    platforms = len({f.platform for f in findings})
    bonus = min(0.1, platforms * 0.01)
    return min(1.0, round(avg + bonus, 2))


def _estimate_confidence_from_graph(nodes: list[dict]) -> float:
    """Confianza estimada a partir de nodos del grafo cuando no hay findings directos."""
    if not nodes:
        return 0.0
    confianzas = [
        node.get("data", {}).get("confianza", 0.5)
        for node in nodes
        if node.get("data", {}).get("confianza") is not None
    ]
    if not confianzas:
        return 0.5
    avg = sum(confianzas) / len(confianzas)
    bonus = min(0.1, len({node.get("classes") for node in nodes}) * 0.02)
    return min(1.0, round(avg + bonus, 2))
