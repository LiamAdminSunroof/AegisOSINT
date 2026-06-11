# AEGIS MEMORY — CONTEXTO OPERATIVO
## Fuente de Verdad Persistente | Viaja con el Repositorio Git

**Última actualización:** 2026-06-11 CLT — Sprint 1 completado
**Revisión activa Cloud Run:** PENDIENTE PRIMER DEPLOY (Neo4j Aura aún requerido)
**Actualizado por:** USR-001 — Lizardo Monsálvez

---

## IDENTIDAD DEL SISTEMA

**AEGIS** (Advanced OSINT Platform) es el módulo de inteligencia de fuentes abiertas del ecosistema SunRoof IA.
Integrado con SAM vía Federation endpoints. Autónomo a nivel de Cloud Run.

- **Repositorio:** `/home/monsalveztapia/AegisOSINT/`
- **Servicio Cloud Run:** `aegis-osint` (pendiente primer deploy)
- **Proyecto GCP:** `sunroof-agent-manager`
- **Región:** `us-central1`

---

## STACK TÉCNICO

| Componente | Tecnología |
|-----------|-----------|
| Framework web | FastAPI + uvicorn |
| Base de grafos | Neo4j Aura (managed — NOT Cloud Run local) |
| Audit log | Firestore `aegis_audit_log` |
| Casos | Firestore `aegis_cases` |
| Recolección | aiohttp async fan-out |
| Rate limiting | slowapi 30/min global |
| Monitoreo | Sentry SDK |
| Container | Python 3.12-slim · PORT 8080 |

---

## MODELOS IA (FinOps AEGIS V1.0)

| Nivel | Modelo | Model ID | Uso |
|-------|--------|----------|-----|
| L1 | Haiku 4.5 | `claude-haiku-4-5-20251001` | Triaje, routing, scoring de confianza básico |
| L2 | Sonnet 4.6 | `claude-sonnet-4-6` | Análisis semántico de perfiles, correlación de entidades |
| L3 | Fable 5 | `claude-fable-5` | Fusion de identidades HITL, análisis de inteligencia crítica |

Mezcla objetivo: **65% Haiku / 30% Sonnet / 5% Fable 5**

---

## NEO4J AURA — ESTADO

| Parámetro | Valor |
|-----------|-------|
| Tipo | AuraDB Free (o Professional) |
| URI | PENDIENTE — crear en console.neo4j.io |
| Secreto GCP | `NEO4J_URI` · `NEO4J_PASSWORD` |
| Constraints aplicados | NO — ejecutar `bash scripts/01_setup_neo4j.sh` post-deploy |

**CRITICAL:** Neo4j DEBE ser Aura (managed). Nunca local en Cloud Run — los datos del grafo se destruirían en cada restart de instancia.

---

## SECRETOS EN SECRET MANAGER (requeridos)

| Secreto | Estado | Descripción |
|---------|--------|-------------|
| `ANTHROPIC_API_KEY` | ✅ Activo (heredado de SAM) | API LLM |
| `GOOGLE_SERVICE_ACCOUNT_JSON` | ✅ Activo (heredado de SAM) | Firestore DWD |
| `NEO4J_URI` | ⏳ PENDIENTE | bolt+ssc://... de Aura |
| `NEO4J_PASSWORD` | ⏳ PENDIENTE | Password generado en Aura |
| `AEGIS_API_KEY` | ⏳ PENDIENTE | Shared secret con SAM Federation |
| `SHODAN_API_KEY` | ⏳ PENDIENTE Sprint 1 | Infra module |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | ⏳ PENDIENTE Sprint 1 | Infra module |
| `DEHASHED_API_KEY` | ⏳ PENDIENTE Sprint 1 | Breach module |
| `SERPAPI_KEY` | ⏳ PENDIENTE Sprint 1 | Web scraping |
| `INTEL_X_API_KEY` | ⏳ PENDIENTE Sprint 1 | Dark web |

---

## SPRINT 0 — ESTADO (2026-06-10)

| Item | Estado |
|------|--------|
| 0.1 Constitución AEGIS.md | ✅ |
| 0.2 Dockerfile + requirements.txt | ✅ |
| 0.3 config.py + core/ontology.py | ✅ |
| 0.4 Neo4j Aura instance | ⏳ MANUAL — USR-001 |
| 0.5 core/case_manager.py | ✅ |
| 0.6 core/graph_client.py | ✅ |
| 0.7 collector/base_module.py + engine.py | ✅ |
| 0.8 collector/modules/username/massive.py | ✅ |
| 0.9 sites_db/sites.json (149 sitios → Sprint 1) | ✅ |
| 0.10 server.py (FastAPI) | ✅ |
| 0.11 scripts/ deploy + neo4j setup | ✅ |
| 0.12 __init__.py en todos los packages | ✅ |
| 0.13 AEGIS_MEMORY/CONTEXTO_OPERATIVO_AEGIS.md | ✅ |
| 0.14 Git init + primer commit | ⏳ PENDIENTE |
| 0.15 Primer deploy Cloud Run `aegis-osint` | ⏳ PENDIENTE NEO4J |
| 0.16 Smoke test end-to-end | ⏳ PENDIENTE |

---

## SPRINT 1 — ESTADO (2026-06-11)

| Item | Estado |
|------|--------|
| 1.1 sites_db expansión (149 sitios) | ✅ |
| 1.2 core/crypto.py (AES-256-GCM) | ✅ |
| 1.3 core/entity_resolver.py (HITL queue) | ✅ |
| 1.4 core/graph_persister.py (Finding→Neo4j) | ✅ |
| 1.5 collector/modules/email/mx_probe.py | ✅ |
| 1.6 collector/modules/domain/dns_recon.py | ✅ |
| 1.7 collector/modules/breach/dehashed.py | ✅ |
| 1.8 agents/orchestrator.py (AEGIS_ORCHESTRATOR) | ✅ |
| 1.9 agents/analyst.py (AEGIS_ANALYST) | ✅ |
| 1.10 server.py — /analyze /graph /query /fusion endpoints | ✅ |
| 1.11 deploy script — secretos opcionales | ✅ |
| 1.12 requirements.txt + cryptography + dnspython | ✅ |
| 1.13 Primer deploy Cloud Run `aegis-osint` | ⏳ Pendiente NEO4J |
| 1.14 Smoke test end-to-end | ⏳ Pendiente deploy |

---

## ARQUITECTURA DE MÓDULOS

```
AegisOSINT/
├── server.py              ← FastAPI entrypoint (Sprint 1: +4 endpoints)
├── config.py              ← Settings + secrets
├── AEGIS.md               ← Constitución / mandatos
├── Dockerfile
├── requirements.txt       ← +cryptography +dnspython
├── agents/
│   ├── orchestrator.py    ← AEGIS_ORCHESTRATOR — triaje/validación Haiku L1
│   └── analyst.py         ← AEGIS_ANALYST — dossier Sonnet L2 / Fable 5 L3
├── core/
│   ├── ontology.py        ← EntityType, RelationType, BaseEntity, EntityRelation
│   ├── case_manager.py    ← CaseManager + Firestore CRUD + WORM audit
│   ├── graph_client.py    ← Neo4j Aura driver (upsert + Cypher read-only)
│   ├── crypto.py          ← AES-256-GCM para findings HIGH sensitivity
│   ├── entity_resolver.py ← Fuzzy match + HITL queue Firestore
│   └── graph_persister.py ← Finding → Neo4j entities + relations
├── collector/
│   ├── base_module.py     ← CollectorModule Protocol + Finding dataclass
│   ├── engine.py          ← Fan-out async + circuit breaker + recursión
│   └── modules/
│       ├── username/
│       │   └── massive.py ← Maigret-style (149 sitios)
│       ├── email/
│       │   └── mx_probe.py ← MX lookup + gravatar + disposable detection
│       ├── domain/
│       │   └── dns_recon.py ← DNS A/MX/TXT/NS/SOA + provider detection
│       └── breach/
│           └── dehashed.py ← DeHashed API (graceful fallback sin key)
├── sites_db/
│   └── sites.json         ← 149 sitios (social, dev, gaming, latam, security)
├── tools/                 ← Tools SAM (Sprint 2+)
├── AEGIS_MEMORY/
│   └── CONTEXTO_OPERATIVO_AEGIS.md
└── scripts/
    ├── 01_setup_neo4j.sh  ← Aplica constraints en Aura
    └── 02_deploy_cloudrun_aegis.sh ← Secretos opcionales (graceful skip)
```

---

## GUARDRAILS IRREVOCABLES

1. **AIR-GAP OT TOTAL** (Constitución SAM §5.1): AEGIS nunca accede, controla ni administra las 29+ plantas FV ni portales SaaS (SMA · Huawei · Solis · Ingeteam).
2. **Proveniencia obligatoria**: toda entidad requiere `fuente` + `confianza` + `origen_caso`.
3. **Guardrail legal port scanning**: módulos de infraestructura solo con `legal_basis` explícito.
4. **HITL fusion**: `MISMO_ACTOR_QUE` requiere aprobación humana explícita vía endpoint `/api/cases/{id}/fusion/approve`.
5. **Escritura Neo4j**: solo a través de `GraphClient`. Cypher directo solo READ en `run_cypher()`.

---

## PENDIENTES ACTIVOS

| # | Item | Bloqueante |
|---|------|-----------|
| 1 | **Neo4j Aura Free** instance → `console.neo4j.io` | USR-001 MANUAL |
| 2 | `NEO4J_URI` + `NEO4J_PASSWORD` en Secret Manager | Depende de #1 |
| 3 | `AEGIS_API_KEY` en Secret Manager (shared secret con SAM) | USR-001 MANUAL |
| 4 | **Primer deploy** `bash scripts/02_deploy_cloudrun_aegis.sh` | Depende de #2+#3 |
| 5 | `bash scripts/01_setup_neo4j.sh` — constraints Neo4j | Depende de #4 |
| 6 | Smoke test end-to-end (caso + username search + dossier) | Depende de #5 |
| 7 | **Sprint 2:** IP recon module + Shodan + dork engine (SerpAPI) | Listo para iniciar |

---

## PROTOCOLO DE DEPLOY

```bash
# Desde /home/monsalveztapia/AegisOSINT/
bash scripts/02_deploy_cloudrun_aegis.sh sunroof-agent-manager us-central1
```

Verificar post-deploy:
```bash
curl https://aegis-osint-591203469479.us-central1.run.app/health
```

---

*[ORIGEN: AEGIS_OSINT | VALIDACIÓN: SENTINEL_CORE_ADVERSARIAL | SEGURIDAD: ZERO_TRUST_VERIFIED | ESTADO: SPRINT_1_COMPLETO_PENDIENTE_NEO4J_DEPLOY | ADMIN: LIZARDO MONSÁLVEZ TAPIA]*
