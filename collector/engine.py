"""
Motor de recolección async — fan-out masivo sobre N módulos.
Rate-limit por dominio. Circuit breaker. Recursión hasta max_depth.
"""
import asyncio
import traceback
from datetime import datetime
from typing import Optional

from collector.base_module import CollectorModule, Finding, SelectorType, MODULE_STATUS_UNSTABLE
from core.case_manager import CaseManager, CaseStatus
from config import MAX_CASE_DEPTH

# Registro de módulos disponibles — se importan aquí
from collector.modules.username.massive import UsernameChecker
from collector.modules.email.mx_probe import EmailMxProbe
from collector.modules.domain.dns_recon import DnsReconModule
from collector.modules.breach.dehashed import DeHashedModule

REGISTRY: dict[str, list[CollectorModule]] = {
    SelectorType.USERNAME: [UsernameChecker(), DeHashedModule()],
    SelectorType.EMAIL:    [EmailMxProbe(), DeHashedModule()],
    SelectorType.DOMAIN:   [DnsReconModule(), DeHashedModule()],
    SelectorType.IP:       [],   # Sprint 2: ip_recon, shodan
    SelectorType.PHONE:    [],   # Sprint 2: phone_recon
    SelectorType.NAME:     [],   # Sprint 3: people_search
}

# Circuit breaker: módulo → contador de fallos consecutivos
_circuit_failures: dict[str, int] = {}
CIRCUIT_OPEN_THRESHOLD = 3


class CollectionEngine:
    """
    Fan-out async sobre módulos del REGISTRY.
    Selecciona módulos por selector_type + tags opcionales.
    Recursión: nuevos selectors en Finding.new_selectors disparan búsquedas hasta max_depth.
    """

    def __init__(self):
        self._case_mgr = CaseManager()

    async def run_case(
        self,
        case_id:        str,
        selector_type:  SelectorType,
        selector_value: str,
        tags:           Optional[list[str]] = None,
        max_depth:      int = MAX_CASE_DEPTH,
        _depth:         int = 0,
    ) -> list[Finding]:
        # 1. Validar caso
        case = self._case_mgr.get_case(case_id)
        if not case:
            raise ValueError(f"Caso no encontrado: {case_id}")
        if case.status == CaseStatus.PURGED:
            raise PermissionError(f"Caso {case_id} está PURGED — datos eliminados por TTL.")

        # 2. Seleccionar módulos
        modules = self._select_modules(selector_type, tags or [])
        if not modules:
            print(f"[engine] No hay módulos para selector_type={selector_type}, tags={tags}")
            return []

        print(f"[engine] depth={_depth} | {selector_value} ({selector_type}) | {len(modules)} módulos")

        # 3. Fan-out async con semáforo global
        sem = asyncio.Semaphore(20)
        tasks = [
            self._run_module_safe(sem, mod, selector_type, selector_value, {"case_id": case_id, "scope": case.scope})
            for mod in modules
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        # 4. Audit log
        self._case_mgr.append_audit(
            case_id,
            actor  = "AEGIS_ENGINE",
            action = "COLLECTION_COMPLETE",
            detail = f"depth={_depth} selector={selector_value} findings={len(findings)}",
        )

        # 5. Recursión — nuevos selectors en findings
        if _depth < max_depth:
            new_tasks = []
            for finding in findings:
                for new_sel in finding.new_selectors:
                    stype = new_sel.get("type")
                    sval  = new_sel.get("value")
                    if stype and sval:
                        new_tasks.append(
                            self.run_case(case_id, SelectorType(stype), sval, tags, max_depth, _depth + 1)
                        )
            if new_tasks:
                sub_results = await asyncio.gather(*new_tasks, return_exceptions=True)
                for sr in sub_results:
                    if isinstance(sr, list):
                        findings.extend(sr)

        return findings

    async def _run_module_safe(
        self,
        semaphore:      asyncio.Semaphore,
        module:         CollectorModule,
        selector_type:  SelectorType,
        selector_value: str,
        context:        dict,
    ) -> list[Finding]:
        # Circuit breaker check
        if _circuit_failures.get(module.name, 0) >= CIRCUIT_OPEN_THRESHOLD:
            print(f"[engine] Circuit OPEN para {module.name} — skip")
            return []

        # Módulos inestables tienen fallback silencioso
        is_unstable = getattr(module, "status", "") == MODULE_STATUS_UNSTABLE

        async with semaphore:
            try:
                findings = await asyncio.wait_for(
                    module.collect(selector_type, selector_value, context),
                    timeout=30.0,
                )
                _circuit_failures[module.name] = 0  # reset en éxito
                return findings or []
            except asyncio.TimeoutError:
                print(f"[engine] Timeout en {module.name}")
                _circuit_failures[module.name] = _circuit_failures.get(module.name, 0) + 1
                return []
            except Exception as e:
                if is_unstable:
                    return []  # fallo silencioso
                print(f"[engine] Error en {module.name}: {type(e).__name__}: {e}")
                _circuit_failures[module.name] = _circuit_failures.get(module.name, 0) + 1
                return []

    def _select_modules(self, selector_type: SelectorType, tags: list[str]) -> list[CollectorModule]:
        candidates = REGISTRY.get(selector_type, [])
        if not tags:
            return candidates
        return [m for m in candidates if not tags or any(t in m.tags for t in tags)]
