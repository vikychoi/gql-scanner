"""Deterministic orchestrator: resolve schema, build the matrix, run checks.

The check registry is an explicit, ordered list — order here plus the CSV sort
keys make the whole scan path reproducible (§9).
"""

from __future__ import annotations

from dataclasses import dataclass

from .accessmatrix import AccessMatrix, build_access_matrix
from .checks.access_checks import (
    BrokenFunctionLevelAuthz,
    BrokenObjectLevelAuthz,
    EdgeNodeAuthz,
    NodeFieldAccess,
    UnauthAccess,
)
from .checks.base import Check, CheckContext
from .checks.batching_checks import AliasBatching, ArrayBatching, BatchRateLimit
from .checks.config_checks import (
    ExcessiveErrors,
    FieldSuggestions,
    GraphiQLExposed,
    IntrospectionEnabled,
    SchemaReconstructed,
)
from .checks.dos_checks import (
    AmountLimit,
    DepthLimit,
    DirectiveOverload,
    Pagination,
    QueryCost,
    Timeout,
)
from .checks.injection_checks import (
    InputAllowlist,
    NoSqlInjection,
    OsInjection,
    SqlInjection,
    SsrfInjection,
    TemplateInjection,
)
from .checks.transport_checks import AuthBatch, CorsMisconfig, CsrfGet
from .config import Settings
from .findings import Finding, finalize_findings
from .report.incremental import IncrementalWriter
from .reporter import Reporter
from .schema.loader import resolve_schema
from .session import SessionManager
from .transport import Transport

# Ordered registry. IDs are stable; order here is part of determinism.
CHECK_REGISTRY: list[Check] = [
    IntrospectionEnabled(),
    GraphiQLExposed(),
    ExcessiveErrors(),
    FieldSuggestions(),
    SchemaReconstructed(),
    NodeFieldAccess(),
    BrokenObjectLevelAuthz(),
    BrokenFunctionLevelAuthz(),
    UnauthAccess(),
    EdgeNodeAuthz(),
    DepthLimit(),
    AmountLimit(),
    Pagination(),
    QueryCost(),
    DirectiveOverload(),
    Timeout(),
    ArrayBatching(),
    AliasBatching(),
    BatchRateLimit(),
    AuthBatch(),
    CsrfGet(),
    CorsMisconfig(),
    SqlInjection(),
    NoSqlInjection(),
    OsInjection(),
    SsrfInjection(),
    TemplateInjection(),
    InputAllowlist(),
]


@dataclass
class ScanResult:
    findings: list[Finding]
    matrix: AccessMatrix
    schema_note: str
    introspection_enabled: bool
    target_reachable: bool
    skipped_checks: list[str]


def _selected(check: Check, settings: Settings) -> bool:
    if settings.checks is not None and check.id not in settings.checks:
        return False
    if check.id in settings.skip:
        return False
    return True


def run_scan(
    settings: Settings,
    transport: Transport,
    reporter: Reporter | None = None,
    *,
    sink: IncrementalWriter | None = None,
) -> ScanResult:
    """Run the full deterministic scan and return findings + matrix.

    When ``sink`` is supplied (the CLI does; tests do not), findings and the access
    matrix are streamed to disk as they are produced, so an interrupted scan still
    leaves valid partial CSVs. Streaming is skipped for an unreachable target.
    """
    reporter = reporter or Reporter(enabled=False)
    reporter.banner(settings.url)

    reporter.phase("resolving schema")
    resolution = resolve_schema(
        transport, settings.url, settings.schema_path, settings.roles
    )
    reporter.info(resolution.note)

    intro_ex = resolution.introspection_exchange
    target_reachable = intro_ex is not None and intro_ex.ok

    session = SessionManager(settings.roles, settings.url, reporter)
    # Stream partial output only for a reachable target; otherwise the CLI exits early
    # and we would leave behind empty / all-ERROR artifacts.
    active_sink = sink if target_reachable else None
    if active_sink is not None:
        active_sink.begin()

    if target_reachable:
        reporter.phase("baseline: validating role credentials")
        session.prime(transport)

    n_ops = len(resolution.model.operations) if resolution.model else 0
    reporter.phase(f"building access matrix ({n_ops} operations × {len(settings.roles)} roles)")
    matrix = build_access_matrix(transport, settings, resolution.model, session, sink=active_sink)

    ctx = CheckContext(
        settings=settings,
        transport=transport,
        schema=resolution.model,
        matrix=matrix,
        introspection_enabled=resolution.introspection_enabled,
        reconstruction=resolution.reconstruction,
        reporter=reporter,
        session=session,
    )

    reporter.phase("running checks")
    findings: list[Finding] = []
    skipped: list[str] = []
    for check in CHECK_REGISTRY:
        if not _selected(check, settings):
            skipped.append(check.id)
            continue
        if check.requires_schema and resolution.model is None:
            skipped.append(check.id)
            continue
        if check.is_mutation_probe and not settings.allow_mutations:
            skipped.append(check.id)
            continue
        reporter.check_start(check.id, check.title)
        check_findings = check.run(ctx)
        for f in check_findings:
            reporter.hit(f.with_derived_operation())
        reporter.check_result(check.id, len(check_findings))
        findings.extend(check_findings)
        if active_sink is not None:
            active_sink.add_findings(check_findings)

    findings = finalize_findings(findings, settings.min_confidence)
    reporter.summary(len(findings))

    return ScanResult(
        findings=findings,
        matrix=matrix,
        schema_note=resolution.note,
        introspection_enabled=resolution.introspection_enabled,
        target_reachable=target_reachable,
        skipped_checks=sorted(skipped),
    )
