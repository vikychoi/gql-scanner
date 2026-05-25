"""Input-validation / injection checks (OWASP §"Injection").

Thin wrappers over :mod:`gql_scanner.checks.injection_engine`, which runs every
differential probe family across every injectable argument exactly once. Each
check here just surfaces its family's findings. All probes are benign canaries
(unique nonce / arithmetic / loopback), bounded and deterministic (§7.5).
"""

from __future__ import annotations

from ..findings import Finding
from .base import Check, CheckContext
from .injection_engine import run_injection


class _InjectionFamily(Check):
    requires_schema = True

    def run(self, ctx: CheckContext) -> list[Finding]:
        return run_injection(ctx).get(self.id, [])


class SqlInjection(_InjectionFamily):
    id = "GQL-INJECTION-SQL"
    title = "SQL injection (differential)"


class NoSqlInjection(_InjectionFamily):
    id = "GQL-INJECTION-NOSQL"
    title = "NoSQL injection (differential)"


class OsInjection(_InjectionFamily):
    id = "GQL-INJECTION-OS"
    title = "OS command injection (canary reflection)"


class SsrfInjection(_InjectionFamily):
    id = "GQL-INJECTION-SSRF"
    title = "SSRF via URL argument"


class TemplateInjection(_InjectionFamily):
    id = "GQL-INJECTION-TEMPLATE"
    title = "Template / expression injection (SSTI)"


class InputAllowlist(_InjectionFamily):
    id = "GQL-INPUT-ALLOWLIST"
    title = "Scalar input not allowlist-validated"
